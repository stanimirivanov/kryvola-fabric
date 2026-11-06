"""Public upload authorization/streaming evidence. Owned by F-live."""

import base64
import concurrent.futures
import copy
import hashlib
import http.client
import json
import os
import select
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import quote

from upload_campaign import exercise

from tools.spire_fixture import spire

ROOT = Path(__file__).resolve().parents[1]


class UploadHttpTests(unittest.TestCase):
    def test_scoped_streaming_reservation_manifest_and_abort(self):
        endpoint = os.environ["FABRIC_FIXTURE_S3_ENDPOINT"]
        socket = Path(os.environ["FABRIC_FIXTURE_PG_SOCKET"])
        container = os.environ["FABRIC_FIXTURE_PG_CONTAINER"]
        binary = ROOT / os.environ.get("CARGO_TARGET_DIR", "target") / "debug/fabric-runtime"
        with (
            tempfile.TemporaryDirectory() as temporary,
            spire(Path(temporary) / "spire", ttl=45) as (agent, fetch, _),
        ):
            folder = Path(temporary)
            for svid in fetch()["svids"]:
                name = svid["spiffe_id"].rsplit("/", 1)[1]
                for field, suffix, label in (
                    ("x509_svid", "pem", "CERTIFICATE"),
                    ("x509_svid_key", "key", "PRIVATE KEY"),
                    ("bundle", "ca", "CERTIFICATE"),
                ):
                    (folder / f"{name}.{suffix}").write_text(
                        ssl.DER_cert_to_PEM_cert(base64.b64decode(svid[field])).replace(
                            "CERTIFICATE", label
                        )
                    )
            db = folder / "database.url"
            db.write_text(
                f"postgresql://postgres@localhost/postgres?host={quote(str(socket), safe='')}"
            )
            config = {
                "endpoint": endpoint,
                "bucket": "fabric-runtime",
                "region": "us-east-1",
                "access_key_id": os.environ["AWS_ACCESS_KEY_ID"],
                "secret_access_key": os.environ["AWS_SECRET_ACCESS_KEY"],
                "allow_http": True,
                "tenant_quota_bytes": 1024 * 1024 * 1024,
            }
            (folder / "s3.json").write_text(json.dumps(config))
            process = subprocess.Popen(
                [
                    str(binary),
                    "--spiffe",
                    f"unix://{agent}",
                    "spiffe://fabric.test/runtime",
                    str(folder / "policy.json"),
                    "--registry",
                    str(db),
                    "--uploads",
                    str(folder / "s3.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert process.stdout is not None
                self.assertTrue(select.select([process.stdout], [], [], 15)[0])
                line = process.stdout.readline()
                self.assertTrue(line, "upload-enabled runtime did not start")
                address, boot = line.split()
                port = int(address.rsplit(":", 1)[1])
                operation = json.loads((ROOT / "contracts/spec/fixtures/control.json").read_text())[
                    "Operation"
                ]
                operation.update(
                    operation_id="upload-http",
                    idempotency_key="upload-http",
                    deadline_unix_ms=str(time.time_ns() // 1_000_000 + 120_000),
                )
                tenant = operation["tenant_scope"]
                coordinator = "f" * 64
                grants = []
                counter = 0

                def publish():
                    document = {
                        "boot_id": boot,
                        "grants": grants,
                        "registry_grants": [
                            {
                                "spiffe_id": "spiffe://fabric.test/coordinator",
                                "token_sha256": hashlib.sha256(coordinator.encode()).hexdigest(),
                                "scope": {
                                    "tenant_scope": tenant,
                                    "operation_id": "upload-http",
                                    "workflow_epoch": operation["workflow_epoch"],
                                },
                                "actions": ["CREATE_OPERATION", "ENSURE_ATTEMPT"],
                                "expires_unix_ms": time.time_ns() // 1_000_000 + 45_000,
                            }
                        ],
                    }
                    path = folder / "policy.next"
                    path.write_text(json.dumps(document))
                    path.replace(folder / "policy.json")

                def connect(name="worker"):
                    tls = ssl.create_default_context(cafile=str(folder / "runtime.ca"))
                    tls.check_hostname = False
                    tls.load_cert_chain(folder / f"{name}.pem", folder / f"{name}.key")
                    return http.client.HTTPSConnection("127.0.0.1", port, context=tls, timeout=12)

                def request(method, path, token, body=None, *, name="worker", length=None):
                    conn = connect(name)
                    try:
                        conn.connect()
                        assert conn.sock is not None
                        cert = conn.sock.getpeercert()
                        assert cert is not None
                        self.assertEqual(
                            cert["subjectAltName"], (("URI", "spiffe://fabric.test/runtime"),)
                        )
                        headers = {
                            "Authorization": f"Bearer {token}",
                            "X-Tenant-Scope": "forged-tenant",
                        }
                        if isinstance(body, dict):
                            headers["Content-Type"] = "application/json"
                            body = json.dumps(body)
                        else:
                            headers["Content-Type"] = "application/octet-stream"
                        if length is not None:
                            headers["Content-Length"] = str(length)
                        conn.request(method, path, body, headers)
                        result = conn.getresponse()
                        raw = result.read()
                        return result.status, json.loads(raw) if raw else None
                    finally:
                        conn.close()

                publish()
                self.assertEqual(
                    request(
                        "POST",
                        "/v1/operations",
                        coordinator,
                        {
                            "schema_version": "1",
                            "operation": operation,
                            "input_manifest_digests": ["a" * 64],
                        },
                        name="coordinator",
                    )[0],
                    200,
                )
                attempt = {
                    "schema_version": "1",
                    "tenant_scope": tenant,
                    "operation_id": "upload-http",
                    "workflow_epoch": operation["workflow_epoch"],
                    "attempt_epoch": "1",
                }
                status, lease = request(
                    "POST",
                    "/v1/attempts/ensure",
                    coordinator,
                    {"schema_version": "1", "attempt": attempt},
                    name="coordinator",
                )
                self.assertEqual(status, 200)
                corpus = json.loads(
                    (ROOT / "contracts/spec/fixtures/canonical-modular-v2.json").read_text()
                )["objects"][0]
                manifest = bytes.fromhex(corpus["canonical_hex"])
                scope: dict[str, Any] = {
                    "schema_version": "1",
                    "attempt": lease["attempt"],
                    "manifest_digest": corpus["digest"],
                    "purpose": "COMPUTE_WRITE",
                }

                def issue(*, ttl_ms=45_000, **changes):
                    nonlocal counter
                    counter += 1
                    token = f"{counter:064x}"
                    candidate = copy.deepcopy(scope)
                    for key, value in changes.items():
                        if key in candidate["attempt"]:
                            candidate["attempt"][key] = value
                        else:
                            candidate[key] = value
                    grants.append(
                        {
                            "spiffe_id": "spiffe://fabric.test/worker",
                            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                            "scope": candidate,
                            "expires_unix_ms": time.time_ns() // 1_000_000 + ttl_ms,
                        }
                    )
                    publish()
                    return token

                def sql(query):
                    return subprocess.run(
                        [
                            "docker",
                            "exec",
                            container,
                            "psql",
                            "-U",
                            "postgres",
                            "-XqtA",
                            "-v",
                            "ON_ERROR_STOP=1",
                            "-c",
                            query,
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10,
                    ).stdout

                reserve = {
                    "schema_version": "1",
                    "tenant_scope": tenant,
                    "byte_length": 768 * 1024 * 1024,
                }
                tokens = [issue(), issue()]
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(
                        pool.map(
                            lambda token: request("POST", "/v1/uploads", token, reserve), tokens
                        )
                    )
                self.assertEqual(sorted(r[0] for r in results), [201, 429])
                self.assertEqual(
                    next(r[1]["code"] for r in results if r[0] == 429), "QUOTA_EXCEEDED"
                )
                upload = next(r[1]["upload_id"] for r in results if r[0] == 201)
                abort = {"schema_version": "1", "attempt": scope["attempt"]}
                self.assertEqual(
                    request("POST", f"/v1/uploads/{upload}/abort", issue(), abort)[0], 204
                )
                status, result = request(
                    "POST", "/v1/uploads", issue(), {**reserve, "byte_length": 131072}
                )
                self.assertEqual(status, 201)
                upload = result["upload_id"]
                part = f"/v1/uploads/{upload}/parts/0"
                self.assertEqual(request("PUT", part, issue(), b"data", name="other")[0], 403)
                self.assertEqual(
                    request("PUT", part, coordinator, b"data", name="coordinator")[0], 403
                )
                self.assertEqual(request("PUT", part, issue(attempt_epoch="999"), b"data")[0], 409)
                self.assertEqual(request("PUT", part, issue(workflow_epoch="999"), b"data")[0], 409)
                self.assertEqual(
                    request("PUT", part, issue(purpose="COMPUTE_READ"), b"data")[0], 403
                )
                self.assertEqual(
                    request("PUT", part, issue(manifest_digest="e" * 64), b"data")[0], 403
                )
                self.assertEqual(request("PUT", part, issue(fence="999"), b"data")[0], 409)
                self.assertEqual(
                    request("POST", "/v1/uploads", issue(), {**reserve, "tenant_scope": "other"})[
                        0
                    ],
                    403,
                )
                replay = issue()
                self.assertEqual(request("PUT", part, replay, b"", length=4194305)[0], 413)
                self.assertEqual(request("PUT", part, replay, b"data")[0], 403)
                self.assertEqual(request("PUT", part, issue(), [b"data"])[0], 400)
                self.assertEqual(sql("SELECT count(*) FROM fabric_upload_parts").strip(), "0")
                self.assertEqual(request("PUT", part, issue(), b"", length=4194305)[0], 413)
                self.assertEqual(
                    request("PUT", part, issue(), [b"x" * 8192 for _ in range(16)], length=131072)[
                        0
                    ],
                    204,
                )
                self.assertEqual(request("PUT", part, issue(), b"data")[0], 409)
                self.assertEqual(request("GET", f"/v1/uploads/{upload}", issue())[0], 404)
                self.assertEqual(
                    request("POST", f"/v1/uploads/{upload}/finalize", issue(), {})[0], 400
                )
                self.assertEqual(
                    request("POST", f"/v1/uploads/{upload}/abort", issue(), abort)[0], 204
                )
                self.assertEqual(
                    request("POST", f"/v1/uploads/{upload}/abort", issue(), abort)[0], 404
                )
                status, result = request(
                    "POST", "/v1/uploads", issue(), {**reserve, "byte_length": 4}
                )
                self.assertEqual(status, 201)
                upload = result["upload_id"]
                self.assertEqual(
                    request("PUT", f"/v1/uploads/{upload}/parts/0", issue(), b"12345")[0], 413
                )
                self.assertEqual(
                    request("PUT", f"/v1/uploads/{upload}/parts/0", issue(), bytes([0, 1, 2, 255]))[
                        0
                    ],
                    204,
                )
                self.assertEqual(
                    request("PUT", f"/v1/uploads/{upload}/manifest", issue(), manifest)[0], 204
                )
                self.assertEqual(
                    request("PUT", f"/v1/uploads/{upload}/manifest", issue(), manifest + b" ")[0],
                    400,
                )
                records = sql("SELECT row_to_json(u)::text FROM fabric_uploads u")
                self.assertIn(upload, records)
                for secret in (config["access_key_id"], config["secret_access_key"], endpoint):
                    self.assertNotIn(secret, records)
                self.assertEqual(
                    request("POST", f"/v1/uploads/{upload}/abort", issue(), abort)[0], 204
                )

                # Renew only the owned fixture lease for the extended failure campaign.
                sql(
                    "UPDATE fabric_attempts SET lease_expires_unix_ms="
                    "floor(extract(epoch FROM clock_timestamp())*1000)+60000 "
                    "WHERE operation_id='upload-http'"
                )
                exercise(self, request, connect, issue, sql, process, tenant, scope["attempt"])
                status, result = request(
                    "POST", "/v1/uploads", issue(), {**reserve, "byte_length": 4}
                )
                self.assertEqual(status, 201)
                candidate = result["upload_id"]
                finalize = f"/v1/uploads/{candidate}/finalize"
                publication = {
                    "schema_version": "1",
                    "tenant_scope": tenant,
                    "manifest_digest": corpus["digest"],
                }
                self.assertEqual(request("POST", finalize, issue(), publication)[0], 400)
                self.assertEqual(
                    request(
                        "PUT", f"/v1/uploads/{candidate}/parts/0", issue(), bytes([0, 1, 2, 255])
                    )[0],
                    204,
                )
                self.assertEqual(
                    request("PUT", f"/v1/uploads/{candidate}/manifest", issue(), manifest)[0], 204
                )
                self.assertEqual(
                    request("POST", finalize, issue(purpose="COMPUTE_READ"), publication)[0], 403
                )
                self.assertEqual(
                    request(
                        "POST", finalize, issue(), {**publication, "manifest_digest": "e" * 64}
                    )[0],
                    403,
                )
                self.assertEqual(
                    request("POST", finalize, issue(), {**publication, "tenant_scope": "other"})[0],
                    403,
                )
                status, reference = request("POST", finalize, issue(), publication)
                self.assertEqual(status, 200)
                self.assertEqual(
                    reference, {"schema_version": "1", "manifest_digest": corpus["digest"]}
                )
                self.assertEqual(request("POST", finalize, issue(), publication), (200, reference))
                self.assertEqual(
                    sql(
                        "SELECT encode(canonical_manifest, 'hex') "
                        f"FROM fabric_finalized_artifacts WHERE upload_id='{candidate}'"
                    ).strip(),
                    manifest.hex(),
                )
                self.assertEqual(
                    request("POST", f"/v1/uploads/{candidate}/abort", issue(), abort)[0], 409
                )
                self.assertEqual(
                    request("GET", f"/v1/artifacts/{corpus['digest']}", issue())[0], 404
                )
                self.assertEqual(
                    request(
                        "POST",
                        "/v1/artifact-access/authorize",
                        issue(),
                        {**scope, "purpose": "CONSUMER_READ"},
                    )[0],
                    400,
                )
                # Fixture teardown only; this does not qualify production GC or abort.
                for namespace in ("staging", "immutable"):
                    cleared = subprocess.run(
                        [
                            "docker",
                            "exec",
                            os.environ["FABRIC_FIXTURE_S3_CLIENT"],
                            "aws",
                            "--endpoint-url",
                            "http://s3:8333",
                            "s3",
                            "rm",
                            f"s3://fabric-runtime/{namespace}/{candidate}/",
                            "--recursive",
                        ],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(cleared.returncode, 0, "private fixture cleanup failed")
                sql(
                    f"DELETE FROM fabric_finalized_artifacts WHERE upload_id='{candidate}'; "
                    f"DELETE FROM fabric_uploads WHERE id='{candidate}'"
                )
                print("VERIFIED_FINALIZATION_HTTP_PASSED", flush=True)

                sql(
                    "UPDATE fabric_attempts SET lease_expires_unix_ms=0 "
                    "WHERE operation_id='upload-http'"
                )
                self.assertEqual(
                    request("POST", "/v1/uploads", issue(), {**reserve, "byte_length": 4})[1][
                        "code"
                    ],
                    "ATTEMPT_EXPIRED",
                )
                records = sql("SELECT scope::text FROM fabric_uploads")
                for secret in (
                    config["access_key_id"],
                    config["secret_access_key"],
                    endpoint,
                    "http://s3:8333",
                ):
                    self.assertNotIn(secret, records)
            finally:
                process.terminate()
                _, audit = process.communicate(timeout=5)
            for secret in (
                config["access_key_id"],
                config["secret_access_key"],
                endpoint,
                "upload-http",
                "forged-tenant",
            ):
                self.assertNotIn(secret, audit)
