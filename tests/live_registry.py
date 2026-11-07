"""Real SPIFFE + PostgreSQL coverage for the public registry boundary (F-live only)."""

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

from tools.spire_fixture import spire

ROOT = Path(__file__).resolve().parents[1]


class RegistryHttpTests(unittest.TestCase):
    def test_authenticated_durable_operation_and_attempt_routes(self):
        socket = Path(os.environ["FABRIC_FIXTURE_PG_SOCKET"])
        container = os.environ["FABRIC_FIXTURE_PG_CONTAINER"]
        binary = ROOT / os.environ.get("CARGO_TARGET_DIR", "target") / "debug/fabric-runtime"
        with (
            tempfile.TemporaryDirectory() as temporary,
            spire(Path(temporary) / "spire", ttl=45) as (endpoint, fetch, _),
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
            database = folder / "database.url"
            database.write_text(
                f"postgresql://postgres@localhost/postgres?host={quote(str(socket), safe='')}"
            )
            audits = []

            def start():
                process = subprocess.Popen(
                    [
                        str(binary),
                        "--spiffe",
                        f"unix://{endpoint}",
                        "spiffe://fabric.test/runtime",
                        str(folder / "policy.json"),
                        "--registry",
                        str(database),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.addCleanup(lambda: process.poll() is None and process.kill())
                assert process.stdout is not None
                self.assertTrue(select.select([process.stdout], [], [], 15)[0])
                line = process.stdout.readline()
                if not line:
                    process.communicate(timeout=5)
                    self.fail("registry-enabled SPIFFE runtime did not start")
                address, boot = line.split()
                return process, int(address.rsplit(":", 1)[1]), boot

            def stop(process):
                process.terminate()
                _, audit = process.communicate(timeout=5)
                audits.append(audit)

            process, port, boot = start()
            token = "7" * 64
            operation = json.loads((ROOT / "contracts/spec/fixtures/control.json").read_text())[
                "Operation"
            ]
            operation.update(
                operation_id="http-operation",
                idempotency_key="http-id",
                deadline_unix_ms=str(time.time_ns() // 1_000_000 + 120_000),
            )
            tenant = operation["tenant_scope"]
            workflow = operation["workflow_epoch"]
            create: dict[str, Any] = {
                "schema_version": "1",
                "operation": operation,
                "input_manifest_digests": ["a" * 64],
            }
            attempt: dict[str, Any] = {
                "schema_version": "1",
                "attempt": {
                    "schema_version": "1",
                    "tenant_scope": tenant,
                    "operation_id": "http-operation",
                    "workflow_epoch": workflow,
                    "attempt_epoch": "1",
                },
            }

            def publish(
                *,
                scope_tenant=tenant,
                scope_operation="http-operation",
                scope_workflow=workflow,
                actions=None,
                expiry=None,
            ):
                document = {
                    "boot_id": boot,
                    "grants": [],
                    "registry_grants": [
                        {
                            "spiffe_id": "spiffe://fabric.test/coordinator",
                            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                            "scope": {
                                "tenant_scope": scope_tenant,
                                "operation_id": scope_operation,
                                "workflow_epoch": scope_workflow,
                            },
                            "actions": actions
                            or ["CREATE_OPERATION", "GET_OPERATION", "ENSURE_ATTEMPT"],
                            "expires_unix_ms": expiry or time.time_ns() // 1_000_000 + 45_000,
                        }
                    ],
                }
                path = folder / "policy.next"
                path.write_text(json.dumps(document))
                path.replace(folder / "policy.json")

            def request(method, path, body=None, name="coordinator"):
                tls = ssl.create_default_context(cafile=str(folder / "runtime.ca"))
                tls.check_hostname = False
                tls.load_cert_chain(folder / f"{name}.pem", folder / f"{name}.key")
                conn = http.client.HTTPSConnection("127.0.0.1", port, context=tls, timeout=5)
                try:
                    conn.connect()
                    assert conn.sock is not None
                    certificate = conn.sock.getpeercert()
                    assert certificate is not None
                    self.assertEqual(
                        certificate["subjectAltName"], (("URI", "spiffe://fabric.test/runtime"),)
                    )
                    conn.request(
                        method,
                        path,
                        None if body is None else json.dumps(body),
                        {
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                            "X-Tenant-Scope": "forged-tenant",
                        },
                    )
                    response = conn.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    conn.close()

            def sql(statement):
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
                        statement,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout

            cancel_path = "/v1/operations/cancel"
            admin_path = "/v1/admin/operations/cancel"
            recovery_path = "/v1/admin/operations/fence-recovery"
            cancel = {
                "schema_version": "1",
                "tenant_scope": tenant,
                "operation_id": "http-operation",
                "idempotency_key": "admin-cancel",
            }
            recovery = {
                "schema_version": "1",
                "tenant_scope": tenant,
                "operation_id": "http-operation",
                "workflow_epoch": workflow,
            }
            pending = (202, {"schema_version": "1", "outcome": "CANCELLATION_PENDING"})
            unavailable = (503, {"schema_version": "1", "code": "UNAVAILABLE"})

            def expire():
                sql(
                    "UPDATE fabric_attempts SET lease_expires_unix_ms=0 "
                    "WHERE operation_id='http-operation'"
                )

            try:
                publish()
                self.assertEqual(request("POST", "/v1/operations", create, "worker")[0], 403)
                artifact_scope = {
                    "schema_version": "1",
                    "attempt": {**attempt["attempt"], "fence": "1"},
                    "manifest_digest": "a" * 64,
                    "purpose": "COMPUTE_READ",
                }
                (folder / "policy.json").write_text(
                    json.dumps(
                        {
                            "boot_id": boot,
                            "grants": [
                                {
                                    "spiffe_id": "spiffe://fabric.test/coordinator",
                                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                                    "scope": artifact_scope,
                                    "expires_unix_ms": time.time_ns() // 1_000_000 + 45_000,
                                }
                            ],
                        }
                    )
                )
                self.assertEqual(
                    request("POST", "/v1/artifact-access/authorize", artifact_scope)[0], 200
                )
                self.assertEqual(request("POST", "/v1/operations", create)[0], 403)
                token = "6" * 64
                publish()
                foreign = copy.deepcopy(create)
                foreign["operation"]["tenant_scope"] = "foreign"
                for ref in ("plan_ref", "key_context_ref", "disclosure_identity"):
                    foreign["operation"][ref]["tenant_scope"] = "foreign"
                self.assertEqual(request("POST", "/v1/operations", foreign)[0], 403)
                self.assertEqual(
                    sql(
                        "SELECT count(*) FROM fabric_operations WHERE tenant_scope='foreign'"
                    ).strip(),
                    "0",
                )
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(
                        pool.map(lambda _: request("POST", "/v1/operations", create), range(2))
                    )
                self.assertEqual(results[0], results[1])
                self.assertEqual(
                    results[0],
                    (200, {"schema_version": "1", "operation": operation, "public_status": None}),
                )
                race = copy.deepcopy(create)
                race["operation"].update(operation_id="http-race", idempotency_key="http-race")
                conflict = {**race, "input_manifest_digests": ["b" * 64]}
                publish(scope_operation="http-race")
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(
                        pool.map(
                            lambda body: request("POST", "/v1/operations", body), (race, conflict)
                        )
                    )
                self.assertEqual(sorted(r[0] for r in results), [200, 409])
                self.assertEqual(
                    next(r[1]["code"] for r in results if r[0] == 409), "IDEMPOTENCY_CONFLICT"
                )
                for body, result in zip((race, conflict), results, strict=True):
                    self.assertEqual(request("POST", "/v1/operations", body), result)
                publish()
                self.assertEqual(
                    request("GET", "/v1/operations/http-operation")[1]["operation"], operation
                )
                publish(scope_tenant="foreign")
                self.assertEqual(request("GET", "/v1/operations/http-operation")[0], 404)
                publish(actions=["GET_OPERATION"])
                self.assertEqual(request("POST", "/v1/attempts/ensure", attempt)[0], 403)
                publish(expiry=1)
                self.assertEqual(request("POST", "/v1/operations", create)[0], 403)
                publish()
                status, first = request("POST", "/v1/attempts/ensure", attempt)
                self.assertEqual(status, 200)
                self.assertEqual(request("POST", "/v1/attempts/ensure", attempt), (200, first))
                invalid = copy.deepcopy(attempt)
                invalid["attempt"]["workflow_epoch"] = str(int(workflow) + 1)
                self.assertEqual(request("POST", "/v1/attempts/ensure", invalid)[0], 403)
                invalid = copy.deepcopy(attempt)
                invalid["attempt"]["fence"] = "999"
                self.assertEqual(request("POST", "/v1/attempts/ensure", invalid)[0], 400)
                expire()
                self.assertEqual(
                    request("POST", "/v1/attempts/ensure", attempt),
                    (409, {"schema_version": "1", "code": "ATTEMPT_EXPIRED"}),
                )
                attempt["attempt"]["attempt_epoch"] = "2"
                status, second = request("POST", "/v1/attempts/ensure", attempt)
                self.assertEqual(status, 200)
                self.assertGreater(int(second["attempt"]["fence"]), int(first["attempt"]["fence"]))
                stale = copy.deepcopy(attempt)
                stale["attempt"]["attempt_epoch"] = "1"
                self.assertEqual(request("POST", "/v1/attempts/ensure", stale)[0], 409)
                self.assertEqual(request("POST", "/v1/operations/cancel", {})[0], 403)
                subprocess.run(
                    ["docker", "stop", "--time", "1", container],
                    check=True,
                    capture_output=True,
                    timeout=20,
                )
                try:
                    self.assertEqual(
                        request("GET", "/v1/operations/http-operation"),
                        unavailable,
                    )
                    publish(actions=["CANCEL_OPERATION"])
                    self.assertEqual(request("POST", cancel_path, cancel), pending)
                    publish(actions=["ADMIN_CANCEL"])
                    self.assertEqual(request("POST", admin_path, cancel), pending)
                    publish(actions=["ADMIN_RECOVERY"])
                    self.assertEqual(request("POST", recovery_path, recovery), unavailable)
                finally:
                    subprocess.run(
                        ["docker", "start", container], check=True, capture_output=True, timeout=20
                    )
                deadline = time.monotonic() + 15
                while True:
                    try:
                        sql("SELECT 1")
                        break
                    except subprocess.CalledProcessError:
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.2)
                publish()
                self.assertEqual(request("POST", "/v1/attempts/ensure", attempt), (200, second))
                stop(process)
                process, port, boot = start()
                self.assertEqual(request("GET", "/v1/operations/http-operation")[0], 403)
                publish()
                self.assertEqual(request("POST", "/v1/attempts/ensure", attempt), (200, second))
                self.assertEqual(
                    request("GET", "/v1/operations/http-operation")[1]["operation"], operation
                )
                expire()
                self.assertEqual(request("POST", "/v1/attempts/ensure", attempt)[0], 409)
                attempt["attempt"]["attempt_epoch"] = "3"
                status, third = request("POST", "/v1/attempts/ensure", attempt)
                self.assertEqual(status, 200)
                self.assertGreater(int(third["attempt"]["fence"]), int(second["attempt"]["fence"]))
                publish(actions=["CANCEL_OPERATION"])
                self.assertEqual(request("POST", admin_path, cancel)[0], 403)
                self.assertEqual(request("POST", recovery_path, recovery)[0], 403)
                publish(actions=["ADMIN_RECOVERY"])
                self.assertEqual(request("POST", recovery_path, recovery, "worker")[0], 403)
                self.assertEqual(
                    request("POST", recovery_path, {**recovery, "successor_epoch": "9"})[0], 400
                )
                stale_epoch = str(int(workflow) + 1)
                publish(actions=["ADMIN_RECOVERY"], scope_workflow=stale_epoch)
                self.assertEqual(
                    request("POST", recovery_path, {**recovery, "workflow_epoch": stale_epoch}),
                    (409, {"schema_version": "1", "code": "STALE_FENCE"}),
                )
                publish(actions=["ADMIN_RECOVERY"])
                fence = str(int(third["attempt"]["fence"]) + 1)
                recovered = (
                    200,
                    {
                        "schema_version": "1",
                        "outcome": "RECOVERY_FENCED",
                        "fence": fence,
                        "successor_epoch": stale_epoch,
                    },
                )
                self.assertEqual(request("POST", recovery_path, recovery), recovered)
                self.assertEqual(request("POST", recovery_path, recovery), recovered)
                self.assertEqual(
                    sql(
                        "SELECT fence || ':' || recovery_epoch FROM fabric_operation_barriers "
                        "WHERE operation_id='http-operation'"
                    ).strip(),
                    f"{fence}:{stale_epoch}",
                )
                self.assertEqual(
                    sql(
                        "SELECT intent->>'workflow_epoch' FROM fabric_operations "
                        "WHERE operation_id='http-operation'"
                    ).strip(),
                    workflow,
                )
                publish()
                self.assertEqual(request("POST", "/v1/attempts/ensure", attempt)[0], 409)

                publish(actions=["ADMIN_CANCEL"], scope_workflow=stale_epoch)
                self.assertEqual(request("POST", admin_path, cancel)[0], 403)
                publish(actions=["ADMIN_CANCEL"])
                self.assertEqual(
                    request("POST", admin_path, {**cancel, "tenant_scope": "foreign"})[0], 403
                )
                # Force PostgreSQL to reject the commit after all barrier writes.
                sql(
                    "CREATE FUNCTION fixture_reject_cancel() RETURNS trigger "
                    "LANGUAGE plpgsql AS $$ "
                    "BEGIN RAISE EXCEPTION 'fixture commit fault'; END $$; "
                    "CREATE CONSTRAINT TRIGGER fixture_cancel_commit AFTER UPDATE "
                    "ON fabric_operation_barriers DEFERRABLE INITIALLY DEFERRED "
                    "FOR EACH ROW EXECUTE FUNCTION fixture_reject_cancel()"
                )
                try:
                    self.assertEqual(request("POST", admin_path, cancel), pending)
                    self.assertEqual(
                        sql(
                            "SELECT count(*) FROM fabric_operation_barriers "
                            "WHERE operation_id='http-operation' AND cancel_key IS NOT NULL"
                        ).strip(),
                        "0",
                    )
                    self.assertEqual(
                        sql(
                            "SELECT count(*) FROM fabric_outbox "
                            "WHERE operation_id='http-operation' "
                            "AND kind='cancelled'"
                        ).strip(),
                        "0",
                    )
                finally:
                    sql(
                        "DROP TRIGGER fixture_cancel_commit ON fabric_operation_barriers; "
                        "DROP FUNCTION fixture_reject_cancel()"
                    )
                cancelled = (
                    200,
                    {"schema_version": "1", "outcome": "CANCELLED", "fence": str(int(fence) + 1)},
                )
                self.assertEqual(request("POST", admin_path, cancel), cancelled)
                self.assertEqual(request("POST", admin_path, cancel), cancelled)
                self.assertEqual(
                    sql(
                        "SELECT fence || ':' || cancel_key FROM fabric_operation_barriers "
                        "WHERE operation_id='http-operation'"
                    ).strip(),
                    f"{cancelled[1]['fence']}:admin-cancel",
                )
                self.assertEqual(
                    sql(
                        "SELECT count(*) FROM fabric_attempts "
                        "WHERE operation_id='http-operation' AND NOT retired"
                    ).strip(),
                    "0",
                )
                publish(actions=["ADMIN_RECOVERY"])
                self.assertEqual(request("POST", recovery_path, recovery)[0], 409)
                publish(scope_operation="http-race", actions=["CANCEL_OPERATION"])
                public = {**cancel, "operation_id": "http-race", "idempotency_key": "public-cancel"}
                public_result = (200, {"schema_version": "1", "outcome": "CANCELLED", "fence": "1"})
                self.assertEqual(request("POST", cancel_path, public), public_result)
                self.assertEqual(request("POST", cancel_path, public), public_result)
                self.assertEqual(
                    request("POST", cancel_path, {**public, "idempotency_key": "different"}),
                    (409, {"schema_version": "1", "code": "IDEMPOTENCY_CONFLICT"}),
                )
                publish(scope_operation="http-race", actions=["GET_OPERATION"])
                self.assertEqual(
                    request("GET", "/v1/operations/http-race")[1]["public_status"], "CANCELLED"
                )
                self.assertEqual(
                    sql(
                        "SELECT count(*) FROM fabric_outbox WHERE operation_id='http-operation' "
                        "AND kind IN ('cancelled','recovery_fenced')"
                    ).strip(),
                    "2",
                )
                exhausted = str((1 << 64) - 1)
                overflow = copy.deepcopy(create)
                overflow["operation"].update(
                    operation_id="http-overflow",
                    idempotency_key="http-overflow",
                    workflow_epoch=exhausted,
                )
                publish(
                    scope_operation="http-overflow",
                    scope_workflow=exhausted,
                    actions=["CREATE_OPERATION", "ADMIN_RECOVERY"],
                )
                self.assertEqual(request("POST", "/v1/operations", overflow)[0], 200)
                self.assertEqual(
                    request(
                        "POST",
                        recovery_path,
                        {
                            **recovery,
                            "operation_id": "http-overflow",
                            "workflow_epoch": exhausted,
                        },
                    ),
                    (409, {"schema_version": "1", "code": "STALE_FENCE"}),
                )
                self.assertEqual(
                    sql(
                        "SELECT count(*) FROM fabric_operation_barriers "
                        "WHERE operation_id='http-overflow'"
                    ).strip(),
                    "0",
                )
                print("FENCING_HTTP_PASSED", flush=True)
                (folder / "policy.json").unlink()
                self.assertEqual(request("GET", "/v1/operations/http-operation")[0], 403)
                self.assertNotIn(
                    token,
                    sql(
                        "SELECT intent::text || inputs::text FROM fabric_operations "
                        "WHERE operation_id='http-operation'"
                    ),
                )
            finally:
                stop(process)
            for audit in audits:
                for secret in (
                    token,
                    str(database),
                    "http-operation",
                    "forged-tenant",
                    "postgresql://",
                ):
                    self.assertNotIn(secret, audit)
