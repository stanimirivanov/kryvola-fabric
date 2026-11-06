"""Live certificate and policy tests for the Fabric runtime."""

import base64
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

from tools.spire_fixture import spire

ROOT = Path(__file__).resolve().parents[1]


class RuntimeAuthorizationTests(unittest.TestCase):
    def test_verified_workload_and_exact_scope(self):
        target = ROOT / os.environ.get("CARGO_TARGET_DIR", "target")
        binary = target / "debug/fabric-runtime"
        self.assertTrue(binary.is_file(), "Build fabric-runtime with cargo build --locked first")
        with (
            tempfile.TemporaryDirectory() as directory,
            spire(Path(directory) / "spire") as (endpoint, fetch),
        ):
            folder = Path(directory)

            def credentials():
                for svid in fetch()["svids"]:
                    name = svid["spiffe_id"].rsplit("/", 1)[1]
                    for field, suffix, label in (
                        ("x509_svid", "pem", "CERTIFICATE"),
                        ("x509_svid_key", "key", "PRIVATE KEY"),
                        ("bundle", "ca", "CERTIFICATE"),
                    ):
                        raw = base64.b64decode(svid[field])
                        pem = ssl.DER_cert_to_PEM_cert(raw).replace("CERTIFICATE", label)
                        (folder / f"{name}.{suffix}").write_text(pem)

            credentials()
            missing = subprocess.run(
                [
                    str(binary),
                    "--spiffe",
                    f"unix://{endpoint}",
                    "spiffe://fabric.test/missing",
                    "policy.json",
                ],
                cwd=folder,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(missing.stdout, "")
            with subprocess.Popen(
                [
                    str(binary),
                    "--spiffe",
                    f"unix://{endpoint}",
                    "spiffe://fabric.test/runtime",
                    "policy.json",
                ],
                cwd=folder,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as process:
                assert process.stdout is not None
                try:
                    self.assertTrue(
                        select.select([process.stdout], [], [], 15)[0],
                        "SPIFFE runtime startup deadline",
                    )
                    line = process.stdout.readline()
                    self.assertTrue(line, "SPIFFE runtime did not start")
                    address, boot = line.split()
                    port = int(address.rsplit(":", 1)[1])
                    request = {
                        "schema_version": "1",
                        "attempt": {
                            "schema_version": "1",
                            "tenant_scope": "tenant-a",
                            "operation_id": "op",
                            "workflow_epoch": "1",
                            "attempt_epoch": "2",
                            "fence": "3",
                        },
                        "manifest_digest": "a" * 64,
                        "purpose": "COMPUTE_READ",
                    }
                    token = "b" * 64

                    def publish(name, expires, *, epoch=boot, legacy=False):
                        document = {
                            "boot_id": epoch,
                            "grants": [
                                {
                                    (
                                        "certificate_sha256" if legacy else "spiffe_id"
                                    ): f"spiffe://fabric.test/{name}",
                                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                                    "scope": request,
                                    "expires_unix_ms": expires,
                                }
                            ],
                        }
                        temporary = folder / "policy.next"
                        temporary.write_text(json.dumps(document))
                        temporary.replace(folder / "policy.json")

                    server_certs = []

                    def post(name, body=request):
                        tls = ssl.create_default_context(cafile=str(folder / "runtime.ca"))
                        tls.check_hostname = False
                        if name:
                            tls.load_cert_chain(folder / f"{name}.pem", folder / f"{name}.key")
                        conn = http.client.HTTPSConnection(
                            "127.0.0.1", port, context=tls, timeout=5
                        )
                        try:
                            conn.connect()
                            assert conn.sock is not None
                            certificate = conn.sock.getpeercert()
                            assert certificate is not None
                            self.assertEqual(
                                certificate["subjectAltName"],
                                (("URI", "spiffe://fabric.test/runtime"),),
                            )
                            server_certs.append(conn.sock.getpeercert(binary_form=True))
                            conn.request(
                                "POST",
                                "/v1/artifact-access/authorize",
                                json.dumps(body),
                                {
                                    "Authorization": f"Bearer {token}",
                                    "X-Workload-Identity": "spiffe://fabric.test/worker",
                                    "Content-Type": "application/json",
                                },
                            )
                            response = conn.getresponse()
                            return response.status, response.read()
                        finally:
                            conn.close()

                    expires = time.time_ns() // 1_000_000 + 45_000
                    publish("worker", expires)
                    # TLS rejection can arrive during the body write, before the alert is read.
                    with self.assertRaises(
                        (ssl.SSLError, http.client.RemoteDisconnected, BrokenPipeError)
                    ):
                        post(None)
                    self.assertEqual(post("other")[0], 403)
                    for field, value in {
                        "tenant_scope": "tenant-b",
                        "operation_id": "different",
                        "workflow_epoch": "4",
                        "attempt_epoch": "4",
                        "fence": "4",
                    }.items():
                        body = {**request, "attempt": {**request["attempt"], field: value}}
                        self.assertEqual(post("worker", body)[0], 403)
                    self.assertEqual(
                        post("worker", {**request, "purpose": "EVIDENCE_READ"})[0], 403
                    )
                    self.assertEqual(post("worker", {**request, "secret": token})[0], 400)
                    publish("worker", 1)
                    self.assertEqual(post("worker")[0], 403)
                    publish("worker", expires, epoch="0" * 64)
                    self.assertEqual(post("worker")[0], 403)
                    publish("worker", expires, legacy=True)
                    self.assertEqual(post("worker")[0], 403)
                    publish("worker", expires)
                    self.assertEqual(
                        post("worker", {**request, "manifest_digest": "f" * 64})[0], 403
                    )
                    # Self-issued CNs and forged SPIFFE URIs cannot replace SVIDs.
                    for san in ("DNS:worker", "URI:spiffe://fabric.test/worker"):
                        subprocess.run(
                            [
                                "openssl",
                                "req",
                                "-x509",
                                "-newkey",
                                "ec",
                                "-pkeyopt",
                                "ec_paramgen_curve:P-256",
                                "-nodes",
                                "-days",
                                "1",
                                "-subj",
                                "/CN=worker",
                                "-addext",
                                f"subjectAltName={san}",
                                "-keyout",
                                str(folder / "forged.key"),
                                "-out",
                                str(folder / "forged.pem"),
                            ],
                            check=True,
                            capture_output=True,
                            timeout=10,
                        )
                        with self.assertRaises(
                            (ssl.SSLError, http.client.RemoteDisconnected, BrokenPipeError)
                        ):
                            post("forged")
                    with spire(folder / "foreign", "foreign.test") as (_, foreign_fetch):
                        foreign = foreign_fetch()["svids"][0]
                        for field, suffix, label in (
                            ("x509_svid", "pem", "CERTIFICATE"),
                            ("x509_svid_key", "key", "PRIVATE KEY"),
                        ):
                            (folder / f"foreign.{suffix}").write_text(
                                ssl.DER_cert_to_PEM_cert(base64.b64decode(foreign[field])).replace(
                                    "CERTIFICATE", label
                                )
                            )
                        with self.assertRaises(
                            (ssl.SSLError, http.client.RemoteDisconnected, BrokenPipeError)
                        ):
                            post("foreign")
                    credentials()
                    status, response = post("worker")
                    self.assertEqual(status, 200)
                    self.assertEqual(
                        json.loads(response),
                        {
                            "schema_version": "1",
                            "expires_unix_ms": str(expires),
                        },
                    )
                    self.assertEqual(post("worker")[0], 403)

                    old_server = server_certs[-1]
                    old = (folder / "worker.pem").read_text()
                    (folder / "expired.pem").write_text(old)
                    (folder / "expired.key").write_bytes((folder / "worker.key").read_bytes())
                    token = "c" * 64
                    expires = time.time_ns() // 1_000_000 + 45_000
                    publish("worker", expires)
                    deadline = time.monotonic() + 30
                    while (folder / "worker.pem").read_text() == old:
                        self.assertLess(time.monotonic(), deadline, "SPIRE did not rotate the SVID")
                        time.sleep(0.5)
                        credentials()
                    # No grant/policy rewrite between publication and rotated credentials.
                    self.assertEqual(post("worker")[0], 200)
                    self.assertNotEqual(
                        server_certs[-1], old_server, "server Workload API SVID did not rotate"
                    )
                    not_after = (
                        subprocess.run(
                            [
                                "openssl",
                                "x509",
                                "-in",
                                str(folder / "expired.pem"),
                                "-noout",
                                "-enddate",
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        .stdout.strip()
                        .split("=", 1)[1]
                    )
                    expiry = ssl.cert_time_to_seconds(not_after)
                    while time.time() <= expiry + 1:
                        self.assertLess(time.monotonic(), deadline, "old SVID did not expire")
                        time.sleep(0.2)
                    with self.assertRaises(
                        (ssl.SSLError, http.client.RemoteDisconnected, BrokenPipeError)
                    ):
                        post("expired")
                    credentials()
                    token = "d" * 64
                    publish("worker", expires)
                    (folder / "policy.json").unlink()
                    self.assertEqual(post("worker")[0], 403)
                    publish("worker", expires)
                    self.assertEqual(post("worker")[0], 200)
                finally:
                    process.terminate()
                    _, audit = process.communicate(timeout=5)
            self.assertIn("runtime_auth_denied", audit)
            for sensitive in ("tenant-a", "a" * 64, "b" * 64, "c" * 64, "d" * 64):
                self.assertNotIn(sensitive, audit)

    def test_no_legacy_or_unavailable_provider_fallback(self):
        binary = ROOT / os.environ.get("CARGO_TARGET_DIR", "target") / "debug/fabric-runtime"
        for args in (
            ("--mtls", "cert", "key", "ca", "policy"),
            (
                "--spiffe",
                "unix:///nonexistent-fabric-agent.sock",
                "spiffe://fabric.test/runtime",
                "policy",
            ),
        ):
            result = subprocess.run(
                [str(binary), *args], capture_output=True, text=True, timeout=15
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
