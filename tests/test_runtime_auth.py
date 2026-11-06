"""Live certificate and policy tests for the Fabric runtime."""

import hashlib
import http.client
import json
import os
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RuntimeAuthorizationTests(unittest.TestCase):
    def test_verified_workload_and_exact_scope(self):
        target = ROOT / os.environ.get("CARGO_TARGET_DIR", "target")
        binary = target / "debug/fabric-runtime"
        self.assertTrue(binary.is_file(), "Build fabric-runtime with cargo build --locked first")
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)

            def openssl(*args):
                subprocess.run(
                    ["openssl", *args], cwd=folder, check=True, capture_output=True, timeout=10
                )

            openssl(
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
                "/CN=Fabric Test Root",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
            )
            for name in ("server", "worker", "rotated"):
                openssl(
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    f"/CN={name}",
                    "-keyout",
                    f"{name}.key",
                    "-out",
                    f"{name}.csr",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                )
                openssl(
                    "x509",
                    "-req",
                    "-days",
                    "1",
                    "-in",
                    f"{name}.csr",
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-copy_extensions",
                    "copy",
                    "-out",
                    f"{name}.pem",
                )
            with subprocess.Popen(
                [str(binary), "--mtls", "server.pem", "server.key", "ca.pem", "policy.json"],
                cwd=folder,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as process:
                assert process.stdout is not None
                try:
                    address, boot = process.stdout.readline().split()
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

                    def publish(name, expires, *, epoch=boot):
                        cert = ssl.PEM_cert_to_DER_cert((folder / f"{name}.pem").read_text())
                        document = {
                            "boot_id": epoch,
                            "grants": [
                                {
                                    "certificate_sha256": hashlib.sha256(cert).hexdigest(),
                                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                                    "scope": request,
                                    "expires_unix_ms": expires,
                                }
                            ],
                        }
                        temporary = folder / "policy.next"
                        temporary.write_text(json.dumps(document))
                        temporary.replace(folder / "policy.json")

                    def post(name, body=request):
                        tls = ssl.create_default_context(cafile=str(folder / "ca.pem"))
                        if name:
                            tls.load_cert_chain(folder / f"{name}.pem", folder / f"{name}.key")
                        conn = http.client.HTTPSConnection(
                            "127.0.0.1", port, context=tls, timeout=5
                        )
                        try:
                            conn.request(
                                "POST",
                                "/v1/artifact-access/authorize",
                                json.dumps(body),
                                {
                                    "Authorization": f"Bearer {token}",
                                    "X-Workload-Identity": "worker",
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
                    self.assertEqual(post("rotated")[0], 403)
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
                    publish("worker", expires)
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

                    token = "c" * 64
                    publish("rotated", expires)
                    self.assertEqual(post("worker")[0], 403)
                    self.assertEqual(post("rotated")[0], 200)
                    token = "d" * 64
                    publish("rotated", expires)
                    (folder / "policy.json").unlink()
                    self.assertEqual(post("rotated")[0], 403)
                    publish("rotated", expires)
                    self.assertEqual(post("rotated")[0], 200)
                finally:
                    process.terminate()
                    _, audit = process.communicate(timeout=5)
            self.assertIn("runtime_auth_denied", audit)
            for sensitive in ("tenant-a", "a" * 64, "b" * 64, "c" * 64, "d" * 64):
                self.assertNotIn(sensitive, audit)
