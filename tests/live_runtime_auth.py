"""Live certificate and policy tests for the Fabric runtime."""

import base64
import concurrent.futures
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
            spire(Path(directory) / "spire", ttl=45) as (endpoint, fetch, agent),
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
            # The negative startup probe can outlast these deliberately short SVIDs.
            credentials()
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

                    def post(name, body=request, *, credential=True, slow=False, send_at=None):
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
                            headers = {
                                "Content-Type": "application/json",
                                "X-Workload-Identity": "spiffe://fabric.test/worker",
                            }
                            if credential:
                                headers["Authorization"] = f"Bearer {token}"
                            if slow:
                                headers["Content-Length"] = "100"
                            if send_at is not None:
                                payload = json.dumps(body).encode()
                                conn.putrequest("POST", "/v1/artifact-access/authorize")
                                for key, value in headers.items():
                                    conn.putheader(key, value)
                                conn.putheader("Content-Length", str(len(payload)))
                                conn.endheaders()
                                time.sleep(max(0, send_at - time.time()))
                                conn.send(payload)
                            else:
                                conn.request(
                                    "POST",
                                    "/v1/artifact-access/authorize",
                                    None if slow else json.dumps(body),
                                    headers,
                                )
                            response = conn.getresponse()
                            return response.status, response.read()
                        finally:
                            conn.close()

                    expires = time.time_ns() // 1_000_000 + 45_000
                    publish("worker", expires)
                    # TLS rejection can arrive during the body write, before the alert is read.
                    with self.assertRaises(
                        (
                            ssl.SSLError,
                            http.client.RemoteDisconnected,
                            BrokenPipeError,
                            ConnectionResetError,
                        )
                    ):
                        post(None)
                    self.assertEqual(post("worker", credential=False)[0], 403)
                    saved = token
                    token = "malformed-secret-credential"
                    self.assertEqual(post("worker")[0], 403)
                    token = saved
                    self.assertEqual(post("worker", {"secret": "x" * 65536})[0], 413)
                    self.assertEqual(post("worker", slow=True)[0], 408)
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
                    publish("worker", time.time_ns() // 1_000_000 + 61_000)
                    self.assertEqual(post("worker")[0], 403)
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
                            (
                                ssl.SSLError,
                                http.client.RemoteDisconnected,
                                BrokenPipeError,
                                ConnectionResetError,
                            )
                        ):
                            post("forged")
                    with spire(folder / "foreign", "foreign.test") as (_, foreign_fetch, _):
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
                            (
                                ssl.SSLError,
                                http.client.RemoteDisconnected,
                                BrokenPipeError,
                                ConnectionResetError,
                            )
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

                    token = "9" * 64
                    publish("worker", time.time_ns() // 1_000_000 + 45_000)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                        results = list(pool.map(post, ("worker", "worker")))
                    self.assertEqual(sorted(status for status, _ in results), [200, 403])
                    old_server = server_certs[-1]
                    old = (folder / "worker.pem").read_text()
                    (folder / "expired.pem").write_text(old)
                    (folder / "expired.key").write_bytes((folder / "worker.key").read_bytes())
                    token = "c" * 64
                    expires = time.time_ns() // 1_000_000 + 45_000
                    publish("worker", expires)
                    deadline = time.monotonic() + 60
                    while (folder / "worker.pem").read_text() == old:
                        self.assertLess(time.monotonic(), deadline, "SPIRE did not rotate the SVID")
                        time.sleep(0.5)
                        credentials()
                    # No grant/policy rewrite between publication and rotated credentials.
                    self.assertEqual(post("worker")[0], 200)
                    # Workload API readers observe the same update asynchronously.
                    while server_certs[-1] == old_server:
                        self.assertLess(time.monotonic(), deadline, "server SVID did not rotate")
                        time.sleep(0.1)
                        self.assertEqual(post("worker")[0], 403)  # Already consumed token.

                    def cert_expiry(name):
                        result = subprocess.run(
                            [
                                "openssl",
                                "x509",
                                "-in",
                                str(folder / f"{name}.pem"),
                                "-noout",
                                "-enddate",
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        return ssl.cert_time_to_seconds(result.stdout.strip().split("=", 1)[1])

                    expiry = cert_expiry("expired")
                    token = "8" * 64
                    publish("worker", time.time_ns() // 1_000_000 + 45_000)
                    while time.time() < expiry - 0.8:
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.1)
                    self.assertEqual(post("expired", send_at=expiry + 0.1)[0], 403)
                    while time.time() <= expiry + 1:
                        self.assertLess(time.monotonic(), deadline, "old SVID did not expire")
                        time.sleep(0.2)
                    with self.assertRaises(
                        (
                            ssl.SSLError,
                            http.client.RemoteDisconnected,
                            BrokenPipeError,
                            ConnectionResetError,
                        )
                    ):
                        post("expired")
                    credentials()
                    token = "d" * 64
                    publish("worker", expires)
                    (folder / "policy.json").unlink()
                    self.assertEqual(post("worker")[0], 403)
                    publish("worker", expires)
                    self.assertEqual(post("worker")[0], 200)
                    token = "e" * 64
                    publish("long", time.time_ns() // 1_000_000 + 45_000)
                    with self.assertRaises(
                        (
                            ssl.SSLError,
                            http.client.RemoteDisconnected,
                            BrokenPipeError,
                            ConnectionResetError,
                        )
                    ):
                        post("long")
                    deadline = time.monotonic() + 60
                    while cert_expiry("worker") - time.time() < 22:
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.2)
                        credentials()
                    agent.terminate()
                    agent.wait(timeout=5)
                    token = "f" * 64
                    publish("worker", time.time_ns() // 1_000_000 + 45_000)
                    self.assertEqual(post("worker")[0], 200)
                    time.sleep(16)
                    self.assertGreater(cert_expiry("worker"), time.time())
                    with self.assertRaises(
                        (
                            ssl.SSLError,
                            http.client.RemoteDisconnected,
                            BrokenPipeError,
                            ConnectionResetError,
                        )
                    ):
                        post("worker")
                finally:
                    process.terminate()
                    _, audit = process.communicate(timeout=5)
            reasons = {line.removeprefix("runtime_auth_denied ") for line in audit.splitlines()}
            self.assertTrue(
                {
                    "credential",
                    "policy",
                    "expiry",
                    "replay",
                    "invalid_scope",
                    "body",
                    "deadline",
                    "handshake",
                    "identity",
                    "provider",
                }
                <= reasons,
                reasons,
            )
            self.assertTrue(
                all(line.startswith("runtime_auth_denied ") for line in audit.splitlines())
            )
            for sensitive in (
                "tenant-a",
                "fabric.test",
                "malformed-secret-credential",
                *[c * 64 for c in "abcdef98"],
            ):
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
