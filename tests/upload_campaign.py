"""Linux resource and real transport interruption probes for the owned F-live runtime."""

import http.client
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

CHUNK = 4 * 1024 * 1024
TOTAL = 1024 * 1024 * 1024


def exercise(case, request, connect, issue, sql, process, tenant, attempt):
    def until(check):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.1)
        case.fail("upload cleanup/transport observation exceeded eight seconds")

    def s3(command, upload):
        result = subprocess.run(
            [
                "docker",
                "exec",
                os.environ["FABRIC_FIXTURE_S3_CLIENT"],
                "aws",
                "--endpoint-url",
                "http://s3:8333",
                "s3api",
                command,
                "--bucket",
                "fabric-runtime",
            ],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        case.assertEqual(result.returncode, 0, "private S3 observation failed")
        data = json.loads(result.stdout)
        return [
            item
            for item in data.get("Uploads", data.get("Contents", []))
            if item["Key"].startswith(f"staging/{upload}/")
        ]

    def reserve(size):
        status, result = request(
            "POST",
            "/v1/uploads",
            issue(),
            {
                "schema_version": "1",
                "tenant_scope": tenant,
                "byte_length": size,
            },
        )
        case.assertEqual(status, 201)
        return result["upload_id"]

    def abort(upload):
        case.assertEqual(
            request(
                "POST",
                f"/v1/uploads/{upload}/abort",
                issue(),
                {
                    "schema_version": "1",
                    "attempt": attempt,
                },
            )[0],
            204,
        )
        case.assertEqual(
            sql(f"SELECT count(*) FROM fabric_uploads WHERE id='{upload}'").strip(), "0"
        )
        case.assertFalse(s3("list-objects-v2", upload))
        case.assertFalse(s3("list-multipart-uploads", upload))

    # Measure the runtime process, not the Python generator or fixture containers.
    rss_file = Path(f"/proc/{process.pid}/status")

    def memory(field):
        return (
            int(
                next(
                    line.split()[1]
                    for line in rss_file.read_text().splitlines()
                    if line.startswith(field + ":")
                )
            )
            * 1024
        )

    baseline = memory("VmRSS")
    virtual_baseline = memory("VmPeak")
    peaks = [baseline]
    stopped = threading.Event()

    def sample():
        while not stopped.wait(0.01):
            peaks.append(memory("VmRSS"))

    sampler = threading.Thread(target=sample)
    sampler.start()
    try:
        upload = reserve(TOTAL)
        case.assertEqual(
            request("PUT", f"/v1/uploads/{upload}/parts/0", issue(), b"", length=TOTAL)[0], 413
        )
        case.assertEqual(
            request(
                "PUT",
                f"/v1/uploads/{upload}/parts/0",
                issue(),
                (b"m" * 65536 for _ in range(64)),
                length=CHUNK,
            )[0],
            204,
        )
        case.assertEqual(
            sql(f"SELECT received_bytes FROM fabric_uploads WHERE id='{upload}'").strip(),
            str(CHUNK),
        )
        abort(upload)
    finally:
        stopped.set()
        sampler.join()
    peak = max(peaks + [memory("VmHWM")])
    virtual_growth = memory("VmPeak") - virtual_baseline
    case.assertLess(virtual_growth, 128 * 1024 * 1024, "runtime virtual peak grew beyond 128 MiB")
    case.assertLess(peak - baseline, 64 * 1024 * 1024, "runtime RSS grew beyond 64 MiB")
    case.assertLess(peak, 192 * 1024 * 1024, "runtime RSS exceeded 192 MiB")

    for mode in ("disconnect", "stall", "expiry"):
        with case.subTest(interruption=mode):
            upload = reserve(CHUNK)
            token = issue(ttl_ms=2500) if mode == "expiry" else issue()
            conn = connect()
            try:
                conn.connect()
                conn.putrequest("PUT", f"/v1/uploads/{upload}/parts/0")
                conn.putheader("Authorization", f"Bearer {token}")
                conn.putheader("Content-Length", "8192")
                conn.endheaders()
                conn.send(b"x" * 4096)
                # Observe a real S3 session before interrupting the transport.
                until(lambda upload=upload: bool(s3("list-multipart-uploads", upload)))
                if mode == "disconnect":
                    assert conn.sock is not None
                    conn.sock.shutdown(socket.SHUT_RDWR)
                    conn.close()
                elif mode == "stall":
                    started = time.monotonic()
                    try:
                        conn.getresponse()
                    except http.client.RemoteDisconnected:
                        pass
                    else:
                        case.fail("stalled upload connection was not closed")
                    case.assertLess(time.monotonic() - started, 10)
                else:
                    time.sleep(2.6)
                    conn.send(b"x" * 4096)
                    response = conn.getresponse()
                    case.assertEqual(response.status, 403)
                    case.assertEqual(json.loads(response.read())["code"], "FORBIDDEN")
            finally:
                conn.close()
            until(lambda upload=upload: not s3("list-multipart-uploads", upload))
            case.assertFalse(s3("list-objects-v2", upload))
            case.assertEqual(
                sql(
                    f"SELECT count(*) FROM fabric_finalized_artifacts WHERE upload_id='{upload}'"
                ).strip(),
                "0",
            )
            case.assertEqual(request("GET", f"/v1/uploads/{upload}", issue())[0], 404)
            case.assertEqual(
                sql(f"SELECT received_bytes FROM fabric_uploads WHERE id='{upload}'").strip(), "0"
            )
            case.assertEqual(
                sql(f"SELECT count(*) FROM fabric_upload_parts WHERE upload_id='{upload}'").strip(),
                "0",
            )
            # A fresh capability can reuse the failed part index, proving SQL rollback.
            case.assertEqual(
                request("PUT", f"/v1/uploads/{upload}/parts/0", issue(), b"retry")[0], 204
            )
            abort(upload)
    print(
        f"Upload campaign runtime RSS baseline={baseline} peak={peak} "
        f"virtual_peak_growth={virtual_growth} bytes",
        flush=True,
    )
    print("UPLOAD_FAILURE_CAMPAIGN_PASSED", flush=True)
