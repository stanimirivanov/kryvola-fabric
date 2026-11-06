"""Fresh races, actual process death and real SQL/S3 wire failures for F-live."""

import concurrent.futures
import http.client
import json
import os
import ssl
import subprocess
import time

from s3_fault_proxy import S3FaultProxy


def exercise(
    case,
    request,
    connect,
    issue,
    sql,
    restart,
    refresh,
    configure,
    endpoint,
    tenant,
    manifest,
    digest,
):
    publication = {"schema_version": "1", "tenant_scope": tenant, "manifest_digest": digest}
    expected = {"schema_version": "1", "manifest_digest": digest}
    client = os.environ["FABRIC_FIXTURE_S3_CLIENT"]

    def aws(*args):
        result = subprocess.run(
            ["docker", "exec", client, "aws", "--endpoint-url", "http://s3:8333", *args],
            capture_output=True,
            timeout=10,
        )
        case.assertEqual(result.returncode, 0, "private S3 observation/cleanup failed")
        return result.stdout

    def objects(upload):
        data = aws(
            "s3api",
            "list-objects-v2",
            "--bucket",
            "fabric-runtime",
            "--prefix",
            f"immutable/{upload}/",
        )
        return json.loads(data).get("Contents", [])

    def committed(upload):
        return sql(
            f"SELECT encode(canonical_manifest,'hex') FROM fabric_finalized_artifacts "
            f"WHERE upload_id='{upload}'"
        ).strip()

    def valid(upload):
        case.assertEqual(committed(upload), manifest.hex())
        case.assertEqual(
            sql(
                f"SELECT manifest_digest FROM fabric_finalized_artifacts WHERE upload_id='{upload}'"
            ).strip(),
            digest,
        )
        case.assertEqual(len(objects(upload)), 1)
        aws(
            "s3api",
            "get-object",
            "--bucket",
            "fabric-runtime",
            "--key",
            f"immutable/{upload}/0",
            "/tmp/fabric49-bytes",
        )
        result = subprocess.run(
            ["docker", "exec", client, "cat", "/tmp/fabric49-bytes"],
            capture_output=True,
            check=True,
            timeout=5,
        )
        case.assertEqual(result.stdout, bytes([0, 1, 2, 255]))

    def clear(upload):
        for namespace in ("staging", "immutable"):
            aws("s3", "rm", f"s3://fabric-runtime/{namespace}/{upload}/", "--recursive")
        sql(
            f"DELETE FROM fabric_finalized_artifacts WHERE upload_id='{upload}'; "
            f"DELETE FROM fabric_uploads WHERE id='{upload}'"
        )

    def prepare():
        refresh()
        # Owned fixture setup only; no production renewal API is claimed.
        sql(
            "UPDATE fabric_attempts SET lease_expires_unix_ms="
            "floor(extract(epoch FROM clock_timestamp())*1000)+60000 "
            "WHERE operation_id='upload-http'"
        )
        status, reserved = request(
            "POST",
            "/v1/uploads",
            issue(),
            {"schema_version": "1", "tenant_scope": tenant, "byte_length": 4},
        )
        case.assertEqual(status, 201)
        upload = reserved["upload_id"]
        case.assertEqual(
            request("PUT", f"/v1/uploads/{upload}/parts/0", issue(), bytes([0, 1, 2, 255]))[0], 204
        )
        case.assertEqual(
            request("PUT", f"/v1/uploads/{upload}/manifest", issue(), manifest)[0], 204
        )
        case.assertFalse(objects(upload), "race/recovery must start without an immutable copy")
        case.assertFalse(committed(upload))
        return upload, f"/v1/uploads/{upload}/finalize"

    def outcome(future):
        try:
            return future.result(timeout=14)
        except http.client.RemoteDisconnected, ConnectionResetError, ssl.SSLError:
            return None

    with (
        S3FaultProxy(endpoint) as proxy,
        concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool,
    ):
        configure(proxy.endpoint)
        restart()
        upload, path = prepare()
        tokens = [issue(), issue()]
        results = list(pool.map(lambda token: request("POST", path, token, publication), tokens))
        case.assertEqual(results, [(200, expected), (200, expected)])
        valid(upload)
        case.assertEqual(request("PUT", f"/v1/uploads/{upload}/parts/0", issue(), b"evil")[0], 409)
        case.assertEqual(
            request("POST", path, issue(), {**publication, "manifest_digest": "e" * 64})[0], 403
        )
        valid(upload)
        clear(upload)
        print("Finalization boundary passed: fresh-race", flush=True)

        for phase in (
            "before",
            "after",
            "unavailable",
            "lost_ack",
            "before_insert",
            "after_insert",
            "commit",
            "db_disconnect",
            "response_lost",
            "conflicting_copy",
        ):
            with case.subTest(finalization_boundary=phase):
                upload, path = prepare()
                token = issue()
                key = f"/immutable/{upload}/0"
                try:
                    if phase in ("before", "after", "unavailable", "lost_ack", "conflicting_copy"):
                        mode = "after" if phase == "conflicting_copy" else phase
                        hit, release = proxy.arm(mode, key)
                        future = pool.submit(request, "POST", path, token, publication)
                        case.assertTrue(hit.wait(7), "real immutable request boundary not reached")
                        if mode in ("before", "after"):
                            restart()  # Actual SIGKILL; SQLx/S3 connections die with the process.
                            release.set()
                        result = outcome(future)
                        if mode == "before":
                            case.assertFalse(objects(upload))
                        if mode == "after":
                            case.assertEqual(len(objects(upload)), 1)
                        if mode != "lost_ack":
                            case.assertFalse(committed(upload))
                        if phase == "conflicting_copy":
                            # Corrupt the genuine crash-created object; never pre-seed the race.
                            subprocess.run(
                                [
                                    "docker",
                                    "exec",
                                    client,
                                    "sh",
                                    "-ec",
                                    "printf evil > /tmp/fabric49-evil",
                                ],
                                check=True,
                                capture_output=True,
                                timeout=5,
                            )
                            aws(
                                "s3api",
                                "put-object",
                                "--bucket",
                                "fabric-runtime",
                                "--key",
                                f"immutable/{upload}/0",
                                "--body",
                                "/tmp/fabric49-evil",
                            )
                        if mode == "unavailable":
                            case.assertTrue(result is None or result[0] == 503)
                        if mode == "lost_ack":
                            case.assertTrue(result is None or result[0] in (200, 503))
                            if result and result[0] == 200:
                                valid(upload)
                            if committed(upload):
                                case.assertEqual(mode, "lost_ack")
                                valid(upload)
                        proxy.arm("", "")
                    elif phase == "response_lost":
                        conn = connect()
                        try:
                            conn.request(
                                "POST",
                                path,
                                json.dumps(publication),
                                {"Authorization": f"Bearer {token}"},
                            )
                            deadline = time.monotonic() + 7
                            while not committed(upload) and time.monotonic() < deadline:
                                time.sleep(0.05)
                            valid(upload)
                            restart()  # Kill after commit without consuming any response.
                        finally:
                            conn.close()
                    else:
                        timing = (
                            "BEFORE" if phase in ("before_insert", "db_disconnect") else "AFTER"
                        )
                        deferred = "CONSTRAINT " if phase == "commit" else ""
                        constraint = "DEFERRABLE INITIALLY DEFERRED " if phase == "commit" else ""
                        action = (
                            "PERFORM pg_advisory_xact_lock(49049); PERFORM pg_sleep(30);"
                            if phase == "db_disconnect"
                            else "RAISE EXCEPTION 'fixture SQL fault';"
                        )
                        sql(
                            "CREATE FUNCTION fabric49_fault() RETURNS trigger "
                            "LANGUAGE plpgsql AS $$ "
                            f"BEGIN {action} RETURN NEW; END $$; "
                            f"CREATE {deferred}TRIGGER fabric49_fault "
                            f"{timing} INSERT ON fabric_finalized_artifacts "
                            f"{constraint}FOR EACH ROW "
                            f"WHEN (NEW.upload_id='{upload}') EXECUTE FUNCTION fabric49_fault()"
                        )
                        future = pool.submit(request, "POST", path, token, publication)
                        if phase == "db_disconnect":
                            pid = ""
                            deadline = time.monotonic() + 7
                            while not pid and time.monotonic() < deadline:
                                pid = sql(
                                    "SELECT pid FROM pg_locks WHERE locktype='advisory' "
                                    "AND objid=49049 AND granted"
                                ).strip()
                            case.assertTrue(pid, "real SQL boundary not reached")
                            case.assertEqual(
                                sql(f"SELECT pg_terminate_backend({int(pid)})").strip(), "t"
                            )
                        case.assertEqual(outcome(future)[0], 503)
                        case.assertFalse(committed(upload))
                        case.assertEqual(len(objects(upload)), 1)
                finally:
                    proxy.arm("", "")
                    sql(
                        "DROP TRIGGER IF EXISTS fabric49_fault ON fabric_finalized_artifacts; "
                        "DROP FUNCTION IF EXISTS fabric49_fault()"
                    )
                if phase == "conflicting_copy":
                    case.assertEqual(request("POST", path, issue(), publication)[0], 400)
                    case.assertFalse(committed(upload))
                    aws(
                        "s3api",
                        "get-object",
                        "--bucket",
                        "fabric-runtime",
                        "--key",
                        f"immutable/{upload}/0",
                        "/tmp/fabric49-conflict",
                    )
                    result = subprocess.run(
                        ["docker", "exec", client, "cat", "/tmp/fabric49-conflict"],
                        capture_output=True,
                        check=True,
                        timeout=5,
                    )
                    case.assertEqual(
                        result.stdout, b"evil", "retry must not overwrite immutable bytes"
                    )
                else:
                    case.assertEqual(request("POST", path, issue(), publication), (200, expected))
                    valid(upload)
                clear(upload)
                print(f"Finalization boundary passed: {phase}", flush=True)
    print("FINALIZATION_RECOVERY_PASSED", flush=True)
