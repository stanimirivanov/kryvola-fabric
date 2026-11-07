"""Drive both lock orders through HTTPS and validate the observed release traces."""

import concurrent.futures
import copy
import hashlib
import json
import subprocess
import time
from typing import Any

from selection_trace import REGISTER, ROOT, SELECT, check_trace

SELECT_GATE = 55001
BARRIER_GATE = 55002


def wait_for(sql, query):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        result = sql(query).strip()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError("PostgreSQL contention was not observed")


def race(sql, container, first, second, first_gate, snapshot):
    """The first request holds the operation row while its INSERT waits at the gate."""
    holder = subprocess.Popen(
        ["docker", "exec", "-i", container, "psql", "-U", "postgres", "-XqtA"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def send(statement):
        assert holder.stdin is not None
        holder.stdin.write(statement + "\n")
        holder.stdin.flush()

    other_gate = BARRIER_GATE if first_gate == SELECT_GATE else SELECT_GATE
    try:
        send(f"SELECT pg_advisory_lock({SELECT_GATE}), pg_advisory_lock({BARRIER_GATE});")
        wait_for(
            sql,
            "SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted "
            f"AND objid IN ({SELECT_GATE},{BARRIER_GATE}) GROUP BY pid HAVING count(*)=2",
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            early = pool.submit(first)
            pid = int(
                wait_for(
                    sql,
                    "SELECT pid FROM pg_locks WHERE locktype='advisory' AND NOT granted "
                    f"AND objid={first_gate}",
                )
            )
            late = pool.submit(second)
            blocked = int(
                wait_for(
                    sql,
                    f"SELECT pid FROM pg_stat_activity WHERE {pid}=ANY(pg_blocking_pids(pid))",
                )
            )
            before = snapshot()
            send(f"SELECT pg_advisory_unlock({first_gate});")
            first_response = early.result(timeout=8)
            between = snapshot()
            send(f"SELECT pg_advisory_unlock({other_gate});")
            second_response = late.result(timeout=8)
            return [first_response, second_response], [before, between, snapshot()], [pid, blocked]
    finally:
        if holder.stdin is not None:
            holder.stdin.close()
        try:
            holder.wait(timeout=5)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait(timeout=5)


def exercise(
    case,
    request,
    issue,
    sql,
    operation,
    scope,
    coordinator,
    authorize,
    canonical,
    publish,
    restart,
    container,
):
    path = "state/v1/release.oracle.json"
    raw = (ROOT / "contracts/spec" / path).read_bytes()
    oracle_hash = hashlib.sha256(raw).hexdigest()
    manifest = json.loads((ROOT / "contracts/spec/manifest.json").read_bytes())
    case.assertEqual(oracle_hash, manifest["files"][path])
    oracle = json.loads(raw)
    digest = scope["manifest_digest"]
    tenant = operation["tenant_scope"]
    evidence = {}

    def post(path, token, body):
        return request("POST", path, token, body, name="coordinator")

    sql(
        "CREATE FUNCTION fixture_gate_fencing() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.operation_id LIKE 'barrier-race-%' THEN "
        "PERFORM pg_advisory_xact_lock(TG_ARGV[0]::bigint); END IF; RETURN NEW; END $$; "
        "CREATE TRIGGER fixture_gate_selection BEFORE INSERT ON fabric_selected_results "
        f"FOR EACH ROW EXECUTE FUNCTION fixture_gate_fencing('{SELECT_GATE}'); "
        "CREATE TRIGGER fixture_gate_barrier BEFORE INSERT ON fabric_operation_barriers "
        f"FOR EACH ROW EXECUTE FUNCTION fixture_gate_fencing('{BARRIER_GATE}');"
    )

    def scenario(kind, selection_first):
        label = f"{kind}-{'selection' if selection_first else 'barrier'}-first"
        op = f"barrier-race-{label}"
        key = f"operation_id='{op}'"
        operation.update(
            operation_id=op,
            idempotency_key=op,
            deadline_unix_ms=str(time.time_ns() // 1_000_000 + 120_000),
        )
        publish()
        case.assertEqual(
            post(
                "/v1/operations",
                coordinator,
                {
                    "schema_version": "1",
                    "operation": operation,
                    "input_manifest_digests": ["a" * 64],
                },
            )[0],
            200,
        )
        identity = {"tenant_scope": tenant, "operation_id": op, "workflow_epoch": "0"}
        ensure = {
            "schema_version": "1",
            "attempt": {
                "schema_version": "1",
                **identity,
                "attempt_epoch": "1",
            },
        }
        status, lease = post("/v1/attempts/ensure", coordinator, ensure)
        case.assertEqual(status, 200)
        scope["attempt"] = lease["attempt"]
        execution_token = authorize(lease["attempt"])
        registration = {
            "schema_version": "1",
            "attempt": lease["attempt"],
            "execution_id": "1-1",
            "plan_digest": operation["plan_ref"]["plan_digest"],
            "policy_digest": operation["policy_digest"],
        }
        for execution in ("1-1", "1-2"):
            case.assertEqual(
                post(
                    REGISTER,
                    execution_token,
                    {
                        **registration,
                        "execution_id": execution,
                    },
                )[0],
                204,
            )
        status, upload_result = request(
            "POST",
            "/v1/uploads",
            issue(),
            {
                "schema_version": "1",
                "tenant_scope": tenant,
                "byte_length": 4,
            },
        )
        case.assertEqual(status, 201)
        upload = upload_result["upload_id"]
        url = f"/v1/uploads/{upload}"
        case.assertEqual(request("PUT", url + "/parts/0", issue(), bytes([0, 1, 2, 255]))[0], 204)
        case.assertEqual(request("PUT", url + "/manifest", issue(), canonical)[0], 204)
        case.assertEqual(
            request(
                "POST",
                url + "/finalize",
                issue(),
                {
                    "schema_version": "1",
                    "tenant_scope": tenant,
                    "manifest_digest": digest,
                },
            )[0],
            200,
        )
        selection = {
            "schema_version": "1",
            "attempt": lease["attempt"],
            "execution_id": "1-1",
            "output_manifest_digest": digest,
        }
        recovery = kind == "recovery"
        route, action = {
            "public": ("/v1/operations/cancel", "CANCEL_OPERATION"),
            "admin": ("/v1/admin/operations/cancel", "ADMIN_CANCEL"),
            "recovery": ("/v1/admin/operations/fence-recovery", "ADMIN_RECOVERY"),
        }[kind]
        barrier_token = authorize(identity, (action,))
        body = {"schema_version": "1", "tenant_scope": tenant, "operation_id": op}
        body.update({"workflow_epoch": "0"} if recovery else {"idempotency_key": op})

        def snapshot():
            return json.loads(
                sql(
                    "SELECT json_build_object("
                    "'workflow', (SELECT intent->>'workflow_epoch' FROM fabric_operations "
                    f"WHERE {key}), "
                    "'attempts', (SELECT json_agg(a) FROM (SELECT attempt_epoch AS epoch, fence, "
                    "retired, NOT retired AND lease_expires_unix_ms > "
                    "extract(epoch FROM clock_timestamp())*1000 "
                    f"AS live FROM fabric_attempts WHERE {key} ORDER BY attempt_epoch) a), "
                    "'executions', (SELECT json_agg(e) FROM (SELECT execution_id AS id, "
                    f"attempt_epoch AS epoch, fence FROM fabric_executions JOIN fabric_attempts "
                    f"USING (tenant_scope, operation_id, attempt_epoch) WHERE {key} "
                    "ORDER BY execution_id) e), "
                    "'winner', (SELECT row_to_json(s) FROM fabric_selected_results s "
                    f"WHERE {key}), "
                    "'barrier', (SELECT row_to_json(b) FROM fabric_operation_barriers b "
                    f"WHERE {key}), "
                    "'artifact', (SELECT manifest_digest FROM fabric_finalized_artifacts "
                    f"WHERE upload_id='{upload}'), "
                    "'events', (SELECT json_agg(kind ORDER BY kind) FROM fabric_outbox "
                    f"WHERE {key}))"
                )
            )

        def project(observed, cancellation="NONE"):
            barrier = observed["barrier"]
            successor = barrier and barrier["recovery_epoch"]
            winner = observed["winner"]
            executions = observed["executions"]
            selected = next(
                (row for row in executions if winner and row["id"] == winner["execution_id"]),
                None,
            )
            return {
                "workflowEpoch": successor if successor is not None else int(observed["workflow"]),
                "run": 0,
                "suspended": successor is not None,
                "compute": {
                    "now": 0,
                    "attempts": []
                    if successor is not None
                    else [
                        {
                            "epoch": row["epoch"],
                            "fence": row["fence"],
                            "until": 1,
                            "retired": row["retired"] if barrier is None else False,
                            "intent": True,
                        }
                        for row in observed["attempts"]
                    ],
                    "executions": []
                    if successor is not None
                    else [{**row, "done": observed["artifact"] == digest} for row in executions],
                    "selected": None if successor is not None else selected,
                },
                "selectedEpoch": int(observed["workflow"])
                if selected and successor is None
                else None,
                "cancel": cancellation,
                "revoked": False,
                "evidence": None,
                "authorization": None,
                "ledger": [],
            }

        def select_result():
            return post(SELECT, execution_token, selection)

        def fence():
            return post(route, barrier_token, body)

        first, second = (select_result, fence) if selection_first else (fence, select_result)
        responses, observations, blockers = race(
            sql,
            container,
            first,
            second,
            SELECT_GATE if selection_first else BARRIER_GATE,
            snapshot,
        )
        before, between, final = observations
        case.assertTrue(before["attempts"][0]["live"])
        case.assertIsNone(before["barrier"])
        case.assertIsNone(before["winner"])
        if selection_first:
            case.assertIsNone(between["barrier"])
        else:
            case.assertEqual(between, final)
        case.assertEqual(project(before), oracle["nodes"][oracle["initial"]]["state"])
        selected_response, barrier_response = responses if selection_first else responses[::-1]
        case.assertEqual(selected_response[0], 200 if selection_first else 409)
        case.assertEqual(
            barrier_response,
            (
                200,
                {
                    "schema_version": "1",
                    "outcome": "RECOVERY_FENCED" if recovery else "CANCELLED",
                    "fence": "2",
                    **({"successor_epoch": "1"} if recovery else {}),
                },
            ),
        )
        case.assertTrue(all(row["retired"] for row in final["attempts"]))
        case.assertEqual(final["workflow"], "0")
        case.assertEqual(final["barrier"]["fence"], 2)
        case.assertEqual(final["barrier"]["cancel_key"], None if recovery else op)
        case.assertEqual(final["barrier"]["recovery_epoch"], 1 if recovery else None)
        case.assertEqual(
            final["winner"]["upload_id"] if final["winner"] else None,
            upload if selection_first else None,
        )
        event = "recovery_fenced" if recovery else "cancelled"
        case.assertEqual(
            final["events"],
            sorted([event, "operation_created"] + (["result_selected"] if selection_first else [])),
        )

        steps = []

        def record(action, outcome, observed, cancellation="NONE"):
            steps.append(
                {"action": action, "outcome": outcome, "state": project(observed, cancellation)}
            )

        if not recovery:
            record("cancel-request", "CANCEL_PENDING", before, "PENDING")
        if selection_first:
            record("select:0:1-1", "SELECTED", between, "NONE" if recovery else "PENDING")
        if recovery:
            record("recover", "RECOVERING", final)
        else:
            record("cancel-commit", "CANCEL_COMMITTED", final, "COMMITTED")
            record("cancel-ack", "CANCELLED", final, "ACKNOWLEDGED")
        if not selection_first:
            record("select:0:1-1", "REJECTED", final, "NONE" if recovery else "ACKNOWLEDGED")

        case.assertEqual(post(REGISTER, execution_token, registration)[0], 409)
        case.assertEqual(select_result()[0], 409)
        case.assertEqual(post("/v1/attempts/ensure", coordinator, ensure)[0], 409)
        if recovery:
            successor = {**identity, "workflow_epoch": "1"}
            resume = {
                "schema_version": "1",
                "attempt": {
                    "schema_version": "1",
                    **successor,
                    "attempt_epoch": "2",
                },
            }
            case.assertEqual(
                post("/v1/attempts/ensure", authorize(successor, ("ENSURE_ATTEMPT",)), resume)[0],
                403,
            )
        case.assertEqual(snapshot(), final)

        restart_evidence = None
        if recovery and selection_first:
            subprocess.run(
                ["docker", "stop", "--time", "1", container],
                check=True,
                capture_output=True,
                timeout=20,
            )
            try:
                unavailable = fence()
                case.assertEqual(unavailable, (503, {"schema_version": "1", "code": "UNAVAILABLE"}))
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
                    case.assertLess(time.monotonic(), deadline)
                    time.sleep(0.2)
            restart()
            barrier_token = authorize(identity, (action,))
            retried = fence()
            restarted = snapshot()
            case.assertEqual(retried, barrier_response)
            case.assertEqual(restarted, final)
            restart_evidence = {"outage": unavailable, "retry": retried, "snapshot": restarted}
            execution_token = authorize(lease["attempt"])
            case.assertEqual(select_result()[0], 409)
            record("select:0:1-1", "REJECTED", snapshot())

        trace: dict[str, Any] = {
            "format": "kryvola-state-trace-v1",
            "model": "release",
            "oracle_sha256": oracle_hash,
            "steps": steps,
        }
        check_trace(oracle, trace, oracle_hash)
        corrupted = copy.deepcopy(trace)
        corrupted["steps"][-1]["outcome"] = "UNOBSERVED"
        with case.assertRaises(ValueError):
            check_trace(oracle, corrupted, oracle_hash)
        evidence[label] = {
            "observations": observations,
            "blocked_backends": blockers,
            "responses": responses,
            "trace": trace,
            "restart": restart_evidence,
        }
        # Release fixture quota and keep later probes independent.
        sql(
            f"DELETE FROM fabric_selected_results WHERE {key}; "
            f"DELETE FROM fabric_finalized_artifacts WHERE upload_id='{upload}'; "
            f"DELETE FROM fabric_uploads WHERE id='{upload}'"
        )

    try:
        for kind, selection_first in (
            ("public", True),
            ("admin", False),
            ("recovery", False),
            ("recovery", True),
        ):
            scenario(kind, selection_first)
    finally:
        sql(
            "DROP TRIGGER fixture_gate_selection ON fabric_selected_results; "
            "DROP TRIGGER fixture_gate_barrier ON fabric_operation_barriers; "
            "DROP FUNCTION fixture_gate_fencing()"
        )
    (ROOT / "build/fencing-race-trace.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("FENCING_RACE_TRACE_PASSED", flush=True)
