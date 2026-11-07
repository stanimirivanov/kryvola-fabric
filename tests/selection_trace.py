"""Compare live registry observations with the pinned, finite Spec graph."""

import concurrent.futures
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.architecture import verify_contracts

ROOT = Path(__file__).resolve().parents[1]
REGISTER = "/v1/executions/register"
SELECT = "/v1/results/select"


def check_trace(oracle, trace, oracle_hash):
    if (
        oracle["format"] != "kryvola-state-oracle-v1"
        or oracle["model"] != "attempts"
        or trace["format"] != "kryvola-state-trace-v1"
        or trace["model"] != oracle["model"]
        or trace["oracle_sha256"] != oracle_hash
        or not trace["steps"]
    ):
        raise ValueError("unexpected oracle binding or empty trace")
    at = oracle["initial"]
    for event in trace["steps"]:
        action, outcome, state = event["action"], event["outcome"], event["state"]
        edges = [
            edge for edge in oracle["nodes"][at]["edges"] if oracle["actions"][edge[0]] == action
        ]
        if len(edges) != 1:
            raise ValueError(f"invalid transition: {action}")
        _, result, target = edges[0]
        expected = oracle["nodes"][target]["state"]
        if oracle["outcomes"][result] != outcome or json.dumps(
            expected, sort_keys=True
        ) != json.dumps(state, sort_keys=True):
            raise ValueError(f"outcome or state mismatch: {action}")
        at = target


def exercise(case, request, issue, sql, operation, scope, coordinator, authorize, canonical):
    digest = scope["manifest_digest"]
    tenant = operation["tenant_scope"]
    key = "operation_id='selection-http'"
    steps, observations, uploads = [], [], {}
    verify_contracts(ROOT)
    raw = (ROOT / "contracts/spec/state/v1/attempts.oracle.json").read_bytes()
    manifest = json.loads((ROOT / "contracts/spec/manifest.json").read_bytes())
    oracle_hash = hashlib.sha256(raw).hexdigest()
    case.assertEqual(oracle_hash, manifest["files"]["state/v1/attempts.oracle.json"])

    def rows(query):
        return json.loads(sql(f"SELECT coalesce(json_agg(q), '[]') FROM ({query}) q"))

    def observe(action, outcome, *, authorizing=False):
        attempts = rows(
            "SELECT attempt_epoch AS epoch, fence, lease_expires_unix_ms AS expiry, retired, "
            "retired OR lease_expires_unix_ms <= extract(epoch FROM clock_timestamp())*1000 "
            f"AS expired FROM fabric_attempts WHERE {key} ORDER BY attempt_epoch"
        )
        executions = rows(
            "SELECT execution_id AS id, attempt_epoch AS epoch, fence FROM fabric_executions "
            f"JOIN fabric_attempts USING (tenant_scope, operation_id, attempt_epoch) WHERE {key} "
            "ORDER BY execution_id"
        )
        artifacts = rows(
            "SELECT upload_id, manifest_digest FROM fabric_finalized_artifacts a "
            "JOIN fabric_uploads u ON u.id=a.upload_id "
            "WHERE u.scope->'attempt'->>'operation_id'='selection-http'"
        )
        winners = rows(f"SELECT execution_id FROM fabric_selected_results WHERE {key}")
        observations.append(
            {
                "attempts": attempts,
                "executions": executions,
                "artifacts": artifacts,
                "winners": winners,
            }
        )
        state = {
            "now": sum(row["expired"] for row in attempts),
            "attempts": [
                {
                    "epoch": row["epoch"],
                    "fence": row["fence"],
                    "until": None if authorizing and row is attempts[-1] else row["epoch"],
                    "retired": row["expired"],
                    "intent": not (authorizing and row is attempts[-1]),
                }
                for row in attempts
            ],
            "executions": [
                {
                    **row,
                    "done": any(
                        a["upload_id"] == uploads.get(row["id"]) and a["manifest_digest"] == digest
                        for a in artifacts
                    ),
                }
                for row in executions
            ],
            "selected": next(
                (
                    {**row}
                    for row in executions
                    if winners and row["id"] == winners[0]["execution_id"]
                ),
                None,
            ),
        }
        steps.append({"action": action, "outcome": outcome, "state": state})

    def registry(path, body, token):
        return request("POST", path, token, body, name="coordinator")

    case.assertEqual(
        registry(
            "/v1/operations",
            {
                "schema_version": "1",
                "operation": operation,
                "input_manifest_digests": ["a" * 64],
            },
            coordinator,
        )[0],
        200,
    )

    def ensure(epoch):
        attempt = {
            "schema_version": "1",
            "tenant_scope": tenant,
            "operation_id": "selection-http",
            "workflow_epoch": operation["workflow_epoch"],
            "attempt_epoch": str(epoch),
        }
        status, result = registry(
            "/v1/attempts/ensure",
            {
                "schema_version": "1",
                "attempt": attempt,
            },
            coordinator,
        )
        case.assertEqual(status, 200)
        scope["attempt"] = result["attempt"]
        case.assertEqual(
            sql(
                f"SELECT lease_expires_unix_ms FROM fabric_attempts WHERE {key} "
                f"AND attempt_epoch={epoch}"
            ).strip(),
            result["lease_expires_unix_ms"],
        )
        observe("workflow-authorize", "AUTHORIZED", authorizing=True)
        observe(f"ensure:{epoch}", "ENSURED")
        return authorize(result["attempt"])

    def register(execution, token, **changes):
        return registry(
            REGISTER,
            {
                "schema_version": "1",
                "attempt": scope["attempt"],
                "execution_id": execution,
                "plan_digest": operation["plan_ref"]["plan_digest"],
                "policy_digest": operation["policy_digest"],
                **changes,
            },
            token,
        )

    def select(execution, token, **changes):
        return registry(
            SELECT,
            {
                "schema_version": "1",
                "attempt": scope["attempt"],
                "execution_id": execution,
                "output_manifest_digest": digest,
                **changes,
            },
            token,
        )

    def complete(execution):
        status, result = request(
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
        upload = result["upload_id"]
        path = f"/v1/uploads/{upload}"
        case.assertEqual(request("PUT", path + "/parts/0", issue(), bytes([0, 1, 2, 255]))[0], 204)
        case.assertEqual(request("PUT", path + "/manifest", issue(), canonical)[0], 204)
        case.assertEqual(
            request(
                "POST",
                path + "/finalize",
                issue(),
                {
                    "schema_version": "1",
                    "tenant_scope": tenant,
                    "manifest_digest": digest,
                },
            )[0],
            200,
        )
        uploads[execution] = upload
        observe(f"complete:{execution}", "COMPLETED")

    def expire(epoch):
        sql(
            f"UPDATE fabric_attempts SET lease_expires_unix_ms=0 WHERE {key} "
            f"AND attempt_epoch={epoch}"
        )
        observe("tick", "TIME_ADVANCED")

    token = ensure(1)
    case.assertEqual(register("1-1", token)[0], 204)
    observe("launch:1", "LAUNCHED")
    complete("1-1")
    expire(1)
    case.assertEqual(select("1-1", token)[1]["code"], "ATTEMPT_EXPIRED")
    observe("select:1-1", "REJECTED")
    token = ensure(2)
    for field in ("plan_digest", "policy_digest"):
        case.assertEqual(register("2-1", token, **{field: "e" * 64})[0], 409)
    case.assertEqual(register("2-1", coordinator)[0], 403)
    other_tenant = {**scope["attempt"], "tenant_scope": "other"}
    case.assertEqual(register("2-1", token, attempt=other_tenant)[0], 403)
    case.assertEqual(select("2-1", authorize(scope["attempt"], ["EXECUTION_REGISTER"]))[0], 403)
    token = authorize(scope["attempt"])
    stale = {**scope["attempt"], "fence": "999"}
    case.assertEqual(register("2-1", token, attempt=stale)[0], 403)
    case.assertEqual(register("2-1", authorize(stale), attempt=stale)[0], 409)
    token = authorize(scope["attempt"])
    for execution in ("2-1", "2-2"):
        case.assertEqual(register(execution, token)[0], 204)
        observe("launch:2", "LAUNCHED")
    # Identical digest on the previous attempt is insufficient.
    case.assertEqual(select("2-1", token)[0], 409)
    observe("select:2-1", "REJECTED")
    for execution in ("2-1", "2-2"):
        complete(execution)
    case.assertEqual(select("2-1", token, output_manifest_digest="e" * 64)[0], 409)
    # Simulate wrong-context storage metadata while keeping the request digest unchanged.
    sql(
        "UPDATE fabric_finalized_artifacts SET canonical_manifest=convert_to("
        "jsonb_set(convert_from(canonical_manifest,'UTF8')::jsonb,'{key_context_digest}',"
        f"to_jsonb(repeat('e',64)))::text,'UTF8') WHERE upload_id IN "
        f"('{uploads['2-1']}','{uploads['2-2']}')"
    )
    case.assertEqual(select("2-1", token)[0], 409)
    sql(
        f"UPDATE fabric_finalized_artifacts SET canonical_manifest="
        f"decode('{canonical.hex()}','hex') "
        f"WHERE upload_id IN ('{uploads['2-1']}','{uploads['2-2']}')"
    )
    case.assertEqual(sql(f"SELECT count(*) FROM fabric_selected_results WHERE {key}").strip(), "0")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = dict(
            zip(("2-1", "2-2"), pool.map(lambda e: select(e, token), ("2-1", "2-2")), strict=True)
        )
    case.assertEqual(sorted(result[0] for result in results.values()), [200, 409])
    winner = next(e for e, result in results.items() if result[0] == 200)
    loser = next(e for e in results if e != winner)
    pinned = rows(f"SELECT execution_id, upload_id FROM fabric_selected_results WHERE {key}")
    case.assertEqual(
        pinned, [{"execution_id": winner, "upload_id": min(uploads["2-1"], uploads["2-2"])}]
    )
    case.assertEqual(
        sql(f"SELECT count(*) FROM fabric_outbox WHERE {key} AND kind='result_selected'").strip(),
        "1",
    )
    observe(f"select:{winner}", "SELECTED")
    observe(f"select:{loser}", "CONFLICT")
    expire(2)
    case.assertEqual(select(winner, token), results[winner])
    observe(f"select:{winner}", "SELECTED")
    status, operation_result = request(
        "GET", "/v1/operations/selection-http", coordinator, name="coordinator"
    )
    case.assertEqual((status, operation_result["public_status"]), (200, "COMPUTE_SELECTED"))
    observe("lookup", "SELECTED")

    oracle = json.loads(raw)
    trace: dict[str, Any] = {
        "format": "kryvola-state-trace-v1",
        "model": "attempts",
        "oracle_sha256": oracle_hash,
        "steps": steps,
    }
    check_trace(oracle, trace, oracle_hash)
    corrupted = copy.deepcopy(trace)
    corrupted["steps"][-1]["state"]["selected"]["fence"] = 999
    with case.assertRaises(ValueError):
        check_trace(oracle, corrupted, oracle_hash)
    (ROOT / "build/selection-trace.json").write_text(
        json.dumps(
            {
                "oracle_sha256": oracle_hash,
                "observations": observations,
                "execution_uploads": uploads,
                "trace": trace,
            },
            indent=2,
        )
        + "\n"
    )
    # The fixture owns this isolated database and bucket. Remove quota rows for later probes.
    sql(
        f"DELETE FROM fabric_outbox WHERE {key}; DELETE FROM fabric_selected_results WHERE {key}; "
        "DELETE FROM fabric_finalized_artifacts WHERE upload_id IN (SELECT id FROM fabric_uploads "
        "WHERE scope->'attempt'->>'operation_id'='selection-http'); "
        "DELETE FROM fabric_uploads WHERE scope->'attempt'->>'operation_id'='selection-http'"
    )
    print("FENCED_SELECTION_TRACE_PASSED", flush=True)
