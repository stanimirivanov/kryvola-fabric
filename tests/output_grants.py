"""Live output grant coverage using the registry and real upload endpoints."""

import hashlib
import re
import time

ROUTE = "/v1/executions/output-grants"


def exercise(
    test, request, sql, operation, attempt, reserve, manifest, digest, policy, publish, legacy
):
    registry, authorities = policy
    expiry = time.time_ns() // 1_000_000 + 45_000
    coordinator = "b1" * 32
    registry.append(
        {
            "spiffe_id": "spiffe://fabric.test/coordinator",
            "token_sha256": hashlib.sha256(coordinator.encode()).hexdigest(),
            "scope": {k: v for k, v in attempt.items() if k != "schema_version"},
            "actions": ["EXECUTION_REGISTER"],
            "expires_unix_ms": expiry,
        }
    )
    publish()

    def register(execution, credential):
        test.assertEqual(
            request(
                "POST",
                "/v1/executions/register",
                coordinator,
                {
                    "schema_version": "1",
                    "attempt": attempt,
                    "execution_id": execution,
                    "plan_digest": operation["plan_ref"]["plan_digest"],
                    "policy_digest": operation["policy_digest"],
                },
                name="coordinator",
            )[0],
            204,
        )
        authority = {
            "spiffe_id": "spiffe://fabric.test/worker",
            "token_sha256": hashlib.sha256(credential.encode()).hexdigest(),
            "attempt": attempt,
            "execution_id": execution,
            "expires_unix_ms": expiry,
        }
        authorities.append(authority)
        publish()
        return authority

    first, second = "output-exec-1", "output-exec-2"
    credential, other = "b2" * 32, "b3" * 32
    authority = register(first, credential)
    register(second, other)

    def issue(action, *, bearer=None, execution=first, output=digest, name="worker", **target):
        return request(
            "POST",
            ROUTE,
            bearer or credential,
            {
                "schema_version": "1",
                "attempt": attempt,
                "execution_id": execution,
                "manifest_digest": output,
                "target": {"action": action, **target},
            },
            name=name,
            capture_grant=True,
        )

    def issued(action, **kwargs):
        status, body, grant, cache = issue(action, **kwargs)
        test.assertEqual(status, 200)
        test.assertEqual(set(body), {"schema_version", "expires_unix_ms"})
        test.assertLessEqual(int(body["expires_unix_ms"]), expiry)
        test.assertTrue(grant and re.fullmatch(r"[0-9a-f]{64}", grant))
        test.assertEqual(cache, "no-store")
        return grant

    def denied(expected, action, **kwargs):
        status, body, header, _ = issue(action, **kwargs)
        test.assertEqual((status, body["code"], header), (*expected, None))

    denied((403, "FORBIDDEN"), "RESERVE", bearer=coordinator, name="coordinator")
    denied((403, "FORBIDDEN"), "RESERVE", execution=second)
    denied((403, "FORBIDDEN"), "RESERVE", name="coordinator")
    denied((400, "INVALID_REQUEST"), "PUT_PART", upload_id="missing", part_index=1024)
    denied((404, "NOT_FOUND"), "FINALIZE", upload_id="missing")

    revoked = issued("RESERVE")
    authorities.remove(authority)
    publish()
    test.assertEqual(request("POST", "/v1/uploads", revoked, reserve)[0], 403)
    credential = "b4" * 32
    authority["token_sha256"] = hashlib.sha256(credential.encode()).hexdigest()
    authorities.append(authority)
    publish()
    test.assertEqual(request("POST", "/v1/uploads", revoked, reserve)[0], 403)
    first_grant = issued("RESERVE")

    reserve = {**reserve, "byte_length": 4}
    status, output = request("POST", "/v1/uploads", first_grant, reserve)
    test.assertEqual(status, 201)
    upload = output["upload_id"]
    test.assertEqual(request("POST", "/v1/uploads", first_grant, reserve)[0], 403)
    test.assertEqual(request("POST", "/v1/uploads", issued("RESERVE"), reserve), (201, output))
    test.assertEqual(
        request("POST", "/v1/uploads", issued("RESERVE"), {**reserve, "byte_length": 5})[1]["code"],
        "IDEMPOTENCY_CONFLICT",
    )
    denied((409, "IDEMPOTENCY_CONFLICT"), "RESERVE", output="e" * 64)
    status, distinct = request(
        "POST", "/v1/uploads", issued("RESERVE", execution=second, bearer=other), reserve
    )
    test.assertEqual(status, 201)
    second_upload = distinct["upload_id"]
    test.assertNotEqual(second_upload, upload)
    denied((403, "FORBIDDEN"), "FINALIZE", execution=second, bearer=other, upload_id=upload)
    abort = issued("ABORT", execution=second, bearer=other, upload_id=second_upload)
    test.assertEqual(
        request(
            "POST",
            f"/v1/uploads/{second_upload}/abort",
            abort,
            {"schema_version": "1", "attempt": attempt},
        )[0],
        204,
    )
    denied((409, "IDEMPOTENCY_CONFLICT"), "RESERVE", execution=second, bearer=other)

    part = issued("PUT_PART", upload_id=upload, part_index=0)
    route = f"/v1/uploads/{upload}"
    data = bytes([0, 1, 2, 255])
    test.assertEqual(request("PUT", f"{route}/parts/1", part, data)[0], 403)
    test.assertEqual(request("PUT", f"{route}/parts/0", legacy(), data)[0], 403)
    test.assertEqual(request("PUT", f"{route}/parts/0", part, data)[0], 204)
    test.assertEqual(
        request("PUT", f"{route}/manifest", issued("PUT_MANIFEST", upload_id=upload), manifest)[0],
        204,
    )
    test.assertEqual(
        request(
            "POST",
            f"{route}/finalize",
            issued("FINALIZE", upload_id=upload),
            {
                "schema_version": "1",
                "tenant_scope": attempt["tenant_scope"],
                "manifest_digest": digest,
            },
        ),
        (200, {"schema_version": "1", "manifest_digest": digest}),
    )
    test.assertEqual(
        sql(
            "SELECT count(*) FROM fabric_execution_output_uploads "
            "WHERE execution_id='output-exec-1'"
        ).strip(),
        "1",
    )

    def check_fenced():
        authority["expires_unix_ms"] = time.time_ns() // 1_000_000 + 45_000
        publish()
        denied((409, "STALE_FENCE"), "RESERVE")
        print("SCOPED_OUTPUT_GRANTS_PASSED", flush=True)

    return upload, check_fenced
