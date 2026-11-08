"""Live signed execution receipt checks using fixed Spec v3 test signatures."""

import base64
import hashlib
import json
import time
from pathlib import Path


def exercise(
    test,
    request,
    sql,
    operation,
    attempt,
    upload,
    registry_grants,
    receipt_grants,
    publish,
    scoped_upload,
):
    fixture = json.loads((Path(__file__).parent / "fixtures/execution-receipts.json").read_text())
    first, second, changed = fixture["records"]
    route = "/v1/executions/receipt"
    expires = time.time_ns() // 1_000_000 + 55_000

    def token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    coordinator = "a1" * 32
    registry_grants.append(
        {
            "spiffe_id": "spiffe://fabric.test/coordinator",
            "token_sha256": token_hash(coordinator),
            "scope": {key: value for key, value in attempt.items() if key != "schema_version"},
            "actions": ["EXECUTION_REGISTER"],
            "expires_unix_ms": expires,
        }
    )
    publish()

    def body(record):
        return {
            "schema_version": "1",
            "attempt": attempt,
            "output_upload_id": upload,
            **{key: value for key, value in record.items() if key != "receipt_digest"},
        }

    def register(record, token):
        execution = record["execution_id"]
        result = request(
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
        )
        test.assertEqual(result[0], 204)
        receipt_grants.append(
            {
                "spiffe_id": "spiffe://fabric.test/worker",
                "token_sha256": token_hash(token),
                "attempt": attempt,
                "execution_id": execution,
                "signer": "test-worker",
                "key_id": "test-key",
                "key_epoch": "1",
                "public_key_hex": fixture["public_key_hex"],
                "expires_unix_ms": expires,
            }
        )
        publish()

    token = "a2" * 32
    other = "a3" * 32
    register(first, token)
    register(second, other)

    def expect(code, bearer, payload, *, name="worker"):
        test.assertEqual(request("POST", route, bearer, payload, name=name)[1]["code"], code)

    expect("FORBIDDEN", token, body(first), name="coordinator")
    expect("FORBIDDEN", token, body(second))
    expect("INVALID_REQUEST", token, {**body(first), "receipt_base64url": "e30"})
    expect("NOT_FOUND", token, {**body(first), "output_upload_id": "no-finalized-upload"})
    envelope = json.loads(base64.urlsafe_b64decode(first["signature_base64url"] + "=="))
    signature = envelope["signature"]
    envelope["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = (
        base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    expect("FORBIDDEN", token, {**body(first), "signature_base64url": tampered})

    expect("FORBIDDEN", other, {**body(second), "output_upload_id": scoped_upload})

    expected = (200, {"schema_version": "1", "receipt_digest": first["receipt_digest"]})
    test.assertEqual(request("POST", route, token, body(first)), expected)
    test.assertEqual(request("POST", route, token, body(first)), expected)
    expect("IDEMPOTENCY_CONFLICT", token, body(changed))
    expect("IDEMPOTENCY_CONFLICT", other, body(second))
    test.assertEqual(
        sql(
            "SELECT output_upload_id, receipt_digest, encode(canonical_receipt, 'hex'), "
            "encode(canonical_signature, 'hex') FROM fabric_execution_receipts "
            "WHERE operation_id='upload-http'"
        )
        .strip()
        .split("|"),
        [
            upload,
            first["receipt_digest"],
            base64.urlsafe_b64decode(first["receipt_base64url"] + "==").hex(),
            base64.urlsafe_b64decode(first["signature_base64url"] + "==").hex(),
        ],
    )
    receipt_grants[0]["public_key_hex"] = "0" * 64
    publish()
    expect("FORBIDDEN", token, body(first))
    receipt_grants[0]["public_key_hex"] = fixture["public_key_hex"]
    publish()

    def check_expired():
        receipt_grants[0]["expires_unix_ms"] = time.time_ns() // 1_000_000 + 45_000
        publish()
        expect("ATTEMPT_EXPIRED", token, body(first))
        cancel = "a4" * 32
        registry_grants.append(
            {
                "spiffe_id": "spiffe://fabric.test/coordinator",
                "token_sha256": token_hash(cancel),
                "scope": {
                    key: attempt[key] for key in ("tenant_scope", "operation_id", "workflow_epoch")
                },
                "actions": ["CANCEL_OPERATION"],
                "expires_unix_ms": time.time_ns() // 1_000_000 + 45_000,
            }
        )
        publish()
        test.assertEqual(
            request(
                "POST",
                "/v1/operations/cancel",
                cancel,
                {
                    "schema_version": "1",
                    "tenant_scope": attempt["tenant_scope"],
                    "operation_id": attempt["operation_id"],
                    "idempotency_key": "receipt-cancel",
                },
                name="coordinator",
            )[0],
            200,
        )
        expect("STALE_FENCE", token, body(first))
        print("SIGNED_EXECUTION_RECEIPTS_PASSED", flush=True)

    return check_expired
