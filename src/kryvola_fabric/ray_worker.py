"""Fixed Ray Jobs entrypoint. Engine credentials stay in the Engine process."""

import hashlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

ATTEMPT_FIELDS = ("tenant_scope", "operation_id", "workflow_epoch", "attempt_epoch", "fence")
ROOT = Path("/run/kryvola/ray")
MAX_ENVELOPE = 1536
ID = r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}"
DIGEST = r"[0-9a-f]{64}"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def namespace(attempt, execution_id):
    return "kryvola-" + hashlib.sha256(canonical([attempt, execution_id]).encode()).hexdigest()


def decode_envelope(raw):
    try:
        if len(raw.encode()) > MAX_ENVELOPE:
            raise ValueError
        value = json.loads(raw)
        if (
            canonical(value) != raw
            or set(value)
            != {"action", "attempt", "execution_id", "namespace", "plan_digest", "policy_digest"}
            or value["action"] != "EXECUTE"
        ):
            raise ValueError
        attempt = value["attempt"]
        if set(attempt) != {*ATTEMPT_FIELDS, "schema_version"} or attempt["schema_version"] != "1":
            raise ValueError
        for key in ATTEMPT_FIELDS[:2]:
            if not re.fullmatch(ID, attempt[key]):
                raise ValueError
        for key in ATTEMPT_FIELDS[2:]:
            number = attempt[key]
            if not re.fullmatch(r"0|[1-9][0-9]{0,19}", number) or int(number) >= 1 << 64:
                raise ValueError
        if (
            not re.fullmatch(ID, value["execution_id"])
            or value["namespace"] != namespace(attempt, value["execution_id"])
            or not all(re.fullmatch(DIGEST, value[key]) for key in ("plan_digest", "policy_digest"))
        ):
            raise ValueError
        return value
    except (KeyError, TypeError, ValueError, RecursionError):
        raise ValueError("INVALID_RAY_EXECUTION") from None


def read_bounded(path, limit):
    # Reject links and special files before reading an operator-provisioned namespace.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("INVALID_RAY_EXECUTION")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("INVALID_RAY_EXECUTION")
    return data


def execute(value, root):
    import grpc  # ty: ignore[unresolved-import] - supplied by the pinned Ray image

    from .control import decode_control, encode_control

    assignment = read_bounded(root / "execute.pb", 128 << 10)
    request = decode_control("ExecuteRequest", assignment)
    attempt, execution = value["attempt"], value["execution_id"]
    if (
        request["execution"]["attempt"] != attempt
        or request["execution"]["execution_id"] != execution
        or request["operation"]["plan_ref"]["plan_digest"] != value["plan_digest"]
        or request["operation"]["policy_digest"] != value["policy_digest"]
    ):
        raise ValueError("INVALID_RAY_EXECUTION")

    status_request = encode_control(
        "GetExecutionStatusRequest",
        {"schema_version": "1", "attempt": attempt, "execution_id": execution},
    )
    prefix = "/kryvola.spec.v1.EngineService/"
    with grpc.insecure_channel(
        f"unix:{root / 'engine.sock'}",
        options=[
            ("grpc.default_authority", "localhost"),
            ("grpc.max_receive_message_length", 128 << 10),
            ("grpc.enable_retries", 0),
        ],
    ) as channel:
        try:
            claim = (root / "started").open("xb")
        except FileExistsError:
            # After Ray or Engine restart, only observe this physical execution.
            pass
        else:
            with claim:
                os.fsync(claim.fileno())
            directory = os.open(root, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            channel.unary_unary(prefix + "Execute")(assignment, timeout=3)
        status = channel.unary_unary(prefix + "GetExecutionStatus")
        until = time.monotonic() + 20
        while time.monotonic() < until:
            result = decode_control("GetExecutionStatusResponse", status(status_request, timeout=2))
            observed = result["execution"]
            if observed["attempt"] != attempt or observed["execution_id"] != execution:
                break
            if observed["physical_state"] == "SUCCEEDED" and len(result["output_refs"]) == 1:
                return {
                    "schema_version": "1",
                    "attempt": attempt,
                    "execution_id": execution,
                    "output_manifest_digest": result["output_refs"][0]["manifest_digest"],
                }
            if observed["physical_state"] not in {"CREATED", "RUNNING"}:
                break
            time.sleep(0.2)
    raise ValueError("RAY_EXECUTION_FAILED")


def main():
    try:
        value = decode_envelope(os.environ["KRYVOLA_EXECUTION"])
        root = ROOT / value["namespace"]
        candidate = execute(value, root)
        # Publish atomically without replacing an earlier observation.
        with tempfile.NamedTemporaryFile(dir=root) as staged:
            staged.write(canonical(candidate).encode())
            staged.flush()
            try:
                os.link(staged.name, root / "candidate.json")
            except FileExistsError:
                if (
                    read_bounded(root / "candidate.json", MAX_ENVELOPE)
                    != canonical(candidate).encode()
                ):
                    raise ValueError("RAY_EXECUTION_FAILED") from None
    except Exception:
        raise SystemExit("RAY_EXECUTION_FAILED") from None


if __name__ == "__main__":
    main()
