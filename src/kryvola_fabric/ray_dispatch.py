"""Bounded Ray Jobs dispatch. SQL registration precedes this adapter."""

import asyncio
import http.client
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from .ray_worker import (
    ATTEMPT_FIELDS,
    MAX_ENVELOPE,
    canonical,
    decode_envelope,
    namespace,
    read_bounded,
)

ENTRYPOINT = "python -m kryvola_fabric.ray_worker"
Document = dict
JobsRequest = Callable[[str, str, Document | None], Document | None]
Observe = Callable[[Document, str], Awaitable[Document]]


def execution_envelope(operation, attempt, execution_id):
    scope = {key: attempt[key] for key in (*ATTEMPT_FIELDS, "schema_version")}
    if any(operation[key] != scope[key] for key in ATTEMPT_FIELDS[:3]):
        raise ValueError("INVALID_RAY_EXECUTION")
    return decode_envelope(
        canonical(
            {
                "action": "EXECUTE",
                "attempt": scope,
                "execution_id": execution_id,
                "namespace": namespace(scope, execution_id),
                "plan_digest": operation["plan_ref"]["plan_digest"],
                "policy_digest": operation["policy_digest"],
            }
        )
    )


def local_jobs(port: int = 8265) -> JobsRequest:
    """Use a private loopback Ray dashboard or an authenticated local tunnel."""
    if not 1 <= port <= 65535:
        raise ValueError("INVALID_RAY_PORT")

    def request(method, path, body):
        connection = http.client.HTTPConnection(
            "127.0.0.1", port, timeout=5 if method == "POST" else 2
        )
        try:
            connection.request(
                method,
                path,
                body=canonical(body).encode() if body is not None else None,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if method == "GET" and response.status == 404:
                return None
            if response.status != 200:
                raise OSError("RAY_JOB_UNAVAILABLE")
            raw = response.read(32 * 1024 + 1)
        except http.client.HTTPException:
            raise OSError("RAY_JOB_UNAVAILABLE") from None
        finally:
            connection.close()
        if len(raw) > 32 * 1024:
            raise ValueError("INVALID_RAY_JOB")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("INVALID_RAY_JOB")
        return result

    return request


def local_candidates(root: Path) -> Observe:
    async def observe(attempt, execution):
        folder = root / namespace(attempt, execution)
        raw = await asyncio.to_thread(read_bounded, folder / "candidate.json", MAX_ENVELOPE)
        return json.loads(raw)

    return observe


class RayUnavailable(Exception):
    """A bounded lookup could not resolve an ambiguous submission."""


class RayDispatcher:
    def __init__(self, request: JobsRequest, observe: Observe):
        self.request, self.observe = request, observe

    async def __call__(self, operation, attempt, execution_id):
        value = execution_envelope(operation, attempt, execution_id)
        key = value["namespace"]
        env = {"env_vars": {"KRYVOLA_EXECUTION": canonical(value)}}
        body = {"submission_id": key, "entrypoint": ENTRYPOINT, "runtime_env": env}
        path = "/api/jobs/" + key
        until = time.monotonic() + 25
        submitted = False
        while time.monotonic() < until:
            try:
                job = await asyncio.to_thread(self.request, "GET", path, None)
                if job is None and not submitted:
                    submitted = True
                    ack = await asyncio.to_thread(self.request, "POST", "/api/jobs/", body)
                    if ack is None or ack.get("submission_id") != key:
                        raise ValueError("INVALID_RAY_JOB")
                elif job is not None:
                    if (
                        job.get("submission_id") != key
                        or job.get("entrypoint") != ENTRYPOINT
                        or job.get("runtime_env") != env
                    ):
                        raise ValueError("INVALID_RAY_JOB")
                    if job["status"] == "SUCCEEDED":
                        candidate = await self.observe(attempt, execution_id)
                        if (
                            candidate.get("attempt") != attempt
                            or candidate.get("execution_id") != execution_id
                        ):
                            raise ValueError("INVALID_RAY_JOB")
                        return candidate
                    if job["status"] not in {"PENDING", "RUNNING"}:
                        raise ValueError("RAY_EXECUTION_FAILED")
            except OSError:
                # A lost acknowledgement or competing submit can only reattach to this ID.
                pass
            await asyncio.sleep(0.2)
        raise RayUnavailable("RAY_JOB_UNAVAILABLE")
