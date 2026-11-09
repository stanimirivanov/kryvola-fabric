"""Fence-first recovery commands for an authorized coordinator."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal, Protocol

from temporalio.client import Client
from temporalio.service import RPCError, RPCStatusCode

from .compute_activities import Document, checked
from .compute_workflow import workflow_id


class BarrierRegistry(Protocol):
    def call(
        self, action: str, method: str, path: str, scope: Document, body: Document | None = None
    ) -> Document: ...


async def stop_compute(
    registry: BarrierRegistry,
    scope: Document,
    mode: Literal["cancel", "admin-cancel", "terminate"],
    request_id: str,
    cleanup: Callable[[Document], Awaitable[None]],
    stop: Callable[[str, bool], Awaitable[None]],
) -> Document:
    """Retry with the same scope and request ID until both follow-ups finish."""
    identity = {key: scope[key] for key in ("tenant_scope", "operation_id")}
    body = {"schema_version": "1", **identity}
    if mode == "terminate":
        body["workflow_epoch"] = scope["workflow_epoch"]
        checked("FenceRecoveryRequest", body)
        action, path = "ADMIN_RECOVERY", "/v1/admin/operations/fence-recovery"
    elif mode in {"cancel", "admin-cancel"}:
        body["idempotency_key"] = request_id
        checked("CancelOperationRequest", body)
        action, path = (
            ("ADMIN_CANCEL", "/v1/admin/operations/cancel")
            if mode == "admin-cancel"
            else ("CANCEL", "/v1/operations/cancel")
        )
    else:
        raise ValueError("INVALID_COMPUTE_CONTROL")
    response = await asyncio.to_thread(registry.call, action, "POST", path, scope, body)
    if mode == "terminate":
        barrier = checked("RecoveryFenceResponse", response)
        if int(barrier["successor_epoch"]) != int(scope["workflow_epoch"]) + 1:
            raise ValueError("INVALID_COMPUTE_CONTROL")
    else:
        if response.get("outcome") == "CANCELLATION_PENDING":
            checked("CancellationPending", response)
            return {"outcome": "CANCELLATION_PENDING"}
        barrier = checked("Cancelled", response)
    identifier = workflow_id(identity["tenant_scope"], identity["operation_id"])

    async def attempt(task: Callable[[], Awaitable[None]]) -> bool:
        try:
            async with asyncio.timeout(10):
                await task()
            return True
        except Exception:
            return False

    # Reconciliation does not depend on Temporal reachability.
    followups = asyncio.gather(
        attempt(lambda: cleanup({**body, **barrier})),
        attempt(lambda: stop(identifier, mode == "terminate")),
    )
    try:
        cleaned, stopped = await asyncio.shield(followups)
    except asyncio.CancelledError:
        await followups
        raise
    return {**barrier, "cleanup_complete": cleaned, "temporal_stopped": stopped}


def temporal_stopper(client: Client) -> Callable[[str, bool], Awaitable[None]]:
    async def stop(identifier: str, terminate: bool) -> None:
        handle = client.get_workflow_handle(identifier)
        try:
            if terminate:
                await handle.terminate(reason="REGISTRY_RECOVERY_FENCED")
            else:
                await handle.cancel()
        except RPCError as error:
            if error.status != RPCStatusCode.NOT_FOUND:
                raise

    return stop
