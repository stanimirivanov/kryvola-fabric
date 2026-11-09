"""Bounded activities over the published mTLS registry and an injected pure dispatcher."""

import asyncio
import http.client
import json
import re
import ssl
from collections.abc import Awaitable, Callable
from datetime import timedelta
from importlib.resources import files
from typing import Any, cast

from jsonschema import Draft202012Validator
from temporalio import activity
from temporalio.client import Client, WorkflowHandle
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import ApplicationError, WorkflowAlreadyStartedError

from .compute_workflow import DATA_CONVERTER, PAYLOAD_MAX, ComputeWorkflow, workflow_id

Document = dict[str, Any]
Token = Callable[[str, Document], str]
Dispatch = Callable[[Document, Document, str], Awaitable[Document]]
SCHEMAS = {
    name: Draft202012Validator(
        json.loads(files("kryvola_fabric").joinpath("_spec", relative).read_bytes())
    )
    for name, relative in {
        "Notification": "notifications/v2/Notification.schema.json",
        **{
            name: f"runtime/{name}.schema.json"
            for name in (
                "OperationResponse",
                "EnsureAttemptRequest",
                "EnsureAttemptResponse",
                "RegisterExecutionRequest",
                "SelectResultRequest",
                "SelectResultResponse",
            )
        },
    }.items()
}


def checked(name: str, value: Any) -> Document:
    if not SCHEMAS[name].is_valid(value):
        raise ApplicationError("INVALID_COMPUTE_CONTROL", non_retryable=True)
    return cast(Document, value)


async def start_from_notification(
    client: Client, task_queue: str, payload: bytes
) -> WorkflowHandle | None:
    """Acknowledge the notification only after this call returns successfully."""
    if len(payload) > PAYLOAD_MAX or client.data_converter != DATA_CONVERTER:
        raise ValueError("INVALID_COMPUTE_CONTROL")

    def unique(pairs: list[tuple[str, Any]]) -> Document:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("INVALID_COMPUTE_CONTROL")
        return result

    try:
        notice = checked("Notification", json.loads(payload, object_pairs_hook=unique))
    except ValueError, RecursionError:
        raise ValueError("INVALID_COMPUTE_CONTROL") from None
    if notice["kind"] != "operation_created":
        return None
    identity = {key: notice[key] for key in ("tenant_scope", "operation_id")}
    identifier = workflow_id(identity["tenant_scope"], identity["operation_id"])
    try:
        return await client.start_workflow(
            ComputeWorkflow.run,
            identity,
            id=identifier,
            task_queue=task_queue,
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            execution_timeout=timedelta(minutes=2),
        )
    except WorkflowAlreadyStartedError:
        return client.get_workflow_handle(identifier)


class Registry:
    def __init__(
        self, host: str, port: int, tls: ssl.SSLContext, spiffe_id: str, credential: Token
    ):
        if tls.verify_mode != ssl.CERT_REQUIRED or not spiffe_id.startswith("spiffe://"):
            raise ValueError("INVALID_REGISTRY_TLS")
        self.host, self.port, self.tls, self.peer, self.credential = (
            host,
            port,
            tls,
            spiffe_id,
            credential,
        )

    def call(
        self, action: str, method: str, path: str, scope: Document, body: Document | None = None
    ) -> Document:
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.tls, timeout=5)
        try:
            try:
                token = self.credential(action, scope)
            except Exception:
                token = ""

            if not re.fullmatch("[0-9a-f]{64}", token):
                raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
            connection.connect()
            certificate = connection.sock.getpeercert() if connection.sock else None
            names = certificate.get("subjectAltName", ()) if certificate else ()
            if not isinstance(names, tuple) or [item for item in names if item[0] == "URI"] != [
                ("URI", self.peer)
            ]:
                raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
            connection.request(
                method,
                path,
                json.dumps(body).encode() if body is not None else None,
                {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            reply = connection.getresponse()
            raw = reply.read(PAYLOAD_MAX + 1)
            if reply.status >= 500:
                raise ApplicationError("COMPUTE_UNAVAILABLE")
            if len(raw) > PAYLOAD_MAX or reply.status != (204 if action == "REGISTER" else 200):
                raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
            return json.loads(raw) if raw else {}
        except OSError, http.client.HTTPException:
            pass
        finally:
            connection.close()
        raise ApplicationError("COMPUTE_UNAVAILABLE")


def _same_identity(identity: Document, candidate: Document) -> bool:
    return all(candidate[key] == identity[key] for key in ("tenant_scope", "operation_id"))


def _operation_path(identity: Document) -> str:
    fields = ("tenant_scope", "operation_id")
    if not all(re.fullmatch("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", identity[k]) for k in fields):
        raise ApplicationError("INVALID_COMPUTE_CONTROL", non_retryable=True)
    return f"/v1/operations/{identity['operation_id']}"


class ComputeActivities:
    def __init__(self, registry: Registry, dispatch: Dispatch):
        self.registry, self.dispatcher = registry, dispatch

    async def _lookup(self, identity: Document) -> Document:
        saved = checked(
            "OperationResponse",
            await asyncio.to_thread(
                self.registry.call, "GET", "GET", _operation_path(identity), identity
            ),
        )
        if not _same_identity(identity, saved["operation"]):
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        return saved

    @activity.defn(name="compute_prepare")
    async def prepare(self, identity: Document) -> Document:
        saved = await self._lookup(identity)
        if saved["public_status"] is not None:
            return {"state": saved["public_status"]}
        operation = saved["operation"]
        requested = {
            "schema_version": "1",
            "attempt": {
                "schema_version": "1",
                **identity,
                "workflow_epoch": operation["workflow_epoch"],
                "attempt_epoch": "1",
            },
        }
        checked("EnsureAttemptRequest", requested)
        lease = checked(
            "EnsureAttemptResponse",
            await asyncio.to_thread(
                self.registry.call,
                "ENSURE",
                "POST",
                "/v1/attempts/ensure",
                requested["attempt"],
                requested,
            ),
        )
        attempt = lease["attempt"]
        if any(attempt[key] != value for key, value in requested["attempt"].items()):
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        return {"state": "READY", "operation": operation, "attempt": attempt}

    @activity.defn(name="compute_dispatch")
    async def dispatch(self, prepared: Document) -> Document:
        operation, attempt = prepared["operation"], prepared["attempt"]
        saved = await self._lookup({key: attempt[key] for key in ("tenant_scope", "operation_id")})
        if saved["public_status"] is not None:
            return {"state": saved["public_status"]}
        if saved["operation"] != operation:
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        execution = "exec-" + workflow_id(attempt["tenant_scope"], attempt["operation_id"])[8:]
        register = checked(
            "RegisterExecutionRequest",
            {
                "schema_version": "1",
                "attempt": attempt,
                "execution_id": execution,
                "plan_digest": operation["plan_ref"]["plan_digest"],
                "policy_digest": operation["policy_digest"],
            },
        )
        activity.heartbeat("REGISTERING")
        await asyncio.to_thread(
            self.registry.call, "REGISTER", "POST", "/v1/executions/register", attempt, register
        )
        activity.heartbeat("DISPATCHING")
        task = asyncio.ensure_future(self.dispatcher(operation, attempt, execution))
        try:
            while not task.done():
                done, _ = await asyncio.wait({task}, timeout=4)
                if not done:
                    activity.heartbeat("DISPATCHING")
            try:
                candidate = await task
            except Exception:
                candidate = None
        finally:
            if not task.done():
                task.cancel()

        if candidate is None:
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        selection = checked("SelectResultRequest", candidate)
        if selection["attempt"] != attempt or selection["execution_id"] != execution:
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        return {"state": "CANDIDATE", "selection": selection}

    @activity.defn(name="compute_select")
    async def select(self, candidate: Document) -> Document:
        checked("SelectResultRequest", candidate)
        selected = checked(
            "SelectResultResponse",
            await asyncio.to_thread(
                self.registry.call,
                "SELECT",
                "POST",
                "/v1/results/select",
                candidate["attempt"],
                candidate,
            ),
        )
        if any(
            selected[field] != candidate[field]
            for field in ("execution_id", "output_manifest_digest")
        ):
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        return selected
