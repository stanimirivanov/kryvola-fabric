"""Temporal history owns logical compute intent and the exact selection candidate."""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.api.common.v1 import Payload, Payloads
from temporalio.api.failure.v1 import Failure
from temporalio.common import RetryPolicy
from temporalio.converter import (
    DataConverter,
    DefaultFailureConverter,
    DefaultPayloadConverter,
    PayloadConverter,
)
from temporalio.exceptions import ActivityError, ApplicationError

PAYLOAD_MAX = 32 * 1024
CALL_MAX = 128 * 1024
FAILURES = {"COMPUTE_UNAVAILABLE", "COMPUTE_REJECTED", "INVALID_COMPUTE_CONTROL", "ATTEMPT_EXPIRED"}


def _budget(payloads: Sequence[Payload]) -> None:
    if any(payload.ByteSize() > PAYLOAD_MAX for payload in payloads):
        raise ValueError("COMPUTE_PAYLOAD_TOO_LARGE")
    if Payloads(payloads=payloads).ByteSize() > CALL_MAX:
        raise ValueError("COMPUTE_CALL_TOO_LARGE")


class WorkflowPayloadConverter(DefaultPayloadConverter):
    """Count serialized payload framing and converter metadata as well as data."""

    def to_payloads(self, values: Sequence[Any]) -> list[Payload]:
        encoded = super().to_payloads(values)
        _budget(encoded)
        return encoded

    def from_payloads(
        self, payloads: Sequence[Payload], type_hints: list[type] | None = None
    ) -> list[Any]:
        _budget(payloads)
        return super().from_payloads(payloads, type_hints)


class WorkflowFailureConverter(DefaultFailureConverter):
    def to_failure(
        self, exception: BaseException, payload_converter: PayloadConverter, failure: Failure
    ) -> None:
        # Do not serialize exception strings, details, stack traces or causes.
        failure.Clear()
        if isinstance(exception, ApplicationError) and exception.message in FAILURES:
            failure.message = exception.message
            failure.application_failure_info.non_retryable = exception.non_retryable
        else:
            failure.message = "COMPUTE_REJECTED"
            failure.application_failure_info.non_retryable = True


DATA_CONVERTER = replace(
    DataConverter.default,
    payload_converter_class=WorkflowPayloadConverter,
    failure_converter_class=WorkflowFailureConverter,
)


def workflow_id(tenant: str, operation: str) -> str:
    key = json.dumps([tenant, operation], separators=(",", ":")).encode()
    return "compute-" + hashlib.sha256(key).hexdigest()


async def _prepare(identity: dict) -> dict:
    return await workflow.execute_activity(
        "compute_prepare",
        identity,
        result_type=dict,
        start_to_close_timeout=timedelta(seconds=10),
        retry_policy=RetryPolicy(maximum_attempts=3),
    )


async def _complete(prepared: dict) -> dict[str, str]:
    candidate = await workflow.execute_activity(
        "compute_dispatch",
        prepared,
        result_type=dict,
        start_to_close_timeout=timedelta(seconds=30),
        heartbeat_timeout=timedelta(seconds=12),
        retry_policy=RetryPolicy(maximum_attempts=1),
    )
    if candidate["state"] != "CANDIDATE":
        return {"outcome": candidate["state"]}
    return await workflow.execute_activity(
        "compute_select",
        candidate["selection"],
        result_type=dict,
        start_to_close_timeout=timedelta(seconds=10),
        retry_policy=RetryPolicy(maximum_attempts=3),
    )


def _expired(error: ActivityError) -> bool:
    return isinstance(error.cause, ApplicationError) and error.cause.message == "ATTEMPT_EXPIRED"


def _binding(operation: dict) -> dict:
    return {
        field: operation[field]
        for field in (
            "tenant_scope",
            "operation_id",
            "logical_job_id",
            "workflow_epoch",
            "disclosure_identity",
        )
    }


@workflow.defn
class ComputeWorkflow:
    def __init__(self) -> None:
        self._rollover = False
        self._waiting_epoch: int | None = None
        self._next_epoch: int | None = None

    @workflow.signal
    def rollover(self) -> None:
        self._rollover = True

    @workflow.query
    def waiting_attempt(self) -> str | None:
        return None if self._waiting_epoch is None else str(self._waiting_epoch)

    @workflow.update
    def advance_attempt(self, expired_epoch: str) -> str:
        epoch = self._waiting_epoch
        if epoch is None or expired_epoch != str(epoch) or epoch >= (1 << 64) - 1:
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        self._next_epoch = epoch + 1
        return str(self._next_epoch)

    def _should_rollover(self) -> bool:
        return self._rollover or workflow.info().is_continue_as_new_suggested()

    @workflow.run
    async def run(self, state: dict) -> dict[str, str]:
        if not workflow.patched("compute-recovery-v2"):
            prepared = await _prepare(state)
            if prepared["state"] != "READY":
                return {"outcome": prepared["state"]}
            return await _complete(prepared)

        identity = {key: state[key] for key in ("tenant_scope", "operation_id")}
        epoch = state.get("attempt_epoch", "1")
        binding = state.get("binding")
        prepared = state.get("prepared")
        expired = state.get("expired", False)
        while True:
            if not expired:
                if prepared is None:
                    prepared = await _prepare({**identity, "attempt_epoch": epoch})
                if prepared["state"] not in {"READY", "ATTEMPT_EXPIRED"}:
                    return {"outcome": prepared["state"]}
                current = _binding(prepared["operation"])
                if binding is not None and current != binding:
                    raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
                binding = current
                expired = prepared["state"] == "ATTEMPT_EXPIRED"
                if not expired:
                    if self._should_rollover():
                        workflow.continue_as_new(
                            {
                                **identity,
                                "attempt_epoch": epoch,
                                "binding": binding,
                                "prepared": prepared,
                            }
                        )
                    try:
                        return await _complete(prepared)
                    except ActivityError as error:
                        if not _expired(error):
                            raise
            self._waiting_epoch = int(epoch)
            await workflow.wait_condition(
                lambda: self._next_epoch is not None or self._should_rollover()
            )
            if self._next_epoch is None:
                workflow.continue_as_new(
                    {
                        **identity,
                        "attempt_epoch": epoch,
                        "binding": binding,
                        "expired": True,
                    }
                )
            epoch = str(self._next_epoch)
            self._waiting_epoch = self._next_epoch = None
            prepared = None
            expired = False
