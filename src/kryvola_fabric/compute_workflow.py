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
from temporalio.exceptions import ApplicationError

PAYLOAD_MAX = 32 * 1024
CALL_MAX = 128 * 1024
FAILURES = {"COMPUTE_UNAVAILABLE", "COMPUTE_REJECTED", "INVALID_COMPUTE_CONTROL"}


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


@workflow.defn
class ComputeWorkflow:
    @workflow.run
    async def run(self, identity: dict[str, str]) -> dict[str, str]:
        retries = RetryPolicy(maximum_attempts=3)
        prepared = await workflow.execute_activity(
            "compute_prepare",
            identity,
            result_type=dict,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=retries,
        )
        if prepared["state"] != "READY":
            return {"outcome": prepared["state"]}
        # A physical launch with ambiguous completion is never automatically retried.
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
        # Candidate identity is in history before the first selection side effect.
        return await workflow.execute_activity(
            "compute_select",
            candidate["selection"],
            result_type=dict,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=retries,
        )
