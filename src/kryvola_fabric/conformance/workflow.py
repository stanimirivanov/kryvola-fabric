"""Only Temporal history determines logical fixture intent and observations."""

import hashlib
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError


@workflow.defn
class FixtureWorkflow:
    def __init__(self) -> None:
        self.digest = ""
        self.ready = False
        self.finished = False
        self.duplicates = 0
        self.ignored = 0

    @workflow.run
    async def run(self, payload: bytes) -> dict[str, str | int]:
        if not isinstance(payload, bytes) or len(payload) > 32768:
            raise ApplicationError("INVALID_FIXTURE_INTENT", non_retryable=True)
        self.digest = hashlib.sha256(payload).hexdigest()
        observed = await workflow.execute_activity(
            "fixture_execute",
            payload,
            result_type=str,
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        if observed != self.digest:
            raise ApplicationError("FIXTURE_OBSERVATION_MISMATCH", non_retryable=True)
        self.ready = True
        await workflow.wait_condition(lambda: self.finished, timeout=timedelta(seconds=30))
        return {
            "intent_digest": self.digest,
            "duplicates": self.duplicates,
            "ignored": self.ignored,
        }

    @workflow.signal
    def observe(self, digest: str) -> None:
        # Signals are diagnostic observations only. They cannot select or release any result.
        if self.ready and digest == self.digest:
            self.duplicates = min(self.duplicates + 1, 16)
        else:
            self.ignored = min(self.ignored + 1, 16)

    @workflow.signal
    def finish(self) -> None:
        self.finished = True

    @workflow.query
    def state(self) -> bool:
        return self.ready
