"""Explicit release activity for an isolated, trusted coordinator worker."""

import asyncio
import json
import re
from pathlib import Path

from temporalio import activity
from temporalio.exceptions import ApplicationError

from .compute_activities import Document
from .compute_workflow import workflow_id


class CoordinatorRelease:
    def __init__(self, binary: Path, database: Path, policy: Path):
        self.command = (
            str(binary.resolve(strict=True)),
            "--commit-release",
            str(database.resolve(strict=True)),
            str(policy.resolve(strict=True)),
        )

    @activity.defn(name="compute_release")
    async def commit(self, request: Document) -> Document:
        if (
            activity.info().workflow_type != "ComputeWorkflow"
            or activity.info().workflow_id
            != workflow_id(request["tenant_scope"], request["operation_id"])
        ):
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(8):
                output, _ = await process.communicate(json.dumps(request).encode())
        except TimeoutError:
            raise ApplicationError("COMPUTE_UNAVAILABLE") from None
        finally:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
        if process.returncode == 75:
            raise ApplicationError("COMPUTE_UNAVAILABLE")
        if process.returncode != 0:
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        value = json.loads(output)
        if (
            not isinstance(value, dict)
            or set(value) != {"outcome", "disclosure_id"}
            or value["outcome"] != "RELEASED"
            or not re.fullmatch(r"[0-9a-f]{64}", value["disclosure_id"])
        ):
            raise ApplicationError("COMPUTE_REJECTED", non_retryable=True)
        return value
