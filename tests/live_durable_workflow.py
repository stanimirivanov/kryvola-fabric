"""Real Temporal retry and history replay with a controlled registry fixture."""

import asyncio
import json
import unittest
from datetime import timedelta
from pathlib import Path

from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from kryvola_fabric.compute_activities import ComputeActivities, Registry, start_from_notification
from kryvola_fabric.compute_workflow import DATA_CONVERTER, ComputeWorkflow

ROOT = Path(__file__).resolve().parents[1]


class FixtureRegistry(Registry):
    def __init__(self):
        fixture = json.loads((ROOT / "contracts/spec/fixtures/control.json").read_bytes())
        self.operation = fixture["Operation"]
        self.ensures = 0
        self.registrations = 0
        self.calls = 0
        self.selected = None

    def call(self, action, method, path, scope, body=None):
        if action == "GET":
            assert method == "GET" and path == f"/v1/operations/{self.operation['operation_id']}"
            return {
                "schema_version": "1",
                "operation": self.operation,
                "public_status": "COMPUTE_SELECTED" if self.selected else None,
            }
        assert body is not None
        if action == "ENSURE":
            self.ensures += 1
            assert body["attempt"]["attempt_epoch"] == "1"
            return {
                "schema_version": "1",
                "attempt": {**body["attempt"], "fence": "1"},
                "lease_expires_unix_ms": "18446744073709551615",
            }
        if action == "REGISTER":
            self.registrations += 1
            return {}
        assert action == "SELECT"
        self.calls += 1
        if self.selected is None:
            self.selected = body
            # The registry committed, but the activity completion was lost.
            raise ApplicationError("COMPUTE_UNAVAILABLE")
        assert self.selected == body
        return {
            "schema_version": "1",
            "outcome": "COMPUTE_SELECTED",
            "execution_id": body["execution_id"],
            "output_manifest_digest": body["output_manifest_digest"],
        }


class DurableWorkflowLiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_start_lost_completion_and_history_replay(self):
        registry = FixtureRegistry()
        dispatches = 0

        async def dispatch(operation, attempt, execution):
            nonlocal dispatches
            dispatches += 1
            self.assertEqual(operation, registry.operation)
            return {
                "schema_version": "1",
                "attempt": attempt,
                "execution_id": execution,
                "output_manifest_digest": "c" * 64,
            }

        activities = ComputeActivities(registry, dispatch)
        queue = "durable-compute"
        async with await WorkflowEnvironment.start_local(
            dev_server_existing_path=str(ROOT / "build/temporal/temporal"),
            dev_server_startup_timeout=timedelta(seconds=30),
            data_converter=DATA_CONVERTER,
        ) as env:
            async with Worker(
                env.client,
                task_queue=queue,
                workflows=[ComputeWorkflow],
                activities=[activities.prepare, activities.dispatch, activities.select],
            ):
                notice = {
                    "version": 2,
                    "id": "1",
                    "kind": "operation_created",
                    **{key: registry.operation[key] for key in ("tenant_scope", "operation_id")},
                }
                async with asyncio.timeout(30):
                    first, second = await asyncio.gather(
                        start_from_notification(env.client, queue, json.dumps(notice).encode()),
                        start_from_notification(
                            env.client, queue, json.dumps({**notice, "id": "2"}).encode()
                        ),
                    )
                    assert first is not None and second is not None
                    self.assertEqual(first.id, second.id)
                    result = await first.result()
                    self.assertEqual(result["output_manifest_digest"], "c" * 64)
                    self.assertEqual(await second.result(), result)
                    duplicate = await start_from_notification(
                        env.client, queue, json.dumps(notice).encode()
                    )
                    assert duplicate is not None
                    self.assertEqual(await duplicate.result(), result)
                    history = await first.fetch_history()
                self.assertEqual(
                    (dispatches, registry.ensures, registry.registrations, registry.calls),
                    (1, 1, 1, 2),
                )
            await Replayer(
                workflows=[ComputeWorkflow], data_converter=DATA_CONVERTER
            ).replay_workflow(history)
