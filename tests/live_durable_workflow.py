"""Real Temporal retry and history replay with a controlled registry fixture."""

import asyncio
import json
import unittest
from datetime import timedelta
from pathlib import Path

from temporalio import workflow
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from kryvola_fabric.compute_activities import ComputeActivities, Registry, start_from_notification
from kryvola_fabric.compute_workflow import DATA_CONVERTER, ComputeWorkflow, _complete, _prepare

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


@workflow.defn(name="ComputeWorkflow", sandboxed=False)
class LegacyComputeWorkflow:
    @workflow.run
    async def run(self, identity: dict) -> dict[str, str]:
        prepared = await _prepare(identity)
        if prepared["state"] != "READY":
            return {"outcome": prepared["state"]}
        return await _complete(prepared)


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

    async def test_recovery_restart_rollover_and_legacy_replay(self):
        from temporalio.client import WorkflowUpdateFailedError

        class ExpiringRegistry(FixtureRegistry):
            epochs: list[str]

            def call(self, action, method, path, scope, body=None):
                if action != "ENSURE":
                    return super().call(action, method, path, scope, body)
                assert body is not None
                epoch = body["attempt"]["attempt_epoch"]
                self.epochs.append(epoch)
                if epoch == "1":
                    raise ApplicationError("ATTEMPT_EXPIRED", non_retryable=True)
                return {
                    "schema_version": "1",
                    "attempt": {**body["attempt"], "fence": "2"},
                    "lease_expires_unix_ms": "18446744073709551615",
                }

        registry = ExpiringRegistry()
        registry.epochs = []
        dispatches = []

        async def dispatch(operation, attempt, execution):
            dispatches.append((operation, attempt["attempt_epoch"], execution))
            return {
                "schema_version": "1",
                "attempt": attempt,
                "execution_id": execution,
                "output_manifest_digest": "c" * 64,
            }

        queue = "recovery"
        activities = ComputeActivities(registry, dispatch)
        async with (
            await WorkflowEnvironment.start_local(
                dev_server_existing_path=str(ROOT / "build/temporal/temporal"),
                dev_server_startup_timeout=timedelta(seconds=30),
                data_converter=DATA_CONVERTER,
            ) as env,
            asyncio.timeout(45),
        ):

            def worker():
                return Worker(
                    env.client,
                    task_queue=queue,
                    workflows=[ComputeWorkflow],
                    activities=[activities.prepare, activities.dispatch, activities.select],
                )

            async with worker():
                notice = {
                    "version": 2,
                    "id": "1",
                    "kind": "operation_created",
                    **{key: registry.operation[key] for key in ("tenant_scope", "operation_id")},
                }
                handle = await start_from_notification(
                    env.client, queue, json.dumps(notice).encode()
                )
                assert handle is not None
                while await handle.query(ComputeWorkflow.waiting_attempt) != "1":
                    await asyncio.sleep(0.05)
                first_run = (await handle.describe()).run_id
                self.assertEqual(registry.epochs, ["1"])
            await handle.signal(ComputeWorkflow.rollover)
            async with worker():
                while (await handle.describe()).run_id == first_run:
                    await asyncio.sleep(0.05)
                while await handle.query(ComputeWorkflow.waiting_attempt) != "1":
                    await asyncio.sleep(0.05)
                self.assertEqual(registry.epochs, ["1"])
                with self.assertRaises(WorkflowUpdateFailedError):
                    await handle.execute_update("advance_attempt", "2")
                self.assertEqual(await handle.execute_update("advance_attempt", "1"), "2")
                self.assertEqual((await handle.result())["outcome"], "COMPUTE_SELECTED")
                first = await env.client.get_workflow_handle(
                    handle.id, run_id=first_run
                ).fetch_history()
                latest = await handle.fetch_history()
            replayer = Replayer(workflows=[ComputeWorkflow], data_converter=DATA_CONVERTER)
            for history in (first, latest):
                await replayer.replay_workflow(history)
            self.assertEqual(registry.epochs, ["1", "2"])
            self.assertEqual(len(dispatches), 1)
            operation, attempt, execution = dispatches[0]
            self.assertEqual((operation, attempt), (registry.operation, "2"))
            self.assertTrue(execution.endswith("-2"))

            legacy = FixtureRegistry()
            activities = ComputeActivities(legacy, dispatch)
            async with Worker(
                env.client,
                task_queue="legacy",
                workflows=[LegacyComputeWorkflow],
                activities=[activities.prepare, activities.dispatch, activities.select],
            ):
                old = await env.client.start_workflow(
                    LegacyComputeWorkflow.run,
                    {key: notice[key] for key in ("tenant_scope", "operation_id")},
                    id="legacy-compute",
                    task_queue="legacy",
                )
                self.assertEqual((await old.result())["outcome"], "COMPUTE_SELECTED")
                old_history = await old.fetch_history()
            await replayer.replay_workflow(old_history)
