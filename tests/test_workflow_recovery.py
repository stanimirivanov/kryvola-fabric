import unittest

from kryvola_fabric.compute_recovery import stop_compute


class FenceFirstTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_cancel_does_not_contact_temporal_or_cleanup(self):
        class Registry:
            def call(self, action, method, path, scope, body=None):
                return {"schema_version": "1", "outcome": "CANCELLATION_PENDING"}

        async def unexpected(*_args):
            self.fail("cleanup or Temporal contacted without a committed fence")

        result = await stop_compute(
            Registry(),
            {"tenant_scope": "tenant", "operation_id": "op"},
            "cancel",
            "request-1",
            unexpected,
            unexpected,
        )
        self.assertEqual(result, {"outcome": "CANCELLATION_PENDING"})

    async def test_lost_cancel_response_and_unreachable_temporal_are_reconcilable(self):
        from kryvola_fabric.compute_workflow import workflow_id

        requests = []
        cleaned = []
        stopped = []

        class Registry:
            def call(self, action, method, path, scope, body=None):
                requests.append((action, method, path, scope, body))
                if len(requests) == 1:
                    raise OSError("response lost after commit")
                return {"schema_version": "1", "outcome": "CANCELLED", "fence": "2"}

        async def cleanup(barrier):
            cleaned.append(barrier["fence"])

        async def stop(identifier, terminate):
            stopped.append((identifier, terminate))
            if len(stopped) == 1:
                raise OSError("Temporal unreachable")

        registry = Registry()
        scope = {"tenant_scope": "tenant", "operation_id": "op"}
        with self.assertRaises(OSError):
            await stop_compute(registry, scope, "cancel", "request-1", cleanup, stop)
        self.assertEqual((cleaned, stopped), ([], []))
        result = await stop_compute(registry, scope, "cancel", "request-1", cleanup, stop)
        self.assertTrue(result["cleanup_complete"])
        self.assertFalse(result["temporal_stopped"])
        result = await stop_compute(registry, scope, "cancel", "request-1", cleanup, stop)
        self.assertTrue(result["temporal_stopped"])
        self.assertEqual(requests, [requests[0]] * 3)
        self.assertEqual(cleaned, ["2", "2"])
        self.assertEqual(stopped, [(workflow_id("tenant", "op"), False)] * 2)

    async def test_admin_termination_rejects_wrong_epoch_and_shields_cleanup(self):
        import asyncio

        reached = asyncio.Event()
        released = asyncio.Event()
        cleaned = []

        class Registry:
            successor = "8"

            def call(self, action, method, path, scope, body=None):
                assert (action, method, path) == (
                    "ADMIN_RECOVERY",
                    "POST",
                    "/v1/admin/operations/fence-recovery",
                )
                assert body and body["workflow_epoch"] == "6"
                return {
                    "schema_version": "1",
                    "outcome": "RECOVERY_FENCED",
                    "fence": "3",
                    "successor_epoch": self.successor,
                }

        async def cleanup(barrier):
            reached.set()
            await released.wait()
            cleaned.append(barrier["workflow_epoch"])

        async def stop(_identifier, terminate):
            self.assertTrue(terminate)

        registry = Registry()
        scope = {"tenant_scope": "tenant", "operation_id": "op", "workflow_epoch": "6"}
        with self.assertRaisesRegex(ValueError, "INVALID_COMPUTE_CONTROL"):
            await stop_compute(registry, scope, "terminate", "request-1", cleanup, stop)
        self.assertFalse(reached.is_set())
        registry.successor = "7"
        task = asyncio.create_task(
            stop_compute(registry, scope, "terminate", "request-1", cleanup, stop)
        )
        async with asyncio.timeout(5):
            await reached.wait()
        task.cancel()
        await asyncio.sleep(0)
        released.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(cleaned, ["6"])
