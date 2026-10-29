"""Offline controls; real Temporal/Ray execution and replay run in the full gate."""

import hashlib
import json
import subprocess
import sys
import traceback
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from kryvola_fabric.conformance.boundary import descriptor, execute
from kryvola_fabric.control import ControlError

PAYLOAD = files("kryvola_fabric.conformance").joinpath("public-request.bin").read_bytes()


class BoundaryTests(unittest.TestCase):
    def test_owned_container_cleanup_on_smoke_failure(self):
        from kryvola_fabric.conformance.__main__ import main

        def fail(coroutine):
            coroutine.close()
            raise RuntimeError("FIXTURE_TEST_FAILURE")

        with (
            patch.object(sys, "argv", ["fixture", "smoke", "--temporal-cli", sys.executable]),
            patch.dict("os.environ", {"DOCKER_HOST": ""}),
            patch("subprocess.check_output", return_value="unix:///var/run/docker.sock"),
            patch("subprocess.run") as run,
            patch("asyncio.run", side_effect=fail),
        ):
            with self.assertRaisesRegex(RuntimeError, "FIXTURE_TEST_FAILURE"):
                main()
            created = run.call_args_list[0].args[0]
            name = created[created.index("--name") + 1]
            self.assertTrue(name.startswith("kryvola-conformance-"))
            self.assertEqual(run.call_args_list[-1].args[0], ["docker", "rm", "-f", name])

    def test_public_request_matches_published_wire(self):
        vectors = json.loads(
            (Path(__file__).resolve().parents[1] / "contracts/native/vectors.json").read_bytes()
        )
        self.assertTrue(
            any(v["type"] == "ExecuteRequest" and v["wire"] == PAYLOAD.hex() for v in vectors)
        )
        self.assertEqual(descriptor(PAYLOAD)["intent_digest"], hashlib.sha256(PAYLOAD).hexdigest())

    def test_invalid_intent_never_dispatches(self):
        with patch("kryvola_fabric.conformance.boundary.subprocess.run") as run:
            for payload in (b"x" * 32769, b"malformed", PAYLOAD + b"\xf8\x1f\x01"):
                with self.assertRaises(ControlError):
                    execute("fixture", payload)
            run.assert_not_called()

    def test_sanitized_failure_and_bounded_reply(self):
        secret = "DO_NOT_PERSIST_BACKEND_DETAIL"
        for failure in (subprocess.TimeoutExpired(secret, 1), OSError(secret)):
            with patch("kryvola_fabric.conformance.boundary.subprocess.run", side_effect=failure):
                try:
                    execute("fixture", PAYLOAD)
                except ValueError as error:
                    self.assertIsNone(error.__context__)
                    self.assertNotIn(secret, "".join(traceback.format_exception(error)))
                    self.assertEqual(str(error), "FIXTURE_COMPUTE_FAILED")
                else:
                    self.fail("Expected sanitized failure")

        def reply(*args, **kwargs):
            kwargs["stdout"].write(b"x" * 1000)

        with patch("kryvola_fabric.conformance.boundary.subprocess.run", side_effect=reply):
            with self.assertRaisesRegex(ValueError, "FIXTURE_COMPUTE_FAILED"):
                execute("fixture", PAYLOAD)


class WorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_stale_and_early_observations_are_bounded(self):
        from kryvola_fabric.conformance.workflow import FixtureWorkflow

        flow = FixtureWorkflow()
        flow.digest = hashlib.sha256(PAYLOAD).hexdigest()
        flow.observe(flow.digest)
        self.assertEqual(flow.duplicates, 0)
        flow.ready = True
        for _ in range(100):
            flow.observe(flow.digest)
            flow.observe("stale")
        self.assertEqual((flow.duplicates, flow.ignored), (16, 16))
        self.assertFalse(flow.finished)
        self.assertEqual(flow.digest, hashlib.sha256(PAYLOAD).hexdigest())

    async def test_activity_failure_has_only_safe_cause(self):
        from temporalio.exceptions import ApplicationError

        from kryvola_fabric.conformance.__main__ import executor

        with patch(
            "kryvola_fabric.conformance.__main__.execute", side_effect=ValueError("DO_NOT_PERSIST")
        ):
            try:
                await executor("fixture")(PAYLOAD)
            except ApplicationError as error:
                self.assertIsNone(error.__context__)
                self.assertEqual(error.message, "FIXTURE_COMPUTE_FAILED")
            else:
                self.fail("Expected sanitized activity error")

    async def test_oversized_workflow_intent_fails_before_activity(self):
        from temporalio.exceptions import ApplicationError

        from kryvola_fabric.conformance.workflow import FixtureWorkflow

        with self.assertRaisesRegex(ApplicationError, "INVALID_FIXTURE_INTENT"):
            await FixtureWorkflow().run(b"x" * 32769)


if __name__ == "__main__":
    unittest.main()
