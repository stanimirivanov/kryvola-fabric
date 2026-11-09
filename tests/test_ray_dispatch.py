import json
import unittest
from pathlib import Path

from kryvola_fabric.ray_dispatch import ENTRYPOINT, RayDispatcher, execution_envelope
from kryvola_fabric.ray_worker import canonical, decode_envelope

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "contracts/spec/fixtures/control.json").read_bytes()
)


class RayDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_ambiguous_submission_recovers_without_reposting(self):
        submissions = {}

        def request(method, path, body):
            if method == "POST":
                key = body["submission_id"]
                self.assertNotIn(key, submissions)
                submissions[key] = {**body, "status": "SUCCEEDED"}
                raise OSError("lost response after scheduler accepted submission")
            return submissions.get(path.rsplit("/", 1)[-1])

        async def observe(attempt, execution):
            return {
                "schema_version": "1",
                "attempt": attempt,
                "execution_id": execution,
                "output_manifest_digest": "e" * 64,
            }

        def crash_before_post(method, path, body):
            if method == "POST":
                raise RuntimeError("coordinator process lost")
            return request(method, path, body)

        with self.assertRaisesRegex(RuntimeError, "coordinator process lost"):
            await RayDispatcher(crash_before_post, observe)(
                FIXTURE["Operation"], FIXTURE["Attempt"], "execution-1"
            )
        self.assertEqual(submissions, {})

        for execution in ("execution-1", "execution-1", "execution-2"):
            candidate = await RayDispatcher(request, observe)(
                FIXTURE["Operation"], FIXTURE["Attempt"], execution
            )
            self.assertEqual(candidate["execution_id"], execution)
        self.assertEqual(len(submissions), 2)
        for key, body in submissions.items():
            env = body["runtime_env"]["env_vars"]
            self.assertEqual(set(env), {"KRYVOLA_EXECUTION"})
            self.assertEqual(decode_envelope(env["KRYVOLA_EXECUTION"])["namespace"], key)
            self.assertNotIn("recipient", env["KRYVOLA_EXECUTION"])

    def test_worker_rejects_code_side_effect_retry_and_oversize(self):
        envelope = execution_envelope(FIXTURE["Operation"], FIXTURE["Attempt"], "execution-1")
        for extra in ({"action": "RELEASE"}, {"entrypoint": "echo bad"}, {"retries": 1}):
            with self.assertRaisesRegex(ValueError, "INVALID_RAY_EXECUTION"):
                decode_envelope(canonical({**envelope, **extra}))
        with self.assertRaisesRegex(ValueError, "INVALID_RAY_EXECUTION"):
            decode_envelope(" " * 2048)

    async def test_terminal_failure_and_stale_candidate_fail_closed(self):
        submitted = []
        attempt = FIXTURE["Attempt"]
        execution = "execution-1"
        envelope = execution_envelope(FIXTURE["Operation"], attempt, execution)
        job = {
            "status": "FAILED",
            "entrypoint": ENTRYPOINT,
            "submission_id": envelope["namespace"],
            "runtime_env": {"env_vars": {"KRYVOLA_EXECUTION": canonical(envelope)}},
        }

        def request(method, path, body):
            if method == "POST":
                submitted.append(body)
            return job

        async def observe(scope, execution_id):
            return {"attempt": {**scope, "fence": "0"}, "execution_id": execution_id}

        dispatcher = RayDispatcher(request, observe)
        with self.assertRaisesRegex(ValueError, "RAY_EXECUTION_FAILED"):
            await dispatcher(FIXTURE["Operation"], attempt, execution)
        job["status"] = "SUCCEEDED"
        with self.assertRaisesRegex(ValueError, "INVALID_RAY_JOB"):
            await dispatcher(FIXTURE["Operation"], attempt, execution)
        self.assertEqual(submitted, [])
