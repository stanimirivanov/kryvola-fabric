"""Owned, public-only Temporal/Ray smoke with actual history replay."""

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
from datetime import timedelta
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

from temporalio import activity
from temporalio.client import WorkflowExecutionStatus, WorkflowFailureError
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from .boundary import descriptor, execute
from .workflow import FixtureWorkflow

RAY_IMAGE = "rayproject/ray@sha256:e93e502244bf8c0ecf8c633099f7819d7c973d76eded8e32617e1fb66725da02"


def executor(container: str):
    @activity.defn(name="fixture_execute")
    async def dispatch(payload: bytes) -> str:
        failed = False
        result = ""
        try:
            result = await asyncio.to_thread(execute, container, payload)
        except ValueError, OSError:
            failed = True
        if failed:
            raise ApplicationError("FIXTURE_COMPUTE_FAILED", non_retryable=True)
        return result

    return dispatch


async def exercise(cli: str, container: str) -> None:
    payload = files(__package__).joinpath("public-request.bin").read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    # Only this immutable public fixture gets startup diagnostics, never an activity payload.
    preflight = await asyncio.to_thread(
        subprocess.run,
        ["docker", "exec", "-i", container, "python", "/fixture/ray_task.py"],
        input=json.dumps(descriptor(payload)).encode(),
        capture_output=True,
        timeout=45,
    )
    assert isinstance(preflight.stdout, bytes) and isinstance(preflight.stderr, bytes)
    if preflight.returncode or preflight.stdout != (digest + "\n").encode():
        print(
            "PUBLIC_FIXTURE_PREFLIGHT",
            preflight.returncode,
            preflight.stdout[-2048:].decode(errors="replace"),
            preflight.stderr[-4096:].decode(errors="replace"),
        )
        raise RuntimeError("PUBLIC_FIXTURE_PREFLIGHT_FAILED")
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=cli,
        dev_server_startup_timeout=timedelta(seconds=30),
    ) as env:
        for failure in (False, True):
            queue = "fixture-" + uuid4().hex
            async with Worker(
                env.client,
                task_queue=queue,
                workflows=[FixtureWorkflow],
                activities=[executor(container + "-absent" if failure else container)],
            ):
                handle = await env.client.start_workflow(
                    FixtureWorkflow.run,
                    payload,
                    id=queue,
                    task_queue=queue,
                    execution_timeout=timedelta(seconds=120),
                )
                if failure:
                    try:
                        await handle.result()
                    except WorkflowFailureError as error:
                        assert isinstance(error.cause, ActivityError)
                        assert isinstance(error.cause.cause, ApplicationError)
                        assert error.cause.cause.message == "FIXTURE_COMPUTE_FAILED"
                    else:
                        raise AssertionError("Expected backend failure")
                else:
                    async with asyncio.timeout(90):
                        while not await handle.query(FixtureWorkflow.state):
                            if (await handle.describe()).status != WorkflowExecutionStatus.RUNNING:
                                await handle.result()  # surface terminal failures immediately
                            await asyncio.sleep(0.1)
                    # A fresh Ray runtime repeats physical work; no Ray identifier owns intent.
                    assert await asyncio.to_thread(execute, container, payload) == digest
                    await handle.signal(FixtureWorkflow.observe, digest)
                    await handle.signal(FixtureWorkflow.observe, digest)
                    await handle.signal(FixtureWorkflow.observe, "0" * 64)
                    await handle.signal(FixtureWorkflow.finish)
                    assert await handle.result() == {
                        "intent_digest": digest,
                        "duplicates": 2,
                        "ignored": 1,
                    }
                history = await handle.fetch_history()
            await Replayer(workflows=[FixtureWorkflow]).replay_workflow(history)
            print(
                "fixture failure replay passed"
                if failure
                else "fixture success/duplicate replay passed"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["smoke"])
    parser.add_argument("--temporal-cli", required=True)
    args = parser.parse_args()
    cli = str(Path(args.temporal_cli).resolve(strict=True))
    # Refuse remote Docker contexts: this fixture intentionally runs only on a trusted local host.
    endpoint = subprocess.check_output(
        ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        timeout=10,
        text=True,
    ).strip()
    if os.environ.get("DOCKER_HOST") or not endpoint.startswith(("unix://", "npipe://")):
        raise ValueError("LOCAL_DOCKER_REQUIRED")
    container = "kryvola-conformance-" + uuid4().hex
    task = Path(__file__).with_name("ray_task.py").resolve()
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container,
                "--network",
                "none",
                "--hostname",
                "localhost",
                "--memory",
                "2g",
                "--cpus",
                "2",
                "--shm-size",
                "128m",
                "--pids-limit",
                "512",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=536870912,mode=1777",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "-e",
                "RAY_USAGE_STATS_ENABLED=0",
                "-e",
                "HOME=/tmp",
                "--mount",
                f"type=bind,source={task},target=/fixture/ray_task.py,readonly",
                "--entrypoint",
                "python",
                RAY_IMAGE,
                "-c",
                "import time; time.sleep(600)",
            ],
            check=True,
            timeout=180,
            stdout=subprocess.DEVNULL,
        )
        asyncio.run(exercise(cli, container))
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], check=True, timeout=30, stdout=subprocess.DEVNULL
        )


if __name__ == "__main__":
    main()
