"""Real pinned Ray Jobs with two private Engine protocol fixtures."""

import asyncio
import copy
import json
import os
import subprocess
import unittest
from pathlib import Path
from uuid import uuid4

from kryvola_fabric.conformance.__main__ import RAY_IMAGE
from kryvola_fabric.control import encode_control
from kryvola_fabric.ray_dispatch import RayDispatcher, execution_envelope

ROOT = Path(__file__).resolve().parents[1]
ENGINE = r"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import grpc
from kryvola_fabric.control import decode_control

servers = []
for folder in Path("/run/kryvola/ray").iterdir():
    def execute(raw, context, folder=folder):
        assert raw == (folder / "execute.pb").read_bytes()
        with (folder / "starts").open("ab") as stream:
            stream.write(b"x")
        return b""

    def observe(raw, context, folder=folder):
        request = decode_control("GetExecutionStatusRequest", raw)
        response = (folder / "status.pb").read_bytes()
        observed = decode_control("GetExecutionStatusResponse", response)
        assert observed["execution"]["execution_id"] == request["execution_id"]
        return response

    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
        "kryvola.spec.v1.EngineService",
        {"Execute": grpc.unary_unary_rpc_method_handler(execute),
         "GetExecutionStatus": grpc.unary_unary_rpc_method_handler(observe)}),))
    assert server.add_insecure_port(f"unix:{folder / 'engine.sock'}")
    server.start()
    servers.append(server)
Path("/run/kryvola/ray/engine-ready").touch()
servers[0].wait_for_termination()
"""
PROVISION = """
import json, sys
from pathlib import Path

root = Path("/run/kryvola/ray")
for key, files in json.load(sys.stdin).items():
    folder = root / key
    folder.mkdir(mode=0o700)
    for name, hex_value in files.items():
        (folder / name).write_bytes(bytes.fromhex(hex_value))
"""
REQUEST = """
import json, sys
from kryvola_fabric.ray_dispatch import local_jobs
print(json.dumps(local_jobs()(*json.load(sys.stdin))))
"""


class RayDispatchLiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_jobs_reattach_and_keep_outputs_separate(self):
        endpoint = subprocess.check_output(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            timeout=10,
            text=True,
        ).strip()
        if os.environ.get("DOCKER_HOST") or not endpoint.startswith("unix://"):
            self.fail("LOCAL_DOCKER_REQUIRED")

        cpus = ",".join(str(cpu) for cpu in sorted(os.sched_getaffinity(0))[:2])
        container = "fabric-ray-" + uuid4().hex
        fixture = json.loads((ROOT / "contracts/spec/fixtures/engine.json").read_bytes())
        operation = fixture["execute"]["operation"]
        attempt = fixture["execute"]["execution"]["attempt"]
        submitted = []

        def request(method, path, body):
            if method == "POST":
                submitted.append(body)
            result = subprocess.run(
                ["docker", "exec", "-i", container, "python", "-c", REQUEST],
                input=json.dumps([method, path, body]),
                capture_output=True,
                text=True,
                timeout=8,
            )
            if result.returncode:
                raise OSError("RAY_JOB_UNAVAILABLE")
            reply = json.loads(result.stdout)
            if isinstance(reply, dict) and reply.get("status") == "FAILED":
                print(reply.get("message"), flush=True)
            return reply

        def lose_ack(method, path, body):
            result = request(method, path, body)
            if method == "POST":
                raise OSError("response lost")
            return result

        def engine_ready():
            return (
                subprocess.run(
                    ["docker", "exec", container, "test", "-f", "/run/kryvola/ray/engine-ready"],
                    timeout=5,
                ).returncode
                == 0
            )

        def read_file(key, name):
            return subprocess.check_output(
                ["docker", "exec", container, "cat", f"/run/kryvola/ray/{key}/{name}"],
                timeout=5,
            )

        fixtures = {}
        for index in (1, 2):
            execution = f"execution-{index}"
            key = execution_envelope(operation, attempt, execution)["namespace"]
            assignment, observed = copy.deepcopy((fixture["execute"], fixture["observation"]))
            assignment["execution"]["execution_id"] = execution
            observed["execution"]["execution_id"] = execution
            observed["output_refs"][0]["manifest_digest"] = str(index) * 64
            fixtures[key] = {
                "execute.pb": encode_control("ExecuteRequest", assignment).hex(),
                "status.pb": encode_control("GetExecutionStatusResponse", observed).hex(),
            }

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
                    "3g",
                    "--cpuset-cpus",
                    cpus,
                    "--shm-size",
                    "128m",
                    "--pids-limit",
                    "1024",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,size=536870912,mode=1777",
                    "-e",
                    "HOME=/tmp",
                    "-e",
                    "OPENBLAS_NUM_THREADS=1",
                    "-e",
                    "RAY_USAGE_STATS_ENABLED=0",
                    "-e",
                    "PYTHONPATH=/opt/kryvola",
                    "--mount",
                    f"type=bind,source={ROOT / 'src'},target=/opt/kryvola,readonly",
                    "--tmpfs",
                    "/run/kryvola/ray:rw,size=1048576,uid=1000,gid=1000,mode=0700",
                    "--entrypoint",
                    "ray",
                    RAY_IMAGE,
                    "start",
                    "--head",
                    "--include-dashboard=true",
                    "--dashboard-host=127.0.0.1",
                    "--node-ip-address=127.0.0.1",
                    "--num-cpus=2",
                    "--object-store-memory=83886080",
                    "--block",
                ],
                check=True,
                timeout=180,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["docker", "exec", "-i", container, "python", "-c", PROVISION],
                input=json.dumps(fixtures),
                text=True,
                check=True,
                timeout=10,
            )
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "-d",
                    container,
                    "sh",
                    "-c",
                    'exec python -c "$1" >/tmp/engine-fixture.log 2>&1',
                    "engine-fixture",
                    ENGINE,
                ],
                check=True,
                timeout=10,
            )
            async with asyncio.timeout(45):
                while True:
                    try:
                        await asyncio.to_thread(request, "GET", "/api/jobs/absent", None)
                        if await asyncio.to_thread(engine_ready):
                            break
                    except OSError:
                        pass
                    await asyncio.sleep(0.5)

            async def observe(scope, execution):
                key = execution_envelope(operation, scope, execution)["namespace"]
                return json.loads(await asyncio.to_thread(read_file, key, "candidate.json"))

            # Simulate process loss immediately after scheduler acceptance, without retaining
            # the scheduler acknowledgement or any mutable dispatcher state.
            def crash_after_accept(method, path, body):
                if method != "POST":
                    return request(method, path, body)
                try:
                    request(method, path, body)
                except OSError:
                    # The Ray server may accept the job just before the client times out.
                    pass
                raise RuntimeError("coordinator process lost")

            with self.assertRaisesRegex(RuntimeError, "coordinator process lost"):
                await RayDispatcher(crash_after_accept, observe)(operation, attempt, "execution-1")
            for index, transport in ((1, request), (2, lose_ack)):
                candidate = await RayDispatcher(transport, observe)(
                    operation, attempt, f"execution-{index}"
                )
                self.assertEqual(candidate["output_manifest_digest"], str(index) * 64)
            self.assertEqual(len(submitted), 2)
            for key in fixtures:
                self.assertEqual(read_file(key, "starts"), b"x")
            for body in submitted:
                job = await asyncio.to_thread(
                    request, "GET", "/api/jobs/" + body["submission_id"], None
                )
                self.assertEqual(job["runtime_env"], body["runtime_env"])
                self.assertEqual(job["entrypoint"], body["entrypoint"])

            # Re-executing the driver may observe but cannot launch the Engine again.
            env = submitted[0]["runtime_env"]["env_vars"]["KRYVOLA_EXECUTION"]
            command = [
                "docker",
                "exec",
                "-e",
                "KRYVOLA_EXECUTION=" + env,
                container,
                "python",
                "-m",
                "kryvola_fabric.ray_worker",
            ]
            subprocess.run(command, check=True, timeout=10)
            forbidden = env.replace('"EXECUTE"', '"RELEASE"')
            command[3] = "KRYVOLA_EXECUTION=" + forbidden
            rejected = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stderr.strip(), b"RAY_EXECUTION_FAILED")
            self.assertEqual(read_file(next(iter(fixtures)), "starts"), b"x")
        except Exception:
            subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "sh",
                    "-c",
                    "tail -n 12 /tmp/engine-fixture.log; "
                    "tail -n 12 /tmp/ray/session_latest/logs/dashboard.log; "
                    "find /tmp/ray/session_latest/logs/ -name 'job-driver-*.log' "
                    "-exec tail -n 12 {} +",
                ],
                timeout=10,
            )
            raise
        finally:
            subprocess.run(["docker", "rm", "-f", container], timeout=30, stdout=subprocess.DEVNULL)
