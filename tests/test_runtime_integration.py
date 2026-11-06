import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import runtime_integration as runtime


class RuntimeFixtureTests(unittest.TestCase):
    def test_failed_start_cleans_the_same_project(self):
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == "context":
                return subprocess.CompletedProcess(args, 0, "unix:///var/run/docker.sock\n")
            if args[-4:] == ("up", "-d", "--wait", "--wait-timeout=90"):
                raise RuntimeError("startup failed")
            return subprocess.CompletedProcess(args, 0, "")

        with tempfile.TemporaryDirectory() as folder, patch.object(runtime, "docker", docker):
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                runtime.run(Path(folder))
        start, cleanup = calls[-2:]
        self.assertEqual(start[:-4], cleanup[:-3])
        self.assertEqual(cleanup[-3:], ("down", "--volumes", "--remove-orphans"))

    def test_runtime_failure_timeout_and_interruption_clean_the_owned_project(self):
        for failure in [
            RuntimeError("unhealthy runtime"),
            FileNotFoundError("missing cargo"),
            subprocess.TimeoutExpired(["cargo"], 30),
            KeyboardInterrupt(),
        ]:
            calls = []

            def docker(*args, _calls=calls, **kwargs):
                _calls.append(args)
                output = "unix:///var/run/docker.sock\n" if args[0] == "context" else ""
                return subprocess.CompletedProcess(args, 0, output)

            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as folder,
                patch.object(runtime, "docker", docker),
                patch.object(runtime, "check_runtime", side_effect=failure),
                patch.object(
                    runtime,
                    "check_postgres",
                    side_effect=AssertionError("runtime probe was bypassed"),
                ),
            ):
                with self.assertRaises(type(failure)):
                    runtime.run(Path(folder))
            start, cleanup = calls[-2:]
            self.assertEqual(start[:-4], cleanup[:-3])
            self.assertEqual(cleanup[-3:], ("down", "--volumes", "--remove-orphans"))

    def test_workload_auth_failure_cleans_fixture_before_database_probes(self):
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            output = "unix:///var/run/docker.sock\n" if args[0] == "context" else ""
            return subprocess.CompletedProcess(args, 0, output)

        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(runtime, "docker", docker),
            patch.object(runtime, "check_runtime"),
            patch.object(runtime, "check_workload_auth", side_effect=RuntimeError("SPIRE failed")),
            patch.object(runtime, "check_postgres") as database,
        ):
            with self.assertRaisesRegex(RuntimeError, "SPIRE failed"):
                runtime.run(Path(folder))
        database.assert_not_called()
        self.assertEqual(calls[-2][:-4], calls[-1][:-3])
        self.assertEqual(calls[-1][-3:], ("down", "--volumes", "--remove-orphans"))

    def test_remote_docker_is_rejected_before_provisioning(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict(runtime.os.environ, {"DOCKER_HOST": "tcp://example.invalid:2375"}),
            patch.object(runtime, "docker") as docker,
        ):
            with self.assertRaisesRegex(RuntimeError, "local Docker"):
                runtime.run(Path(folder))
        docker.assert_not_called()

    def test_probe_build_failure_execution_failure_and_skips_fail_closed(self):
        success = subprocess.CompletedProcess([], 0, "built", "")
        for results, reason in [
            ([subprocess.CompletedProcess([], 1, "", "secret")], "Runtime probe build failed"),
            (
                [success, subprocess.CompletedProcess([], 1, "", "secret")],
                "Bounded runtime probe failed",
            ),
            (
                [success, subprocess.CompletedProcess([], 0, "0 passed; 0 failed; 1 ignored", "")],
                "did not run",
            ),
            (
                [
                    success,
                    subprocess.CompletedProcess(
                        [], 0, "test unrelated ... ok\n1 passed; 0 failed", ""
                    ),
                ],
                "did not run",
            ),
        ]:
            with (
                self.subTest(reason=reason),
                patch.object(runtime, "_runtime_command", side_effect=results),
            ):
                with self.assertRaisesRegex(RuntimeError, reason) as raised:
                    runtime.check_runtime()
                self.assertNotIn("secret", str(raised.exception))
        with patch.object(
            runtime,
            "_runtime_command",
            side_effect=[
                success,
                subprocess.CompletedProcess(
                    [],
                    0,
                    "test loopback_shell_bounds_requests_and_denies_runtime_routes ... ok\n"
                    "1 passed; 0 failed",
                    "",
                ),
            ],
        ):
            runtime.check_runtime()

    def test_owned_runtime_command_returns_output_and_rejects_missing_tools(self):
        result = runtime._runtime_command([sys.executable, "-c", "print('ready')"], 5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "ready")
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                runtime._runtime_command([str(Path(folder) / "missing-tool")], 5)

    def test_timeout_cleans_descendant_even_after_parent_exit(self):
        # The child holds the output pipe and loopback socket after its parent exits.
        child = (
            "import signal,socket,sys; from pathlib import Path; "
            "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); "
            "Path(sys.argv[1]).write_text(str(s.getsockname()[1])); signal.pause()"
        )
        parent = (
            "import subprocess,sys; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])"
        )
        with tempfile.TemporaryDirectory() as folder:
            port = Path(folder) / "port"
            with self.assertRaises(subprocess.TimeoutExpired):
                runtime._runtime_command([sys.executable, "-c", parent, child, str(port)], 3)
            with socket.socket() as connection:
                connection.settimeout(1)
                self.assertNotEqual(connection.connect_ex(("127.0.0.1", int(port.read_text()))), 0)


if __name__ == "__main__":
    unittest.main()
