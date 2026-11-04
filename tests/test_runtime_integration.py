import subprocess
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

    def test_remote_docker_is_rejected_before_provisioning(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict(runtime.os.environ, {"DOCKER_HOST": "tcp://example.invalid:2375"}),
            patch.object(runtime, "docker") as docker,
        ):
            with self.assertRaisesRegex(RuntimeError, "local Docker"):
                runtime.run(Path(folder))
        docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
