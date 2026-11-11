"""Execute M1 packages from fresh isolated installations, never a source mount."""

import argparse
import shutil
import subprocess
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory

if __package__:
    from . import runtime_release as runtime
else:
    import runtime_release as runtime


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=600, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("source")
    args = parser.parse_args()
    folder = args.folder.resolve()
    runtime.validate(folder, args.source)
    for libraries in runtime.read(folder / "native-runtime.json")["libraries"].values():
        for name, digest in libraries.items():
            if runtime.sha(Path(name)) != digest:
                raise ValueError("INSTALLED_NATIVE_LIBRARY_MISMATCH")
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for role, binary in (("runtime", "fabric-runtime"), ("owner", "kryvola-owner-agent")):
            target = root / role
            with tarfile.open(folder / f"{role}-{args.source}.tar") as archive:
                archive.extractall(target, filter="data")
            result = subprocess.run(
                [target / "bin" / binary, "--invalid"], cwd=root, capture_output=True, timeout=10
            )
            if result.returncode != (1 if role == "runtime" else 2):
                raise ValueError("INSTALLED_BINARY_STARTUP_FAILED")
        environment = root / "workflow-env"
        run("uv", "venv", "--python", "3.14.7", environment)
        python = environment / "bin/python"
        run("uv", "pip", "sync", "--python", python, "--require-hashes", folder / "workflow.lock")
        run(
            "uv",
            "pip",
            "install",
            "--python",
            python,
            "--no-deps",
            folder / runtime.wheel_name("workflow", args.source),
        )
        run(
            python,
            "-I",
            "-c",
            """import importlib.util, sys
from kryvola_fabric.compute_workflow import ComputeWorkflow, DATA_CONVERTER
from kryvola_fabric.compute_activities import ComputeActivities
from kryvola_fabric.compute_release import CoordinatorRelease
assert sys.version_info[:3] == (3,14,7)
assert importlib.util.find_spec('kryvola_fabric.ray_worker') is None
assert importlib.util.find_spec('kryvola_fabric.conformance') is None
assert importlib.util.find_spec('kryvola_owner') is None
""",
            cwd=root,
        )
        # Replay the existing public Temporal trace against the installed role wheel.
        tests = root / "tests"
        tests.mkdir()
        shutil.copyfile(runtime.ROOT / "tests/live_durable_workflow.py", tests / "live.py")
        fixture = root / "contracts/spec/fixtures"
        fixture.mkdir(parents=True)
        shutil.copyfile(
            runtime.ROOT / "contracts/spec/fixtures/control.json", fixture / "control.json"
        )
        temporal = root / "build/temporal"
        temporal.mkdir(parents=True)
        (temporal / "temporal").symlink_to(runtime.ROOT / "build/temporal/temporal")
        run(python, "-I", tests / "live.py", cwd=root)
        image = "kryvola-fabric-ray:" + args.source
        run("docker", "build", "--file", folder / "ray.Dockerfile", "--tag", image, folder)
        run(
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python",
            image,
            "-I",
            "-c",
            """import importlib.util, sys, ray, grpc
from kryvola_fabric.control import decode_control
from kryvola_fabric.ray_worker import decode_envelope
assert sys.version_info[:3] == (3,12,14)
assert ray.__version__ == '2.59.0' and grpc.__version__ == '1.75.0'
assert decode_control('GetCapabilitiesRequest', bytes.fromhex('0a0131'))['schema_version']=='1'
assert importlib.util.find_spec('kryvola_fabric.compute_workflow') is None
assert importlib.util.find_spec('kryvola_owner') is None
try: decode_envelope('invalid')
except ValueError: pass
else: raise AssertionError('unbounded bridge input')
""",
        )
    print("M1_INSTALLED_RUNTIME_AND_ROLE_ISOLATION_PASSED")


if __name__ == "__main__":
    main()
