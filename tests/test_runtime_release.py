"""Fail-closed M1 inventory and role/package isolation controls."""

import copy
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from tools import runtime_release as runtime
from tools.release import read, write


def fixture_manifest(folder):
    source = "a" * 40
    for name in runtime.subjects(source) - {"provenance.json"}:
        (folder / name).write_bytes(b"fixture")
    for role in ("runtime", "owner"):
        runtime.tar(
            folder / f"{role}-{source}.tar", {name: b"fixture" for name in runtime.assets(role)}
        )
    for role, config in runtime.inventory()["python"].items():
        with ZipFile(folder / runtime.wheel_name(role, source), "w") as archive:
            for name in config["modules"]:
                archive.writestr("kryvola_fabric/" + name, b"fixture")
            for path in (runtime.ROOT / "src/kryvola_fabric/_spec").rglob("*"):
                if path.is_file():
                    archive.writestr(
                        "kryvola_fabric/_spec/"
                        + str(path.relative_to(runtime.ROOT / "src/kryvola_fabric/_spec")),
                        path.read_bytes(),
                    )
            info = f"kryvola_fabric_{role}-{runtime.release.version(source)}.dist-info/"
            archive.writestr(
                info + "METADATA",
                f"Name: kryvola-fabric-{role}\nVersion: {runtime.release.version(source)}\n"
                f"Requires-Python: =={config['python']}\n"
                + "".join(
                    "Requires-Dist: " + dependency + "\n" for dependency in config["dependencies"]
                ),
            )
            archive.writestr(info + "WHEEL", "fixture")
            archive.writestr(info + "RECORD", "fixture")
    write(folder / "spec.lock.json", read(runtime.ROOT / "spec.lock.json"))
    write(folder / "inventory.json", runtime.inventory())
    write(
        folder / "native-runtime.json",
        {"platform": "linux-x86_64", "rust": "1.98.1", "libraries": {"runtime": {}, "owner": {}}},
    )
    return runtime.record(folder, source)


class RuntimeReleaseTests(unittest.TestCase):
    def test_role_boundaries_are_explicit_and_disjoint(self):
        roles = runtime.inventory()["python"]
        self.assertEqual(set(roles), {"workflow", "ray"})
        self.assertNotIn("ray_worker.py", roles["workflow"]["modules"])
        self.assertNotIn("compute_workflow.py", roles["ray"]["modules"])
        self.assertNotIn("temporalio", " ".join(roles["ray"]["dependencies"]))
        self.assertFalse(
            any("owner" in dep for role in roles.values() for dep in role["dependencies"])
        )

    def test_missing_extra_and_schema_skew_fail_before_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            manifest = fixture_manifest(folder)
            self.assertEqual(runtime.validate(folder, manifest["source"]), manifest)
            for name in manifest["subjects"]:
                original = (folder / name).read_bytes()
                (folder / name).unlink()
                with self.assertRaises(ValueError):
                    runtime.validate(folder, manifest["source"])
                (folder / name).write_bytes(original)
            changed = copy.deepcopy(manifest)
            changed["spec"]["revision"] = "0" * 40
            write(folder / "manifest.json", changed)
            with self.assertRaises(ValueError):
                runtime.validate(folder, manifest["source"])
            write(folder / "manifest.json", manifest)
            (folder / "unexpected.key").write_bytes(b"fixture")
            with self.assertRaises(ValueError):
                runtime.validate(folder, manifest["source"])

    def test_rehashed_role_injection_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            manifest = fixture_manifest(folder)
            name = next(name for name in manifest["subjects"] if name.startswith("owner-"))
            runtime.tar(folder / name, {"bin/fabric-runtime": b"wrong-role"})
            manifest["subjects"][name] = runtime.sha(folder / name)
            write(folder / "manifest.json", manifest)
            with self.assertRaises(ValueError):
                runtime.validate(folder, manifest["source"])
            self.assertEqual(read(folder / "manifest.json"), manifest)


class NativeLibraryTests(unittest.TestCase):
    def test_system_library_symlinks_bind_the_resolved_file(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "libexample.so.1.2"
            real.write_bytes(b"public library fixture")
            link = Path(directory) / "libexample.so.1"
            link.symlink_to(real)
            with patch.object(
                runtime.release,
                "run",
                return_value=SimpleNamespace(stdout=f"libexample.so.1 => {link} (0x0000)\n"),
            ):
                self.assertEqual(runtime.libraries(Path("fixture")), {str(real): runtime.sha(real)})
