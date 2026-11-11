"""Separate M1 delivery assets; does not rename or replace the M0 publication."""

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from email.parser import BytesParser
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

if __package__:
    from . import release
else:
    import release

ROOT = release.ROOT
OUTPUT = ROOT / "build/m1-publication"
sha, read, write = release.sha, release.read, release.write


def inventory():
    return read(ROOT / "packaging/m1.json")


def assets(role):
    if role == "owner":
        return {"bin/kryvola-owner-agent", "LICENSE"}
    return {
        "bin/fabric-runtime",
        "LICENSE",
        "spec.lock.json",
        "Cargo.lock",
        "rust-toolchain.toml",
    } | {
        "migrations/" + path.name
        for path in (ROOT / "crates/control-core/migrations").glob("*.sql")
    }


def tar(path, contents):
    with tarfile.open(path, "w") as archive:
        for name, data in sorted(contents.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o755 if name.startswith("bin/") else 0o644
            archive.addfile(entry, io.BytesIO(data))


def wheel_name(role, source):
    return f"kryvola_fabric_{role}-{release.version(source)}-py3-none-any.whl"


def subjects(source):
    return (
        {f"{role}-{source}.tar" for role in ("runtime", "owner")}
        | {wheel_name(role, source) for role in inventory()["python"]}
        | {
            "inventory.json",
            "spec.lock.json",
            "Cargo.lock",
            "uv.lock",
            "rust-toolchain.toml",
            "ray.lock",
            "workflow.lock",
            "ray.Dockerfile",
            "sbom.spdx.json",
            "provenance.json",
            "native-runtime.json",
        }
    )


def record(folder, source):
    names = subjects(source) - {"provenance.json"}
    write(
        folder / "provenance.json",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"name": name, "digest": {"sha256": sha(folder / name)}} for name in sorted(names)
            ],
            "predicate": {
                "buildDefinition": {
                    "buildType": release.REPOSITORY + "/m1-runtime/v1",
                    "externalParameters": {
                        "source": source,
                        "spec": read(folder / "spec.lock.json"),
                    },
                },
                "runDetails": {
                    "builder": {"id": os.environ.get("GITHUB_WORKFLOW_REF", "LOCAL_QUALIFICATION")}
                },
            },
        },
    )
    manifest = {
        "schema_version": "fabric-m1-publication-v1",
        "source": source,
        "version": release.version(source),
        "spec": read(folder / "spec.lock.json"),
        "production_ready": False,
        "subjects": {name: sha(folder / name) for name in sorted(subjects(source))},
    }
    write(folder / "manifest.json", manifest)
    return manifest


def validate(folder, source):
    release.version(source)
    manifest = read(folder / "manifest.json")
    if (
        set(manifest)
        != {"schema_version", "source", "version", "spec", "production_ready", "subjects"}
        or manifest["schema_version"] != "fabric-m1-publication-v1"
        or manifest["source"] != source
        or manifest["version"] != release.version(source)
        or manifest["production_ready"] is not False
        or set(manifest["subjects"]) != subjects(source)
        or {path.name for path in folder.iterdir()}
        - subjects(source)
        - {"manifest.json", "manifest.sigstore.json"}
        or manifest["spec"] != read(ROOT / "spec.lock.json")
        or read(folder / "spec.lock.json") != manifest["spec"]
        or read(folder / "inventory.json") != inventory()
    ):
        raise ValueError("M1_MANIFEST_MISMATCH")
    for name, digest in manifest["subjects"].items():
        if sha(folder / name) != digest:
            raise ValueError("M1_SUBJECT_MISMATCH")
    native = read(folder / "native-runtime.json")
    if (
        native["platform"] != inventory()["platform"]
        or native["rust"] != inventory()["rust"]
        or set(native["libraries"]) != {"runtime", "owner"}
    ):
        raise ValueError("M1_NATIVE_RUNTIME_MISMATCH")
    for role in ("owner", "runtime"):
        with tarfile.open(folder / f"{role}-{source}.tar") as archive:
            members = archive.getmembers()
            if (
                len(members) != len(assets(role))
                or {item.name for item in members} != assets(role)
                or any(
                    not item.isfile()
                    or item.size > 128 << 20
                    or item.mode != (0o755 if item.name.startswith("bin/") else 0o644)
                    for item in members
                )
            ):
                raise ValueError("M1_ROLE_ASSET_MISMATCH")
    for role, config in inventory()["python"].items():
        with ZipFile(folder / wheel_name(role, source)) as archive:
            names = archive.namelist()
            info = f"kryvola_fabric_{role}-{release.version(source)}.dist-info/"
            modules = {"kryvola_fabric/" + name for name in config["modules"]}
            resources = {
                "kryvola_fabric/_spec/" + str(path.relative_to(ROOT / "src/kryvola_fabric/_spec"))
                for path in (ROOT / "src/kryvola_fabric/_spec").rglob("*")
                if path.is_file()
            }
            if (
                len(names) != len(set(names))
                or set(names)
                != modules
                | resources
                | {info + suffix for suffix in ("METADATA", "WHEEL", "RECORD")}
                or any(archive.getinfo(name).file_size > 8 << 20 for name in names)
            ):
                raise ValueError("M1_WHEEL_API_MISMATCH")
            metadata = BytesParser().parsebytes(archive.read(info + "METADATA"))
            if (
                metadata["Version"] != release.version(source)
                or metadata["Name"] != f"kryvola-fabric-{role}"
                or set(metadata.get_all("Requires-Dist", [])) != set(config["dependencies"])
                or metadata["Requires-Python"] != f"=={config['python']}"
            ):
                raise ValueError("M1_WHEEL_DEPENDENCY_MISMATCH")
            for name in resources:
                if archive.read(name) != (ROOT / "src" / name).read_bytes():
                    raise ValueError("M1_WHEEL_SCHEMA_SKEW")
    provenance = read(folder / "provenance.json")
    if (
        provenance["_type"] != "https://in-toto.io/Statement/v1"
        or provenance["predicateType"] != "https://slsa.dev/provenance/v1"
    ):
        raise ValueError("M1_PROVENANCE_MISMATCH")
    if provenance["subject"] != [
        {"name": name, "digest": {"sha256": manifest["subjects"][name]}}
        for name in sorted(subjects(source) - {"provenance.json"})
    ] or provenance["predicate"]["buildDefinition"]["externalParameters"] != {
        "source": source,
        "spec": manifest["spec"],
    }:
        raise ValueError("M1_PROVENANCE_MISMATCH")
    return manifest


def build():
    source = release.git("rev-parse", "HEAD")
    if release.git("status", "--porcelain") or os.environ.get("GITHUB_SHA", source) != source:
        raise ValueError("CLEAN_PINNED_SOURCE_REQUIRED")
    OUTPUT.mkdir(parents=True, exist_ok=False)
    subprocess.run(
        ["cargo", "build", "--locked", "--release", "--workspace"],
        cwd=ROOT,
        check=True,
        timeout=1800,
    )
    native = {"platform": inventory()["platform"], "rust": inventory()["rust"], "libraries": {}}
    for role, binary in (("runtime", "fabric-runtime"), ("owner", "kryvola-owner-agent")):
        linked = release.run(
            "ldd", ROOT / "target/release" / binary, capture_output=True, text=True
        ).stdout
        native["libraries"][role] = {
            path: sha(Path(path)) for path in re.findall(r"(/[^\s()]+)", linked)
        }
        contents = {}
        for name in assets(role):
            path = (
                ROOT / "target/release" / binary
                if name.startswith("bin/")
                else ROOT / "crates/control-core" / name
                if name.startswith("migrations/")
                else ROOT / name
            )
            contents[name] = path.read_bytes()
        tar(OUTPUT / f"{role}-{source}.tar", contents)
    write(OUTPUT / "native-runtime.json", native)
    for name in ("spec.lock.json", "Cargo.lock", "uv.lock", "rust-toolchain.toml"):
        shutil.copyfile(ROOT / name, OUTPUT / name)
    for name in ("ray.lock", "workflow.lock", "ray.Dockerfile"):
        shutil.copyfile(ROOT / "packaging" / name, OUTPUT / name)
    shutil.copyfile(ROOT / "packaging/m1.json", OUTPUT / "inventory.json")
    env = {**os.environ, "SOURCE_DATE_EPOCH": release.git("show", "-s", "--format=%ct", "HEAD")}
    for role, config in inventory()["python"].items():
        with TemporaryDirectory() as temporary:
            stage = Path(temporary)
            package = stage / "src/kryvola_fabric"
            package.mkdir(parents=True)
            for name in config["modules"]:
                shutil.copyfile(ROOT / "src/kryvola_fabric" / name, package / name)
            shutil.copytree(ROOT / "src/kryvola_fabric/_spec", package / "_spec")
            (stage / "pyproject.toml").write_text(
                f'[project]\nname="kryvola-fabric-{role}"\nversion="{release.version(source)}"\nrequires-python="=={config["python"]}"\ndependencies={json.dumps(config["dependencies"])}\n'
                '[build-system]\nrequires=["hatchling==1.32.4"]\nbuild-backend="hatchling.build"\n'
                '[tool.hatch.build.targets.wheel]\npackages=["src/kryvola_fabric"]\n'
            )
            built = []
            for number in range(2):
                destination = stage / str(number)
                release.run(
                    sys.executable,
                    "-m",
                    "hatchling",
                    "build",
                    "-t",
                    "wheel",
                    "-d",
                    destination,
                    cwd=stage,
                    env=env,
                )
                built.append(destination / wheel_name(role, source))
            if sha(built[0]) != sha(built[1]):
                raise ValueError("M1_NON_REPRODUCIBLE_WHEEL")
            shutil.copyfile(built[0], OUTPUT / built[0].name)
    release.run(
        release.tool("syft"),
        "scan",
        "dir:" + str(OUTPUT),
        "-o",
        "spdx-json=" + str(OUTPUT / "sbom.spdx.json"),
    )
    record(OUTPUT, source)
    validate(OUTPUT, source)
    release.run(sys.executable, ROOT / "tools/check_runtime.py", str(OUTPUT), source)


def verify(folder, source, key=None):
    validate(folder, source)
    args = [release.tool("cosign"), "verify-blob", "--bundle", folder / "manifest.sigstore.json"]
    if key is not None:
        args += ["--key", key, "--insecure-ignore-tlog", "--offline"]
    else:
        args += [
            "--certificate-identity",
            release.IDENTITY,
            "--certificate-oidc-issuer",
            release.ISSUER,
            "--certificate-github-workflow-sha",
            source,
            "--certificate-github-workflow-trigger",
            "workflow_dispatch",
        ]
        if read(folder / "provenance.json")["predicate"]["runDetails"]["builder"][
            "id"
        ] != release.IDENTITY.removeprefix("https://github.com/"):
            raise ValueError("M1_BUILDER_MISMATCH")
    release.run(*args, folder / "manifest.json", capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("qualify", "verify"))
    parser.add_argument("--folder", type=Path, default=OUTPUT)
    parser.add_argument("--source")
    args = parser.parse_args()
    if args.command == "verify":
        verify(args.folder, args.source)
    else:
        build()
        source = release.git("rev-parse", "HEAD")
        with TemporaryDirectory() as temporary:
            key = Path(temporary) / "key"
            env = {**os.environ, "COSIGN_PASSWORD": "public-ci-fixture"}
            release.run(
                release.tool("cosign"), "generate-key-pair", "--output-key-prefix", key, env=env
            )
            release.run(
                release.tool("cosign"),
                "sign-blob",
                "--yes",
                "--use-signing-config=false",
                "--tlog-upload=false",
                "--key",
                str(key) + ".key",
                "--bundle",
                OUTPUT / "manifest.sigstore.json",
                OUTPUT / "manifest.json",
                env=env,
            )
            verify(OUTPUT, source, Path(str(key) + ".pub"))
            wrong = Path(temporary) / "wrong"
            release.run(
                release.tool("cosign"), "generate-key-pair", "--output-key-prefix", wrong, env=env
            )
            try:
                verify(OUTPUT, source, Path(str(wrong) + ".pub"))
            except subprocess.CalledProcessError:
                pass
            else:
                raise ValueError("M1_WRONG_SIGNER_ACCEPTED")
            originals = {
                name: (OUTPUT / name).read_bytes()
                for name in (
                    "manifest.json",
                    "provenance.json",
                    "sbom.spdx.json",
                )
            }
            try:
                (OUTPUT / "sbom.spdx.json").write_bytes(originals["sbom.spdx.json"] + b"\n")
                record(OUTPUT, source)
                try:
                    verify(OUTPUT, source, Path(str(key) + ".pub"))
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise ValueError("M1_TAMPERED_SIGNATURE_ACCEPTED")
            finally:
                for name, data in originals.items():
                    (OUTPUT / name).write_bytes(data)
        (OUTPUT / "manifest.sigstore.json").unlink()


if __name__ == "__main__":
    main()
