"""Experimental Python wheel qualification; never enables a production capability."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

if __package__:
    from .install_release import tool
else:
    from install_release import tool

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/stanimirivanov/kryvola-fabric"
IDENTITY = REPOSITORY + "/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
OUTPUT = ROOT / "build/publication"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=300, **kwargs)


def git(*args):
    return run("git", "-C", ROOT, *args, capture_output=True, text=True).stdout.strip()


def sha(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 << 20:
        raise ValueError("INVALID_RELEASE_FILE")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("DUPLICATE_RELEASE_KEY")
        result[key] = value
    return result


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1 << 20:
        raise ValueError("RELEASE_METADATA_LIMIT")
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def version(source):
    if not isinstance(source, str) or re.fullmatch("[0-9a-f]{40}", source) is None:
        raise ValueError("INVALID_RELEASE_SOURCE")
    return "0.1.0.dev0+g" + source


def validate(folder, source):
    expected_version = version(source)
    wheel = f"kryvola_fabric-{expected_version}-py3-none-any.whl"
    subjects = {wheel, "LICENSE", "uv.lock", "sbom.spdx.json", "provenance.json"}
    manifest = read(folder / "manifest.json")
    if (
        set(manifest)
        != {"schema_version", "source", "version", "distribution", "production_ready", "subjects"}
        or manifest["schema_version"] != "fabric-publication-v1"
        or manifest["source"] != source
        or manifest["version"] != expected_version
        or manifest["distribution"] != "EXPERIMENTAL_CONFORMANCE_ONLY"
        or manifest["production_ready"] is not False
        or not isinstance(manifest["subjects"], dict)
        or set(manifest["subjects"]) != subjects
        or not {p.name for p in folder.iterdir()}.issubset(
            subjects | {"manifest.json", "manifest.sigstore.json"}
        )
    ):
        raise ValueError("RELEASE_MANIFEST_MISMATCH")
    for name, digest in manifest["subjects"].items():
        if not isinstance(digest, str) or sha(folder / name) != digest:
            raise ValueError("RELEASE_SUBJECT_MISMATCH")
    with ZipFile(folder / wheel) as archive:
        entry = archive.getinfo(f"kryvola_fabric-{expected_version}.dist-info/METADATA")
        if entry.file_size > 65536:
            raise ValueError("WHEEL_METADATA_LIMIT")
        metadata = archive.read(entry)
        if f"Version: {expected_version}\n".encode() not in metadata:
            raise ValueError("WHEEL_VERSION_MISMATCH")
    provenance = read(folder / "provenance.json")
    if (
        provenance["_type"] != "https://in-toto.io/Statement/v1"
        or provenance["predicateType"] != "https://slsa.dev/provenance/v1"
        or provenance["subject"] != [{"name": wheel, "digest": {"sha256": sha(folder / wheel)}}]
        or provenance["predicate"]["buildDefinition"]["externalParameters"]
        != {"repository": REPOSITORY, "ref": source, "version": expected_version}
    ):
        raise ValueError("RELEASE_PROVENANCE_MISMATCH")
    return manifest


def build():
    source = git("rev-parse", "HEAD")
    release_version = version(source)
    if git("status", "--porcelain") or os.environ.get("GITHUB_SHA", source) != source:
        raise ValueError("CLEAN_PINNED_SOURCE_REQUIRED")
    OUTPUT.mkdir(parents=True, exist_ok=False)
    lock = read(ROOT / "spec.lock.json")
    env = {**os.environ, "SOURCE_DATE_EPOCH": git("show", "-s", "--format=%ct", "HEAD")}
    with TemporaryDirectory() as temporary:
        wheels = []
        for index in range(2):
            stage = Path(temporary) / str(index)
            stage.mkdir()
            for name in filter(None, git("ls-files", "-z").split("\0")):
                path = ROOT / name
                if not name or path.is_symlink() or not path.is_file():
                    raise ValueError("TRACKED_SOURCE_REQUIRED")
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
            project = stage / "pyproject.toml"
            text = project.read_text()
            if text.count('version = "0.1.0.dev0"') != 1:
                raise ValueError("BASE_VERSION_CHANGED")
            project.write_text(
                text.replace('version = "0.1.0.dev0"', f'version = "{release_version}"')
            )
            run(
                "uv",
                "build",
                "--no-build-isolation",
                "--python",
                sys.executable,
                "--wheel",
                "--directory",
                stage,
                "--out-dir",
                stage / "out",
                env=env,
            )
            candidates = list((stage / "out").glob("*.whl"))
            if len(candidates) != 1:
                raise ValueError("EXPECTED_ONE_WHEEL")
            wheels.append(candidates[0])
        if sha(wheels[0]) != sha(wheels[1]):
            raise ValueError("NON_REPRODUCIBLE_WHEEL")
        wheel = OUTPUT / wheels[0].name
        shutil.copyfile(wheels[0], wheel)
    run(sys.executable, ROOT / "tools/check_wheel.py", "--wheel", wheel)
    for name in ("LICENSE", "uv.lock"):
        shutil.copyfile(ROOT / name, OUTPUT / name)
    run(
        tool("syft"),
        "scan",
        "file:" + str(wheel),
        "-o",
        "spdx-json=" + str(OUTPUT / "sbom.spdx.json"),
    )
    write(
        OUTPUT / "provenance.json",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": wheel.name, "digest": {"sha256": sha(wheel)}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": REPOSITORY + "/experimental-wheel-two-builds/v1",
                    "externalParameters": {
                        "repository": REPOSITORY,
                        "ref": source,
                        "version": release_version,
                    },
                    "resolvedDependencies": [
                        {"uri": "git+" + REPOSITORY, "digest": {"gitCommit": source}},
                        {
                            "uri": "urn:kryvola:spec-bundle",
                            "digest": {"sha256": lock["manifest_sha256"]},
                        },
                        {"uri": "uv.lock", "digest": {"sha256": sha(ROOT / "uv.lock")}},
                    ],
                },
                "runDetails": {
                    "builder": {"id": os.environ.get("GITHUB_WORKFLOW_REF", "LOCAL_QUALIFICATION")}
                },
            },
        },
    )
    names = [wheel.name, "LICENSE", "uv.lock", "sbom.spdx.json", "provenance.json"]
    write(
        OUTPUT / "manifest.json",
        {
            "schema_version": "fabric-publication-v1",
            "source": source,
            "version": release_version,
            "distribution": "EXPERIMENTAL_CONFORMANCE_ONLY",
            "production_ready": False,
            "subjects": {name: sha(OUTPUT / name) for name in names},
        },
    )
    validate(OUTPUT, source)


def verify(folder, source, key=None):
    validate(folder, source)
    args = [tool("cosign"), "verify-blob", "--bundle", folder / "manifest.sigstore.json"]
    if key is not None:
        args += ["--key", key, "--insecure-ignore-tlog", "--offline"]
    else:
        args += [
            "--certificate-identity",
            IDENTITY,
            "--certificate-oidc-issuer",
            ISSUER,
            "--certificate-github-workflow-sha",
            source,
            "--certificate-github-workflow-trigger",
            "workflow_dispatch",
        ]
        if read(folder / "provenance.json")["predicate"]["runDetails"]["builder"][
            "id"
        ] != IDENTITY.removeprefix("https://github.com/"):
            raise ValueError("PUBLICATION_BUILDER_MISMATCH")
    run(*args, folder / "manifest.json", capture_output=True)


def qualify():
    build()
    source = git("rev-parse", "HEAD")
    with TemporaryDirectory() as temporary:
        env = {**os.environ, "COSIGN_PASSWORD": "public-ci-fixture"}
        keys = [Path(temporary) / name for name in ("right", "wrong")]
        for key in keys:
            run(tool("cosign"), "generate-key-pair", "--output-key-prefix", key, env=env)
        run(
            tool("cosign"),
            "sign-blob",
            "--yes",
            "--use-signing-config=false",
            "--tlog-upload=false",
            "--key",
            str(keys[0]) + ".key",
            "--bundle",
            OUTPUT / "manifest.sigstore.json",
            OUTPUT / "manifest.json",
            env=env,
        )
        verify(OUTPUT, source, Path(str(keys[0]) + ".pub"))
        try:
            verify(OUTPUT, source, Path(str(keys[1]) + ".pub"))
        except subprocess.CalledProcessError:
            pass
        else:
            raise ValueError("WRONG_SIGNER_ACCEPTED")
        # Keep the structure/hash bindings valid while invalidating the real signature.
        manifest = (OUTPUT / "manifest.json").read_bytes()
        sbom = (OUTPUT / "sbom.spdx.json").read_bytes()
        try:
            (OUTPUT / "sbom.spdx.json").write_bytes(sbom + b"\n")
            changed = read(OUTPUT / "manifest.json")
            changed["subjects"]["sbom.spdx.json"] = sha(OUTPUT / "sbom.spdx.json")
            write(OUTPUT / "manifest.json", changed)
            try:
                verify(OUTPUT, source, Path(str(keys[0]) + ".pub"))
            except subprocess.CalledProcessError:
                pass
            else:
                raise ValueError("TAMPERED_SIGNATURE_ACCEPTED")
        finally:
            (OUTPUT / "manifest.json").write_bytes(manifest)
            (OUTPUT / "sbom.spdx.json").write_bytes(sbom)
    # A local-key fixture bundle must never flow into the publication job.
    (OUTPUT / "manifest.sigstore.json").unlink()
    print("REPRODUCIBLE_WHEEL_AND_SIGNATURE_NEGATIVE_PASSED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["qualify", "verify"])
    parser.add_argument("--folder", type=Path, default=OUTPUT)
    parser.add_argument("--source")
    args = parser.parse_args()
    if args.command == "qualify":
        qualify()
    else:
        verify(args.folder, args.source)


if __name__ == "__main__":
    main()
