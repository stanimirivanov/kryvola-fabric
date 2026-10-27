"""Focused dependency and vendored-contract checks; not a semantic security proof."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

REPO = "kryvola-fabric"
IMPLEMENTATIONS = {"kryvola_fabric", "kryvola_engines", "kryvola_ml", "kryvola_platform"}

REQUIRED_ARTIFACTS = {
    "control/Operation.schema.json",
    "engine/ExecuteRequest.schema.json",
    "profiles/ModelDescriptor.schema.json",
    "python/limits.py",
    "artifact-ref.schema.json",
    "limits.json",
    "rust/limits.rs",
    "cpp/artifact_ref.hpp",
    "fixtures/artifact-ref.json",
    "rust/artifact_ref.rs",
    "foundation-inventory.schema.json",
    "proto/kryvola/spec/v1/artifact_ref.proto",
    "cpp/limits.hpp",
    "python/artifact_ref.py",
}
REQUIRED_NATIVE_ARTIFACTS = {"descriptor.bin", "schemas.json", "vectors.json", "fixtures.json"}
RUNTIME_ASSETS = {"descriptor.bin": "native", "schemas.json": "native", "limits.json": "spec"}


def is_foreign(name: str, forbidden: set[str]) -> bool:
    normalized = re.sub(r"[-_.]+", "_", name).lower()
    return any(normalized == item or normalized.startswith(item + "_") for item in forbidden)


def verify_contracts(root: Path) -> None:
    lock = json.loads((root / "spec.lock.json").read_text(encoding="utf-8"))
    if lock["repository"] != "https://github.com/stanimirivanov/kryvola-spec":
        raise ValueError("spec.lock.json: unexpected source repository")
    if not re.fullmatch(r"[0-9a-f]{40}", lock["revision"]):
        raise ValueError("spec.lock.json: immutable source revision required")
    vendor = (root / lock["artifact_root"]).resolve()
    if not vendor.is_relative_to(root.resolve()):
        raise ValueError("spec.lock.json: artifact_root escapes repository")
    raw = (vendor / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock["manifest_sha256"]:
        raise ValueError("spec.lock.json: contract manifest digest mismatch")
    manifest = json.loads(raw)
    if manifest["contract_version"] != lock["contract_version"]:
        raise ValueError("spec.lock.json: contract version mismatch")
    if not REQUIRED_ARTIFACTS.issubset(manifest["files"]):
        raise ValueError("contracts: required contract projections missing from manifest")
    expected = {"manifest.json", *manifest["files"]}
    actual = {
        p.relative_to(vendor).as_posix()
        for p in vendor.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    if expected != actual:
        raise ValueError("contracts: missing or unlisted artifact files")
    for name, digest in manifest["files"].items():
        path = (vendor / name).resolve()
        if not path.is_relative_to(vendor):
            raise ValueError(f"contracts: unsafe manifest path {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"contracts: modified generated artifact {name}")
    native = (root / lock["native_artifact_root"]).resolve()
    if not native.is_relative_to(root.resolve()):
        raise ValueError("contracts: native root escapes repository")
    raw = (native / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock["native_manifest_sha256"]:
        raise ValueError("contracts: native manifest digest mismatch")
    bindings = json.loads(raw)
    if bindings["contract_version"] != lock[
        "contract_version"
    ] or not REQUIRED_NATIVE_ARTIFACTS.issubset(bindings["files"]):
        raise ValueError("contracts: native version or required artifacts mismatch")
    if {p.relative_to(native).as_posix() for p in native.rglob("*") if p.is_file()} != {
        "manifest.json",
        *bindings["files"],
    }:
        raise ValueError("contracts: missing or unlisted native artifacts")
    for name, digest in bindings["files"].items():
        path = (native / name).resolve()
        if (
            not path.is_relative_to(native)
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise ValueError("contracts: modified native artifact")
    generated_sources = {
        name.removeprefix("generated/"): digest
        for name, digest in bindings["sources"].items()
        if name.startswith("generated/")
    }
    if set(generated_sources) != expected or any(
        hashlib.sha256((vendor / name).read_bytes()).hexdigest() != digest
        for name, digest in generated_sources.items()
    ):
        raise ValueError("contracts: mixed generated/native bundles")
    for name, bundle in RUNTIME_ASSETS.items():
        source = vendor if bundle == "spec" else native
        if (root / "src/kryvola_fabric/_spec" / name).read_bytes() != (source / name).read_bytes():
            raise ValueError("contracts: modified packaged runtime asset")


def dependency_errors(root: Path, repo: str) -> list[str]:
    errors: list[str] = []
    pyproject = root / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    forbidden = set() if repo == "kryvola-platform" else IMPLEMENTATIONS - {repo.replace("-", "_")}
    for package in data.get("project", {}).get("dependencies", []):
        normalized = re.split(r"[\s<>=!~;\[@]", package, maxsplit=1)[0]
        if is_foreign(normalized, forbidden) or re.search(
            r"@\s*(?:file:|\.\.?[/\\])", package, re.IGNORECASE
        ):
            errors.append(f"pyproject.toml: forbidden implementation/local dependency {package}")
    for name, source in data.get("tool", {}).get("uv", {}).get("sources", {}).items():
        if isinstance(source, dict) and "path" in source:
            errors.append(
                f"pyproject.toml: local source dependency {name} is not a release artifact"
            )
    for path in sorted((root / "src").rglob("*.py")):
        if "_spec" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            imports: list[str] = []
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports = [node.module]
            else:
                continue
            for imported in imports:
                if is_foreign(imported.split(".")[0], forbidden):
                    errors.append(
                        f"{path.relative_to(root)}:{node.lineno}: "
                        f"forbidden implementation import {imported}"
                    )
    cargo_files = [root / "Cargo.toml", *(root / "crates").glob("*/Cargo.toml")]
    if repo in {"kryvola-fabric", "kryvola-engines"} and not cargo_files[0].is_file():
        errors.append("Cargo.toml: required Rust workspace missing")
    for path in cargo_files:
        if not path.is_file():
            continue
        cargo = tomllib.loads(path.read_text(encoding="utf-8"))
        sections = [cargo, cargo.get("workspace", {}), *cargo.get("target", {}).values()]
        for section in sections:
            for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, value in section.get(group, {}).items():
                    if is_foreign(name.replace("-", "_"), forbidden):
                        errors.append(
                            f"{path.relative_to(root)}: forbidden implementation dependency {name}"
                        )
                    if isinstance(value, dict) and "path" in value:
                        target = (path.parent / value["path"]).resolve()
                        if not target.is_relative_to(root.resolve()):
                            errors.append(
                                f"{path.relative_to(root)}: dependency {name} escapes repository"
                            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        verify_contracts(args.root)
        errors = dependency_errors(args.root, REPO)
        if errors:
            raise ValueError("\n".join(errors))
    except (ValueError, KeyError, OSError, SyntaxError) as error:
        print(f"architecture: {error}", file=sys.stderr)
        return 1
    print("Architecture and pinned spec artifact checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
