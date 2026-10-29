"""Explicit checksum-pinned Linux CI tools; installs only under ignored build/."""

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "cosign": (
        "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64",
        "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
        "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    ),
    "syft": (
        "https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz",
        "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d",
        "64c9631c3560336c55c549df0de08cd577d02399c9de807ac390960a4ed5c351",
    ),
}


def tool(name):
    path = ROOT / "build/release-tools" / name
    if hashlib.sha256(path.read_bytes()).hexdigest() != PINS[name][2]:
        raise ValueError("RELEASE_TOOL_INTEGRITY")
    return path


def main():
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("LINUX_X86_64_REQUIRED")
    for name, (url, digest, _) in PINS.items():
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read((160 << 20) + 1)
        if len(raw) > 160 << 20 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("RELEASE_TOOL_DOWNLOAD")
        if name == "syft":
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                entry = archive.getmember("syft")
                if not entry.isfile() or entry.size > 160 << 20:
                    raise ValueError("RELEASE_TOOL_ARCHIVE")
                stream = archive.extractfile(entry)
                assert stream is not None
                raw = stream.read()
        path = ROOT / "build/release-tools" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o700)
        tool(name)


if __name__ == "__main__":
    main()
