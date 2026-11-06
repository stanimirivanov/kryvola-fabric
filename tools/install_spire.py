"""Install a checksum-pinned Linux x86_64 SPIRE fixture binaries; no package/host installation."""

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

SHA256 = "7bcf5e167151a1fc58293768462b44e155ba8784214582aefa6adf18c633d1d5"
URL = (
    "https://github.com/spiffe/spire/releases/download/v1.16.0/spire-1.16.0-linux-amd64-musl.tar.gz"
)


def main() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Linux x86_64 CI installer only")
    with urllib.request.urlopen(URL, timeout=60) as response:
        raw = response.read(128 * 1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("SPIRE_DIGEST_MISMATCH")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for name in ("spire-server", "spire-agent"):
            entry = archive.getmember(f"spire-1.16.0/bin/{name}")
            if not entry.isfile() or entry.size > 256 * 1024 * 1024:
                raise ValueError("SPIRE_INVALID_ARCHIVE")
            stream = archive.extractfile(entry)
            assert stream is not None
            target = Path("build/spire") / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.read())
            target.chmod(0o755)


if __name__ == "__main__":
    main()
