"""Install a checksum-pinned Linux x86_64 test CLI; no package/host installation."""

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

SHA256 = "09a0326a51db84d02735e53542b9ebd8c4758daf47482a9ab0abce15844e60d5"
URL = "https://github.com/temporalio/cli/releases/download/v1.9.1/temporal_cli_1.9.1_linux_amd64.tar.gz"


def main() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Linux x86_64 CI installer only")
    with urllib.request.urlopen(URL, timeout=60) as response:
        raw = response.read(128 * 1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("TEMPORAL_CLI_DIGEST_MISMATCH")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        entry = archive.getmember("temporal")
        if not entry.isfile() or entry.size > 256 * 1024 * 1024:
            raise ValueError("TEMPORAL_CLI_INVALID_ARCHIVE")
        stream = archive.extractfile(entry)
        assert stream is not None
        target = Path("build/temporal/temporal")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(stream.read())
        target.chmod(0o755)


if __name__ == "__main__":
    main()
