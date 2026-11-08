"""Install a checksum-pinned Linux x86_64 test CLI; no package/host installation."""

import hashlib
import io
import platform
import sys
import tarfile
import urllib.request
from pathlib import Path
from urllib.error import URLError

SHA256 = "09a0326a51db84d02735e53542b9ebd8c4758daf47482a9ab0abce15844e60d5"
URL = "https://github.com/temporalio/cli/releases/download/v1.9.1/temporal_cli_1.9.1_linux_amd64.tar.gz"
DOWNLOAD_ATTEMPTS = 3


def download() -> bytes:
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(URL, timeout=60) as response:
                return response.read(128 * 1024 * 1024 + 1)
        except (TimeoutError, URLError) as error:
            cause = error.reason if isinstance(error, URLError) else error
            if not isinstance(cause, TimeoutError) or attempt == DOWNLOAD_ATTEMPTS:
                raise
            print(
                f"Temporal CLI download timed out on attempt {attempt}; retrying", file=sys.stderr
            )
    raise AssertionError("No Temporal CLI download attempts configured")


def main() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Linux x86_64 CI installer only")
    raw = download()
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
