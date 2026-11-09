"""Private subprocess bridge to the installed Engines owner wheel."""

import ctypes
import importlib
import importlib.metadata
import resource
import sys

MAX_ENVELOPE = (65 << 20) + 40


def main() -> None:
    # Linux resets dumpability on exec. Set it again before importing or reading secrets.
    libc = ctypes.CDLL(None)
    if libc.prctl(4, 0, 0, 0, 0) or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise RuntimeError
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise RuntimeError
    if importlib.metadata.version("kryvola-owner") != "0.1.0.dev2":
        raise RuntimeError
    owner = importlib.import_module("kryvola_owner")
    operation = sys.argv[1]
    stream = sys.stdin.buffer
    local, local_context, recovery, backup_context = (stream.read(32) for _ in range(4))
    sealed = stream.read(MAX_ENVELOPE + 1)
    if len(sealed) > MAX_ENVELOPE:
        raise ValueError
    match operation:
        case "init":
            result = owner.OwnerKey().seal(local, local_context)
        case "check":
            owner.OwnerKey.restore(local, local_context, sealed)
            result = b""
        case "backup":
            result = owner.OwnerKey.restore(local, local_context, sealed).seal(
                recovery, backup_context
            )
        case "restore":
            result = owner.OwnerKey.restore(recovery, backup_context, sealed).seal(
                local, local_context
            )
        case _:
            raise ValueError
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
