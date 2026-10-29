"""Reference-only adapter; structural validity grants no execution rights."""

import hashlib
import json
import subprocess
from tempfile import TemporaryFile

from kryvola_fabric.control import decode_control


def descriptor(payload: bytes) -> dict[str, str]:
    value = decode_control("ExecuteRequest", payload, temporal=True)
    return {
        "intent_digest": hashlib.sha256(payload).hexdigest(),
        "execution_id": value["execution"]["execution_id"],
    }


def execute(container: str, payload: bytes) -> str:
    """Fixed command, bounded output, no backend diagnostic in raised exceptions."""
    intent = descriptor(payload)
    answer = b""
    failed = False
    with TemporaryFile() as output:
        try:
            subprocess.run(
                ["docker", "exec", "-i", container, "python", "/fixture/ray_task.py"],
                input=json.dumps(intent).encode(),
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=45,
                check=True,
            )
            output.seek(0)
            answer = output.read(66)
        except OSError, subprocess.SubprocessError:
            failed = True
    # Raise outside the except suite: SDK failure conversion must see no hidden cause/context.
    if failed or answer != (intent["intent_digest"] + "\n").encode():
        raise ValueError("FIXTURE_COMPUTE_FAILED")
    return intent["intent_digest"]
