"""Fixed public task, run only inside the isolated pinned Ray fixture image."""

import json
import re
import sys


def main() -> None:
    import ray  # ty: ignore[unresolved-import] - supplied by the pinned fixture image only

    raw = sys.stdin.buffer.read(1025)
    intent = json.loads(raw)
    if (
        len(raw) > 1024
        or not isinstance(intent, dict)
        or set(intent) != {"intent_digest", "execution_id"}
        or not isinstance(intent["intent_digest"], str)
        or not re.fullmatch("[0-9a-f]{64}", intent["intent_digest"])
        or not isinstance(intent["execution_id"], str)
        or not 1 <= len(intent["execution_id"]) <= 128
    ):
        raise ValueError("INVALID_FIXTURE_TASK")

    ray.init(
        _node_ip_address="127.0.0.1",
        num_cpus=1,
        include_dashboard=False,
        object_store_memory=80 * 1024 * 1024,
        log_to_driver=False,
        logging_level="ERROR",
    )
    try:
        # Only this deployed function is serialized internally by Ray. No caller supplies code.
        @ray.remote(num_cpus=1, max_retries=0)
        def observe(value):
            return value["intent_digest"]

        print(ray.get(observe.remote(intent), timeout=20))
    finally:
        ray.shutdown()


if __name__ == "__main__":
    main()
