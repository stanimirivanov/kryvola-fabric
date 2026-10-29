# Temporal-to-Ray conformance fixture (M0-PR30)

This opt-in fixture runs a fixed Ray task through a Temporal activity and replays
actual success and failure histories. It consumes the existing public generated
ExecuteRequest wire vector (1,020 bytes), validates it before dispatch, and sends
only its SHA-256 intent digest and execution ID into Ray. References are synthetic;
no artifact is fetched. A digest is correlation metadata, not authorization.

Temporal owns logical intent and activity completion. Ray echoes the digest;
physical work is repeated in a fresh runtime, demonstrating replaceable compute.
Duplicate and stale observations update bounded diagnostic counters only. They
cannot select results, change intent or authorize disclosure. Both activity and
Ray retries are disabled. Physical attempt fences, registry transactions,
cancellation recovery, effect deduplication and authorized output commits remain
M1 work. This fixture is not durable private inference.

## Gates

Install with `uv sync --locked --extra conformance`. Offline checks start no services:

```sh
uv run --locked --extra conformance python -m unittest discover -s tests -v
uv run --locked --extra conformance python tools/verify.py fast
```

Full checks require a trusted Linux x86_64 Docker host. The installer writes only
under ignored `build/temporal`:

```sh
uv run --locked --extra conformance python tools/install_temporal.py
uv run --locked --extra conformance python tools/verify.py full
```

Standalone service check:

```sh
uv run --locked --extra conformance python -m kryvola_fabric.conformance smoke --temporal-cli build/temporal/temporal
```

The SDK owns a loopback-only ephemeral Temporal dev server. The runner owns a
uniquely named, digest-pinned Ray container: no network or published ports,
read-only root, bounded memory/CPU/PIDs and tmpfs, and only its fixed read-only
task script mounted. The runner removes it in `finally`; the SDK stops Temporal.
Its home is inside tmpfs, including Ray's self-generated ephemeral local auth token;
no host credentials are supplied and the token is never printed or uploaded.
Remote Docker contexts are refused. Host Docker access is a trusted test harness
privilege, not a production bridge design. No socket, credentials, keys or user
closures enter Ray. A killed runner can leave its named fixture container behind;
CI uses disposable runners.

Live checks cover real execution, repeated physical work, two duplicate and one
stale observation, backend failure and replay of both terminal histories. Offline
checks cover malformed/unknown/oversized metadata before dispatch, bounded replies
and counters, and sanitized exception chains. Backend errors become fixed
non-retryable application failures outside their caught exception context.
The wheel check validates the packaged public vector in isolation.

## Prior art and dependency scope

- [Temporal Python SDK](https://github.com/temporalio/sdk-python) 1.35.0 (MIT):
  optional dependency and activity wrapper; native Worker/Replayer APIs provide
  workflow execution and history replay rather than a custom state machine.
- [Ray tasks](https://docs.ray.io/en/latest/ray-core/tasks.html) 2.59.0 (Apache-2.0):
  fixed task in the same immutable image as the platform fixture. No Ray package
  is added to the Python 3.14 control environment. The image's Python 3.12 receives
  bounded JSON, never caller-supplied executable code.
- [Temporal CLI](https://github.com/temporalio/cli/releases/tag/v1.9.1) 1.9.1 (MIT):
  checksum-pinned upstream test executable, not an application dependency.

The SDK adds locked Nexus/type support dependencies. Protobuf stubs require narrow
adaptations for existing dynamic-message typing; generated schema/wire bytes stay
unchanged. No cryptographic integrity, production security or availability claim
is established by this fixture.
