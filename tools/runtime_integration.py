"""Exercise the Fabric fixture boundary with real PostgreSQL and S3 services."""

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

POSTGRES = "postgres@sha256:0b81cec82228160abfa753aeaad0609b709eb26eeb950f2e404ad2326e1cc370"
SEAWEED = (
    "chrislusf/seaweedfs@sha256:3a522c379599e163433a636e75022630848b63a74f08ea37bf06f8d776e9a707"
)
AWS = "amazon/aws-cli@sha256:0c240be22c3ce600499ec36429bbdd758c86b10ac3e34f2c6e17698816b5f04a"
Invoke = Callable[..., subprocess.CompletedProcess[str]]


def docker(*args: str, env: dict[str, str] | None = None, timeout: int = 30):
    return subprocess.run(
        ["docker", *args],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


def require(result: subprocess.CompletedProcess[str], label: str) -> str:
    if result.returncode:
        # Compose and client errors may include credentials or endpoint details.
        raise RuntimeError(f"{label} failed (exit {result.returncode})")
    return result.stdout


def fixture(folder: Path) -> tuple[Path, dict[str, str]]:
    access, secret = secrets.token_hex(12), secrets.token_hex(24)
    config = folder / "s3.json"
    config.write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "name": "fabric-fixture",
                        "credentials": [{"accessKey": access, "secretKey": secret}],
                        "actions": ["Admin", "Read", "Write", "List"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config.chmod(0o600)
    client_env = {
        "AWS_ACCESS_KEY_ID": access,
        "AWS_SECRET_ACCESS_KEY": secret,
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_REQUEST_CHECKSUM_CALCULATION": "when_required",
        "AWS_RESPONSE_CHECKSUM_VALIDATION": "when_required",
        "AWS_MAX_ATTEMPTS": "1",
    }
    # The socket directory is writable by the container UID. Its private
    # temporary parent blocks access by other host users.
    socket = folder / "postgres-socket"
    socket.mkdir()
    socket.chmod(0o777)
    compose = folder / "compose.json"
    compose.write_text(
        json.dumps(
            {
                "networks": {"default": {"internal": True}, "host-probe": {}},
                "services": {
                    "postgres": {
                        "image": POSTGRES,
                        "command": [
                            "postgres",
                            "-c",
                            "unix_socket_directories=/var/run/postgresql,/fixture-socket",
                        ],
                        "volumes": [f"{socket}:/fixture-socket"],
                        "environment": {"POSTGRES_PASSWORD": "${FIXTURE_PG_PASSWORD:?required}"},
                        "healthcheck": {
                            "test": ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                            "interval": "1s",
                            "timeout": "2s",
                            "retries": 60,
                        },
                    },
                    "s3": {
                        "image": SEAWEED,
                        "ports": ["127.0.0.1::8333"],
                        "networks": ["default", "host-probe"],
                        "entrypoint": ["/bin/sh", "-ec"],
                        "command": [
                            "cp /fixture.json /data/fixture-s3.json; "
                            "chown 1000:1000 /data/fixture-s3.json; "
                            "chmod 600 /data/fixture-s3.json; "
                            "exec /entrypoint.sh server -dir=/data -ip=s3 -ip.bind=0.0.0.0 "
                            "-filer -s3 -s3.config=/data/fixture-s3.json "
                            "-volume.max=2 -master.volumeSizeLimitMB=32"
                        ],
                        "volumes": [f"{config}:/fixture.json:ro"],
                    },
                    "s3-client": {
                        "image": AWS,
                        "entrypoint": ["sleep", "infinity"],
                        "environment": dict.fromkeys(client_env),
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return compose, {**os.environ, **client_env, "FIXTURE_PG_PASSWORD": secrets.token_hex(24)}


def check_postgres(invoke: Invoke) -> None:
    sql = (
        "CREATE TEMP TABLE fixture (id integer PRIMARY KEY); "
        "BEGIN; INSERT INTO fixture VALUES (1); COMMIT; "
        "BEGIN; INSERT INTO fixture VALUES (2); ROLLBACK; "
        "SELECT id FROM fixture ORDER BY id;"
    )
    result = invoke(
        "exec",
        "-T",
        "postgres",
        "sh",
        "-ec",
        'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -h 127.0.0.1 -U postgres -XqtA '
        '-v ON_ERROR_STOP=1 -c "$1"',
        "fixture",
        sql,
    )
    if require(result, "PostgreSQL transaction probe").strip() != "1":
        raise RuntimeError("PostgreSQL did not preserve commit and rollback semantics")


def check_s3(invoke: Invoke) -> None:
    def s3(*args: str, read_timeout: int = 20):
        return invoke(
            "exec",
            "-T",
            "s3-client",
            "aws",
            "--endpoint-url",
            "http://s3:8333",
            "--cli-connect-timeout",
            "2",
            "--cli-read-timeout",
            str(read_timeout),
            "s3api",
            *args,
            "--bucket",
            "fabric-runtime",
            timeout=read_timeout + 7,
        )

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if s3("create-bucket", read_timeout=3).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("S3 fixture did not become ready")

    require(
        invoke(
            "exec",
            "-T",
            "s3-client",
            "sh",
            "-ec",
            "printf original > /tmp/original; printf replacement > /tmp/replacement",
        ),
        "S3 test input setup",
    )
    condition = ("--key", "immutable", "--if-none-match", "*")
    require(s3("put-object", *condition, "--body", "/tmp/original"), "S3 conditional create")
    duplicate = s3("put-object", *condition, "--body", "/tmp/replacement")
    if not duplicate.returncode or "PreconditionFailed" not in duplicate.stderr:
        raise RuntimeError("S3 did not reject the conditional overwrite")
    require(s3("get-object", "--key", "immutable", "/tmp/result"), "S3 read")
    result = invoke("exec", "-T", "s3-client", "cat", "/tmp/result")
    if require(result, "S3 byte comparison") != "original":
        raise RuntimeError("S3 conditional overwrite changed the stored bytes")


def check_registry(folder: Path, test: str, **settings: str) -> None:
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "FABRIC_FIXTURE_PG_SOCKET": str(folder / "postgres-socket"), **settings}
    result = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "kryvola-fabric-core",
            "--test",
            "registry",
            "--",
            "--ignored",
            "--exact",
            test,
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    output = require(result, f"Registry probe {test}")
    if "1 passed; 0 failed" not in output:
        raise RuntimeError(f"Registry probe {test} did not run")


def run(folder: Path) -> None:
    host = os.environ.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        raise RuntimeError("The live gate requires local Docker")
    endpoint = require(
        docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}"),
        "Docker context inspection",
    )
    if not endpoint.strip().startswith("unix://"):
        raise RuntimeError("The live gate requires local Docker")

    compose, env = fixture(folder)
    project = f"fabric-runtime-{secrets.token_hex(8)}"

    def invoke(*args: str, timeout: int = 30):
        return docker("compose", "-p", project, "-f", str(compose), *args, env=env, timeout=timeout)

    try:
        require(invoke("up", "-d", "--wait", "--wait-timeout=90", timeout=600), "Fixture startup")
        check_postgres(invoke)
        check_registry(folder, "durable_registry")
        require(invoke("restart", "postgres", timeout=90), "PostgreSQL restart")
        require(
            invoke("up", "-d", "--wait", "--wait-timeout=90", timeout=120),
            "Fixture restart readiness",
        )
        check_registry(folder, "registry_survives_postgres_restart")
        check_s3(invoke)
        endpoint = require(invoke("port", "s3", "8333"), "S3 loopback endpoint").strip()
        host, _, port = endpoint.rpartition(":")
        if host != "127.0.0.1" or not port.isascii() or not port.isdecimal():
            raise RuntimeError("S3 fixture endpoint must be loopback")
        check_registry(
            folder,
            "bounded_uploads",
            FABRIC_FIXTURE_S3_ENDPOINT=f"http://{endpoint}",
            AWS_ACCESS_KEY_ID=env["AWS_ACCESS_KEY_ID"],
            AWS_SECRET_ACCESS_KEY=env["AWS_SECRET_ACCESS_KEY"],
        )
    finally:
        require(
            invoke("down", "--volumes", "--remove-orphans", timeout=90),
            f"Cleanup of {project}",
        )


def interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["ci"])
    parser.parse_args()
    signal.signal(signal.SIGTERM, interrupt)
    try:
        with tempfile.TemporaryDirectory(prefix="fabric-runtime-") as folder:
            run(Path(folder))
    except RuntimeError as error:
        print(f"Runtime integration: {error}", file=sys.stderr)
        return 1
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f"Runtime integration: {type(error).__name__}", file=sys.stderr)
        return 1
    print("Runtime integration passed: PostgreSQL registry and S3 conditional writes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
