"""Real local SPIRE fixture. UID selectors and insecure bootstrap are test-only."""

import json
import os
import socket
import subprocess
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def spire(folder: Path, domain: str = "fabric.test", ttl: int = 10):
    folder.mkdir()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server_socket = folder / "server.sock"
    agent_socket = folder / "agent.sock"
    (folder / "server.conf").write_text(f'''
server {{
 bind_address = "127.0.0.1"
 bind_port = {port}
 trust_domain = "{domain}"
 data_dir = "{folder}/server"
 socket_path = "{server_socket}"
 log_level = "ERROR"
}}
plugins {{
 DataStore "sql" {{ plugin_data {{ database_type = "sqlite3" connection_string = "{folder}/db" }} }}
 KeyManager "disk" {{ plugin_data {{ keys_path = "{folder}/keys.json" }} }}
 NodeAttestor "join_token" {{ plugin_data {{}} }}
}}
''')
    (folder / "agent.conf").write_text(f'''
agent {{
 data_dir = "{folder}/agent"
 log_level = "ERROR"
 trust_domain = "{domain}"
 server_address = "127.0.0.1"
 server_port = {port}
 socket_path = "{agent_socket}"
 insecure_bootstrap = true
}}
plugins {{
 KeyManager "memory" {{ plugin_data {{}} }}
 NodeAttestor "join_token" {{ plugin_data {{}} }}
 WorkloadAttestor "unix" {{ plugin_data {{}} }}
}}
''')

    def command(binary, *args):
        return subprocess.run(
            [str(ROOT / "build/spire" / binary), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout

    with ExitStack() as stack:

        def start(binary, *args):
            log = stack.enter_context((folder / f"{binary}.log").open("w+"))
            process = subprocess.Popen(
                [str(ROOT / "build/spire" / binary), *args],
                stdout=log,
                stderr=log,
            )

            def stop():
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

            stack.callback(stop)
            return process

        def ready(path, process):
            deadline = time.monotonic() + 20
            while not path.exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("SPIRE fixture failed to start")
                time.sleep(0.05)

        server = start("spire-server", "run", "-config", str(folder / "server.conf"))
        ready(server_socket, server)
        parent = f"spiffe://{domain}/agent"
        token = json.loads(
            command(
                "spire-server",
                "token",
                "generate",
                "-socketPath",
                str(server_socket),
                "-spiffeID",
                parent,
                "-output",
                "json",
            )
        )["value"]
        for name in ("runtime", "worker", "other", "long", "coordinator"):
            command(
                "spire-server",
                "entry",
                "create",
                "-socketPath",
                str(server_socket),
                "-parentID",
                parent,
                "-spiffeID",
                f"spiffe://{domain}/{name}",
                "-selector",
                f"unix:uid:{os.getuid()}",
                "-x509SVIDTTL",
                "120" if name == "long" else str(ttl),
            )
        agent = start(
            "spire-agent", "run", "-config", str(folder / "agent.conf"), "-joinToken", token
        )
        ready(agent_socket, agent)

        def fetch():
            deadline = time.monotonic() + 20
            while True:
                try:
                    return json.loads(
                        command(
                            "spire-agent",
                            "api",
                            "fetch",
                            "x509",
                            "-socketPath",
                            str(agent_socket),
                            "-output",
                            "json",
                        )
                    )
                except subprocess.CalledProcessError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("SPIRE Workload API did not supply identities") from None
                    time.sleep(0.1)

        yield agent_socket, fetch, agent
