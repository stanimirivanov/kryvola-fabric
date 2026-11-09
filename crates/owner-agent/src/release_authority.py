"""Fetch only the authorized manifest using the owner's workload credential."""

import http.client
import ssl
import sys

LIMIT = 65536


def main():
    host, port, peer, certificate, key, ca = sys.argv[1:]
    token = sys.stdin.buffer.read(64).decode("ascii")
    body = sys.stdin.buffer.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError
    tls = ssl.create_default_context(cafile=ca)
    # Fabric workload certificates identify the server by URI SAN.
    tls.check_hostname = False
    tls.load_cert_chain(certificate, key)
    connection = http.client.HTTPSConnection(host, int(port), context=tls, timeout=5)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert() if connection.sock else None
        names = certificate.get("subjectAltName", ()) if certificate else ()
        if not isinstance(names, tuple) or [item for item in names if item[0] == "URI"] != [
            ("URI", peer)
        ]:
            raise ValueError
        connection.request(
            "POST",
            "/v1/released-outputs/manifest",
            body,
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        length = int(response.getheader("Content-Length", "0"))
        if response.status != 200 or not 1 <= length <= LIMIT or response.chunked:
            raise ValueError
        raw = response.read(LIMIT + 1)
        if len(raw) != length:
            raise ValueError
        sys.stdout.buffer.write(raw)
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
