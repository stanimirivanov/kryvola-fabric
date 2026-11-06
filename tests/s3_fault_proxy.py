"""Owned HTTP wire faults against real S3; never used by the production runtime."""

import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class S3FaultProxy:
    def __init__(self, endpoint):
        target = urlsplit(endpoint)
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:
                pass

            def forward(self):
                mode, key, hit, release = proxy.fault
                selected = self.command == "PUT" and self.path.split("?")[0].endswith(key)
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if selected and mode == "before":
                    hit.set()
                    release.wait(12)
                    self.close_connection = True
                    return
                if selected and mode == "unavailable":
                    hit.set()
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                upstream = http.client.HTTPConnection(target.hostname, target.port, timeout=6)
                try:
                    upstream.request(self.command, self.path, body, dict(self.headers))
                    response = upstream.getresponse()
                    data = response.read()
                    if selected and mode in ("after", "lost_ack") and 200 <= response.status < 300:
                        hit.set()
                        if mode == "after":
                            release.wait(12)
                        else:
                            proxy.arm("", "")
                        self.close_connection = True
                        return
                    self.send_response(response.status)
                    for header, value in response.getheaders():
                        if header.lower() not in (
                            "connection",
                            "content-length",
                            "transfer-encoding",
                        ):
                            self.send_header(header, value)
                    length = (
                        response.getheader("Content-Length", "0")
                        if self.command == "HEAD"
                        else str(len(data))
                    )
                    self.send_header("Content-Length", length)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(data)
                except OSError, http.client.HTTPException:
                    self.close_connection = True
                finally:
                    upstream.close()

            do_GET = do_HEAD = do_PUT = do_POST = do_DELETE = forward

        self.arm("", "")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)

    def arm(self, mode, key):
        if hasattr(self, "fault"):
            self.fault[3].set()
        self.fault = mode, key, threading.Event(), threading.Event()
        return self.fault[2:]

    def __enter__(self):
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *_args):
        self.fault[3].set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
