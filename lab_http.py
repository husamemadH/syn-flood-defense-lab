"""A loopback-only HTTP service used by both demonstration modes."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


@contextmanager
def service(decide, port=0):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                decision = decide()
                status = 200 if decision == "served" else 503
                body = f"{decision}\n".encode()
            else:
                status = 404
                body = b"Unknown endpoint\n"
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    with HTTPServer(("127.0.0.1", port), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join()
