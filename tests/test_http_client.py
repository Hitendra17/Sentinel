import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from sentinel.scope import Scope
from sentinel.http_client import BoundedClient

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/redirect": self.send_response(302); self.send_header("Location","http://127.0.0.1:1/"); self.end_headers(); return
        body=b"x"*2048; self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass

def test_redirect_block_and_response_limit():
    server=HTTPServer(("127.0.0.1",0),H); thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        port=server.server_port; s=Scope([f"http://127.0.0.1:{port}"],True,max_response_bytes=1024)
        assert "blocked out-of-scope" in BoundedClient(s).request(f"http://127.0.0.1:{port}/redirect").error
        assert "size limit" in BoundedClient(s).request(f"http://127.0.0.1:{port}/").error
    finally: server.shutdown(); thread.join()


def test_method_is_case_insensitive_and_query_is_not_recorded():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args): pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        response = BoundedClient(Scope([f"http://127.0.0.1:{port}"], True)).request(
            f"http://127.0.0.1:{port}/check?token=secret", method="get"
        )
        assert response.error is None
        assert response.url == f"http://127.0.0.1:{port}/check"
        assert b"secret" not in response.body
    finally:
        server.shutdown()
        thread.join()
