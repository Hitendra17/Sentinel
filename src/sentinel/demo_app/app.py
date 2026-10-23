"""A deliberately modest local training HTTP fixture."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body=b'{"status":"ok"}'; self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        body=("<!doctype html><html><head><title>Sentinel Training Fixture</title></head><body><h1>Sentinel demo</h1><p>Local training fixture; no credentials or sensitive data.</p><a href='/health'>Health</a></body></html>").encode()
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("Set-Cookie","training=fixture; HttpOnly; SameSite=Lax"); self.end_headers(); self.wfile.write(body)
    def log_message(self, fmt, *args): pass

def main():
    print("Sentinel demo listening on http://127.0.0.1:8000 (training fixture)")
    HTTPServer(("127.0.0.1",8000),Handler).serve_forever()

if __name__ == "__main__": main()
