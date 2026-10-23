import json
from http.server import BaseHTTPRequestHandler,HTTPServer
from threading import Thread
from sentinel.cli import main

class Demo(BaseHTTPRequestHandler):
    def do_GET(self):
        body=b"<title>training</title>"; self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass

def test_complete_local_scan(tmp_path):
    server=HTTPServer(("127.0.0.1",0),Demo); t=Thread(target=server.serve_forever,daemon=True); t.start()
    try:
        scope=tmp_path/"scope.json"; scope.write_text(json.dumps({"origins":[f"http://127.0.0.1:{server.server_port}"],"allow_private":True}))
        assert main(["scan",f"http://127.0.0.1:{server.server_port}","--scope",str(scope),"--output",str(tmp_path/"out")])==0
        assert (tmp_path/"out/report.md").exists()
        data=json.loads((tmp_path/"out/report.json").read_text()); assert data["mode"]=="deterministic" and data["evidence"]
    finally: server.shutdown(); t.join()
