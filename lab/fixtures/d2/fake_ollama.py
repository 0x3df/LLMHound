import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        r={"/api/version":{"version":"0.5.7"},
           "/api/tags":{"models":[{"name":"llama3:latest","model":"llama3:latest","digest":"sha256:aaaa","size":123,"details":{"family":"llama"}}]},
           "/api/ps":{"models":[]}}.get(self.path)
        if r is None: self.send_response(404); self.end_headers(); return
        b=json.dumps(r).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
HTTPServer(("127.0.0.1",int(sys.argv[1])),H).serve_forever()
