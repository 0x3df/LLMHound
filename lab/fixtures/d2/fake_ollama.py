import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send_json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        r = {
            "/api/version": {"version": "0.5.7"},
            "/api/tags": {
                "models": [
                    {
                        "name": "llama3:latest",
                        "model": "llama3:latest",
                        "digest": "sha256:aaaa",
                        "size": 123,
                        "details": {"family": "llama"},
                    }
                ]
            },
            "/api/ps": {"models": []},
        }.get(self.path)
        if r is None:
            self.send_response(404)
            self.end_headers()
            return
        self._send_json(r)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(length)
        if self.path != "/api/show":
            self.send_response(404)
            self.end_headers()
            return
        self._send_json(
            {
                "details": {"parent_model": "llama3:8b", "family": "llama"},
                "license": "LLAMA 3 COMMUNITY LICENSE",
                "modelfile": "FROM llama3:8b\nSYSTEM Lab fixture assistant.\n",
                "template": "{{ .System }}\n{{ .Prompt }}",
                "system": "Lab fixture assistant.",
                "parameters": "temperature 0.2\n",
            }
        )


srv = HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
if len(sys.argv) > 2:
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write(str(srv.server_port))
srv.serve_forever()
