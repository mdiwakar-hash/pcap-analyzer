#!/usr/bin/env python3
"""PCAP Analyzer — local web server. Run: python3 server.py"""

import json
import os
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(__file__))
from analyzer import run_analysis
from analyzer.tshark_runner import get_tshark_version

HOST = "127.0.0.1"
PORT = 8000
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


def parse_multipart(body: bytes, content_type: str) -> dict:
    """Minimal multipart/form-data parser. Returns dict of {name: value_or_bytes}."""
    m = re.search(r'boundary=([^\s;]+)', content_type)
    if not m:
        return {}
    boundary = ('--' + m.group(1).strip('"')).encode()
    parts = body.split(boundary)
    result = {}
    for part in parts[1:]:
        if part in (b'--\r\n', b'--', b'--\r\n--'):
            continue
        if part.startswith(b'--'):
            continue
        # Strip leading CRLF
        if part.startswith(b'\r\n'):
            part = part[2:]
        # Split headers from body at first blank line
        if b'\r\n\r\n' not in part:
            continue
        header_block, _, content = part.partition(b'\r\n\r\n')
        # Strip trailing CRLF
        if content.endswith(b'\r\n'):
            content = content[:-2]
        headers = {}
        for line in header_block.decode('utf-8', errors='replace').splitlines():
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()
        disp = headers.get('content-disposition', '')
        name_m = re.search(r'name="([^"]+)"', disp)
        file_m = re.search(r'filename="([^"]*)"', disp)
        if not name_m:
            continue
        name = name_m.group(1)
        if file_m:
            result[name] = {'filename': file_m.group(1), 'data': content}
        else:
            result[name] = content.decode('utf-8', errors='replace')
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
        elif self.path == "/api/health":
            self._json({"status": "ok", "tshark": get_tshark_version()})
        else:
            self._error(404, "Not found")

    def do_POST(self):
        if self.path == "/api/analyze":
            self._handle_analyze()
        else:
            self._error(404, "Not found")

    def _handle_analyze(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_UPLOAD_BYTES:
            self._error(413, f"Upload too large (max {MAX_UPLOAD_BYTES // 1024 // 1024} MB)")
            return

        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(content_length)
        form = parse_multipart(body, content_type)

        if "pcap_file" not in form or not isinstance(form["pcap_file"], dict):
            self._error(400, "Missing pcap_file field")
            return

        pcap_field = form["pcap_file"]
        filename = pcap_field.get("filename", "upload.pcap")
        if not filename:
            self._error(400, "No file selected")
            return

        tmp_name = f"{uuid.uuid4()}.pcap"
        tmp_path = os.path.join(UPLOAD_DIR, tmp_name)
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        def _str(key):
            v = form.get(key, "")
            return v.strip() if isinstance(v, str) else ""

        try:
            with open(tmp_path, "wb") as f:
                f.write(pcap_field["data"])

            filters = {
                "endpoint_ip": _str("endpoint_ip"),
                "src_ip": _str("src_ip"),
                "dst_ip": _str("dst_ip"),
                "port": _str("port"),
                "protocol": _str("protocol"),
            }

            report = run_analysis(tmp_path, filters)
            report["pcap_filename"] = filename
            self._json(report)

        except Exception as exc:
            self._json({"error": str(exc)}, status=500)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _serve_file(self, path: str, content_type: str):
        try:
            with open(path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self._error(404, f"File not found: {path}")

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str):
        self._json({"error": message}, status=status)


def main():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    server = HTTPServer((HOST, PORT), Handler)
    print(f"PCAP Analyzer running at http://{HOST}:{PORT}")
    print(f"tshark: {get_tshark_version()}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
