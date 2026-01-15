#!/usr/bin/env python3
"""
Chunked file transfer server for E2E testing.

Runs alongside the buckwild daemon on each node.

Endpoints:
- POST /upload - store file locally, returns {filename, sha256}
- POST /transfer?target=<node> - receive file and forward to target node via buckwild
- GET /file/<filename> - get file info
- GET /health - server health

When transferring to another node, the routing table directs traffic through
the TUN interface, forcing it through the buckwild protocol.
"""

import hashlib
import http.client
import json
import os
import socket
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

STORAGE_DIR = "/tmp/buckwild/files"
FILE_SERVER_PORT = 8081

# Node IP mapping (must match docker-compose network config)
NODE_IPS = {
    "node-a": "172.30.0.10",
    "node-b": "172.30.0.11",
    "node-c": "172.30.0.12",
    "node-d": "172.30.0.13",
    "node-e": "172.30.0.14",
}

# TUN IP mapping (virtual IPs routed through buckwild)
TUN_IPS = {
    "node-a": "10.0.0.1",
    "node-b": "10.0.0.2",
    "node-c": "10.0.0.3",
    "node-d": "10.0.0.4",
    "node-e": "10.0.0.5",
}


def get_node_id() -> str:
    """Get this node's ID from hostname or environment."""
    node_id = os.environ.get("NODE_ID")
    if node_id:
        return node_id
    hostname = socket.gethostname()
    if hostname in NODE_IPS:
        return hostname
    return "unknown"


class ChunkedFileHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/upload":
            self._handle_upload()
        elif parsed.path == "/transfer":
            self._handle_transfer(parsed)
        else:
            self.send_error(404, "Not Found")

    def _handle_upload(self):
        """Store file locally and return filename + SHA256."""
        result = self._receive_file()
        if result is None:
            return

        filename, filepath, sha256_hex, total_bytes = result

        response_data = {
            "filename": filename,
            "filepath": filepath,
            "sha256": sha256_hex,
            "size_bytes": total_bytes,
        }
        self._send_json_response(200, response_data)

    def _handle_transfer(self, parsed):
        """Receive file and forward to target node via TUN/buckwild."""
        params = parse_qs(parsed.query)
        target_node = params.get("target", [None])[0]

        if not target_node:
            self.send_error(400, "Missing target parameter")
            return

        if target_node not in TUN_IPS:
            self.send_error(400, f"Unknown target node: {target_node}")
            return

        # Receive the file first
        result = self._receive_file()
        if result is None:
            return

        filename, filepath, sha256_hex, total_bytes = result

        # Forward to target node via TUN IP (routed through buckwild)
        target_ip = TUN_IPS[target_node]

        try:
            with open(filepath, "rb") as f:
                file_data = f.read()

            # Send to target node's file server via TUN
            forward_result = self._forward_to_node(target_ip, file_data)

            response_data = {
                "source_node": get_node_id(),
                "target_node": target_node,
                "local_filename": filename,
                "local_sha256": sha256_hex,
                "size_bytes": total_bytes,
                "remote_filename": forward_result.get("filename"),
                "remote_sha256": forward_result.get("sha256"),
                "transfer_success": forward_result.get("sha256") == sha256_hex,
            }
            self._send_json_response(200, response_data)

        except Exception as e:
            self.send_error(500, f"Transfer failed: {e}")

    def _receive_file(self):
        """
        Receive file from request body (chunked or content-length).
        Returns (filename, filepath, sha256_hex, total_bytes) or None on error.
        """
        unique_id = uuid.uuid4().hex[:16]
        filename = f"transfer_{unique_id}.bin"
        filepath = os.path.join(STORAGE_DIR, filename)

        os.makedirs(STORAGE_DIR, exist_ok=True)

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        content_length = self.headers.get("Content-Length")

        sha256 = hashlib.sha256()
        total_bytes = 0

        try:
            with open(filepath, "wb") as f:
                if transfer_encoding == "chunked":
                    while True:
                        size_line = self.rfile.readline().decode().strip()
                        if not size_line:
                            continue
                        chunk_size = int(size_line, 16)
                        if chunk_size == 0:
                            self.rfile.readline()
                            break

                        chunk = self.rfile.read(chunk_size)
                        f.write(chunk)
                        sha256.update(chunk)
                        total_bytes += len(chunk)
                        self.rfile.readline()

                elif content_length:
                    remaining = int(content_length)
                    while remaining > 0:
                        chunk_size = min(remaining, 65536)
                        chunk = self.rfile.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        sha256.update(chunk)
                        total_bytes += len(chunk)
                        remaining -= len(chunk)
                else:
                    self.send_error(400, "Missing Content-Length or Transfer-Encoding")
                    return None

        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            self.send_error(500, f"Write error: {e}")
            return None

        return filename, filepath, sha256.hexdigest(), total_bytes

    def _forward_to_node(self, target_ip: str, data: bytes) -> dict:
        """Forward file data to target node via TUN IP."""
        conn = http.client.HTTPConnection(target_ip, FILE_SERVER_PORT, timeout=120)

        try:
            conn.putrequest("POST", "/upload")
            conn.putheader("Transfer-Encoding", "chunked")
            conn.putheader("Content-Type", "application/octet-stream")
            conn.endheaders()

            # Send in chunks
            chunk_size = 8192
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + chunk_size]
                chunk_header = f"{len(chunk):x}\r\n".encode()
                conn.send(chunk_header)
                conn.send(chunk)
                conn.send(b"\r\n")
                offset += len(chunk)

            conn.send(b"0\r\n\r\n")

            response = conn.getresponse()
            if response.status != 200:
                raise RuntimeError(f"Target returned {response.status}: {response.reason}")

            body = response.read().decode()
            return json.loads(body)

        finally:
            conn.close()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._handle_health()
        elif parsed.path.startswith("/file/"):
            filename = parsed.path[6:]
            self._handle_file_info(filename)
        else:
            self.send_error(404, "Not Found")

    def _handle_health(self):
        """Return server health status."""
        response_data = {
            "status": "healthy",
            "node_id": get_node_id(),
            "storage_dir": STORAGE_DIR,
        }
        self._send_json_response(200, response_data)

    def _handle_file_info(self, filename: str):
        """Return info about a stored file."""
        filename = os.path.basename(filename)
        filepath = os.path.join(STORAGE_DIR, filename)

        if not os.path.exists(filepath):
            self.send_error(404, "File not found")
            return

        sha256 = hashlib.sha256()
        size = 0
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                size += len(chunk)

        response_data = {
            "filename": filename,
            "filepath": filepath,
            "sha256": sha256.hexdigest(),
            "size_bytes": size,
        }
        self._send_json_response(200, response_data)

    def _send_json_response(self, status: int, data: dict):
        """Send JSON response."""
        response = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        import datetime
        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] {args[0]}")


def main():
    port = int(os.environ.get("FILE_SERVER_PORT", str(FILE_SERVER_PORT)))
    server = HTTPServer(("0.0.0.0", port), ChunkedFileHandler)
    print(f"Chunked file server listening on port {port}")
    print(f"Node ID: {get_node_id()}")
    print(f"Storage directory: {STORAGE_DIR}")
    server.serve_forever()


if __name__ == "__main__":
    main()
