"""FastAPI file transfer server for e2e testing.

This server runs on each node in the e2e test environment and provides:
- Basic endpoints: /upload, /download, /health
- Trigger endpoints: /trigger-upload, /trigger-download for node-to-node transfers
- Protocol endpoints: /ws/stream, /sse/stream, /h2/multiplex for multi-protocol testing
"""

import hashlib
import os
import socket
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.responses import StreamingResponse

from server.h2 import router as h2_router
from server.h2 import trigger_h2_multiplex_test
from server.models import (
    H2MultiplexResponse,
    HealthResponse,
    MTLSResponse,
    SSEResponse,
    TransferResponse,
    TriggerDownloadRequest,
    TriggerH2MultiplexRequest,
    TriggerHTTPSRequest,
    TriggerMTLSRequest,
    TriggerSSERequest,
    TriggerUploadRequest,
    TriggerWebSocketRequest,
    UploadResponse,
    WebSocketResponse,
)
from server.sse import router as sse_router
from server.sse import trigger_sse_test
from server.websocket import router as websocket_router
from server.websocket import trigger_websocket_test

# Configuration
FILE_SERVER_PORT = 8081
CHUNK_SIZE = 8192

# TUN IP for this node (set by environment or detected)
TUN_IP: str | None = None


def get_tun_ip() -> str | None:
    """Get this node's TUN IP address."""
    global TUN_IP
    if TUN_IP is not None:
        return TUN_IP

    # Try environment variable first
    TUN_IP = os.environ.get("TUN_IP")
    if TUN_IP:
        return TUN_IP

    # Try to detect from network interfaces
    try:
        import subprocess

        result = subprocess.run(
            ["ip", "addr", "show", "bw0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "inet " in line:
                    TUN_IP = line.strip().split()[1].split("/")[0]
                    return TUN_IP
    except Exception:
        pass

    return None


def get_node_id() -> str:
    """Get this node's identifier."""
    node_id = os.environ.get("NODE_ID")
    if node_id:
        return node_id
    return socket.gethostname()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    tun_ip = get_tun_ip()
    node_id = get_node_id()
    print(f"File transfer server starting on node {node_id} (TUN IP: {tun_ip})")
    yield
    # Shutdown
    print("File transfer server shutting down")


app = FastAPI(
    title="Buckwild E2E File Transfer Server",
    description="Handles file transfers for e2e testing through the VPN tunnel",
    version="0.1.0",
    lifespan=lifespan,
)

# Include protocol routers
app.include_router(websocket_router)
app.include_router(sse_router)
app.include_router(h2_router)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        node_id=get_node_id(),
        tun_ip=get_tun_ip(),
    )


@app.post("/upload", response_model=UploadResponse)
async def upload(request: Request):
    """Receive uploaded data and return SHA256 hash.

    Accepts both chunked transfer encoding and content-length bodies.
    """
    sha256 = hashlib.sha256()
    size = 0

    async for chunk in request.stream():
        sha256.update(chunk)
        size += len(chunk)

    return UploadResponse(
        sha256=sha256.hexdigest(),
        size_bytes=size,
    )


@app.get("/download")
async def download(size: int = Query(..., ge=1024, le=10 * 1024 * 1024)):
    """Generate and stream random data with SHA256 in header.

    Args:
        size: Number of bytes to generate (1KB-10MB)
    """
    # Generate random data
    data = os.urandom(size)
    sha256 = hashlib.sha256(data).hexdigest()

    def generate():
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + CHUNK_SIZE]
            yield chunk
            offset += len(chunk)

    return StreamingResponse(
        generate(),
        media_type="application/octet-stream",
        headers={
            "X-Content-SHA256": sha256,
            "X-Content-Size": str(size),
        },
    )


@app.post("/trigger-upload", response_model=TransferResponse)
async def trigger_upload(req: TriggerUploadRequest):
    """Trigger an upload to another node via TUN.

    1. Generate random data of specified size
    2. Compute SHA256
    3. POST to target's /upload endpoint via TUN IP
    4. Return both SHA256 values for verification
    """
    start_ms = time.monotonic() * 1000

    # Generate random data
    data = os.urandom(req.size)
    source_sha256 = hashlib.sha256(data).hexdigest()

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"http://{req.target}:{FILE_SERVER_PORT}/upload",
                content=data,
                headers={"Content-Type": "application/octet-stream"},
            )
            response.raise_for_status()
            result = response.json()

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return TransferResponse(
            success=True,
            source_sha256=source_sha256,
            target_sha256=result["sha256"],
            size_bytes=req.size,
            duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return TransferResponse(
            success=False,
            source_sha256=source_sha256,
            target_sha256="",
            size_bytes=req.size,
            duration_ms=duration_ms,
            error=str(e),
        )


@app.post("/trigger-download", response_model=TransferResponse)
async def trigger_download(req: TriggerDownloadRequest):
    """Trigger a download from another node via TUN.

    1. GET from target's /download endpoint via TUN IP
    2. Receive data and X-Content-SHA256 header
    3. Compute SHA256 of received data
    4. Return both for verification
    """
    start_ms = time.monotonic() * 1000

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.get(
                f"http://{req.target}:{FILE_SERVER_PORT}/download",
                params={"size": req.size},
            )
            response.raise_for_status()

            # Get the SHA256 from header (what server says it sent)
            source_sha256 = response.headers.get("X-Content-SHA256", "")

            # Compute SHA256 of what we received
            data = response.content
            computed_sha256 = hashlib.sha256(data).hexdigest()

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return TransferResponse(
            success=True,
            source_sha256=source_sha256,
            target_sha256=computed_sha256,
            size_bytes=len(data),
            duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return TransferResponse(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=0,
            duration_ms=duration_ms,
            error=str(e),
        )


# Protocol test trigger endpoints


@app.post("/trigger-websocket", response_model=WebSocketResponse)
async def trigger_websocket(req: TriggerWebSocketRequest):
    """Trigger WebSocket bidirectional streaming test."""
    result = await trigger_websocket_test(
        target=req.target,
        duration_seconds=req.duration_seconds,
        message_size=req.message_size,
    )
    return WebSocketResponse(**result)


@app.post("/trigger-sse", response_model=SSEResponse)
async def trigger_sse(req: TriggerSSERequest):
    """Trigger SSE streaming test."""
    result = await trigger_sse_test(
        target=req.target,
        count=req.count,
        interval_ms=req.interval_ms,
    )
    return SSEResponse(**result)


@app.post("/trigger-https", response_model=TransferResponse)
async def trigger_https(req: TriggerHTTPSRequest):
    """Trigger HTTPS transfer test.

    Same as HTTP upload/download but over TLS.
    """
    start_ms = time.monotonic() * 1000

    # Generate random data
    data = os.urandom(req.size)
    source_sha256 = hashlib.sha256(data).hexdigest()

    try:
        # Create SSL context
        import ssl

        ssl_context = ssl.create_default_context()
        if not req.verify_cert:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(timeout=120.0, verify=ssl_context) as client:
            response = await client.post(
                f"https://{req.target}:{FILE_SERVER_PORT}/upload",
                content=data,
                headers={"Content-Type": "application/octet-stream"},
            )
            response.raise_for_status()
            result = response.json()

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return TransferResponse(
            success=True,
            source_sha256=source_sha256,
            target_sha256=result["sha256"],
            size_bytes=req.size,
            duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return TransferResponse(
            success=False,
            source_sha256=source_sha256,
            target_sha256="",
            size_bytes=req.size,
            duration_ms=duration_ms,
            error=str(e),
        )


@app.post("/trigger-h2-multiplex", response_model=H2MultiplexResponse)
async def trigger_h2_multiplex(req: TriggerH2MultiplexRequest):
    """Trigger HTTP/2 multiplexing test."""
    result = await trigger_h2_multiplex_test(
        target=req.target,
        streams=req.streams,
        size_per_stream=req.size_per_stream,
    )
    return H2MultiplexResponse(**result)


@app.post("/trigger-mtls", response_model=MTLSResponse)
async def trigger_mtls(req: TriggerMTLSRequest):
    """Trigger mTLS transfer test.

    Uses mutual TLS authentication with client and server certificates.
    """
    start_ms = time.monotonic() * 1000

    # Generate random data
    data = os.urandom(req.size)
    source_sha256 = hashlib.sha256(data).hexdigest()

    try:
        # Load certificates for mTLS
        import ssl

        from server.tls import ensure_certs_exist

        certs = ensure_certs_exist()

        ssl_context = ssl.create_default_context(cafile=str(certs["ca_cert"]))
        ssl_context.load_cert_chain(
            certfile=str(certs["server_cert"]),
            keyfile=str(certs["server_key"]),
        )

        async with httpx.AsyncClient(timeout=120.0, verify=ssl_context) as client:
            response = await client.post(
                f"https://{req.target}:{FILE_SERVER_PORT}/upload",
                content=data,
                headers={"Content-Type": "application/octet-stream"},
            )
            response.raise_for_status()
            result = response.json()

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return MTLSResponse(
            success=True,
            client_cert_verified=True,
            server_cert_verified=True,
            sha256=result["sha256"],
            duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return MTLSResponse(
            success=False,
            client_cert_verified=False,
            server_cert_verified=False,
            sha256=source_sha256,
            duration_ms=duration_ms,
            error=str(e),
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=FILE_SERVER_PORT)
