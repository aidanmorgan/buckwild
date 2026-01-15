"""HTTP/2 multiplexing handlers for concurrent stream testing."""

import asyncio
import hashlib
import os
import time
from typing import Any

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

FILE_SERVER_PORT = 8081


class H2MultiplexRequest(BaseModel):
    """Request for HTTP/2 multiplexing test."""

    streams: int
    size_per_stream: int


class StreamResult(BaseModel):
    """Result for a single HTTP/2 stream."""

    stream_id: int
    sha256: str
    size_bytes: int
    duration_ms: int


class H2MultiplexResponseData(BaseModel):
    """Response from HTTP/2 multiplexing endpoint."""

    streams: list[StreamResult]
    total_bytes: int


@router.post("/h2/multiplex")
async def h2_multiplex(req: H2MultiplexRequest) -> H2MultiplexResponseData:
    """HTTP/2 multiplexing endpoint.

    Spawns N concurrent streams, each sending random data.

    Args:
        req: Request with stream count and size per stream

    Returns:
        Aggregated results from all streams
    """

    async def generate_stream(stream_id: int) -> StreamResult:
        """Generate random data for a single stream."""
        start_ms = time.monotonic() * 1000

        # Generate random data
        data = os.urandom(req.size_per_stream)
        sha256 = hashlib.sha256(data).hexdigest()

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return StreamResult(
            stream_id=stream_id,
            sha256=sha256,
            size_bytes=len(data),
            duration_ms=duration_ms,
        )

    # Generate all streams concurrently
    tasks = [generate_stream(i) for i in range(req.streams)]
    results = await asyncio.gather(*tasks)

    total_bytes = sum(r.size_bytes for r in results)

    return H2MultiplexResponseData(
        streams=list(results),
        total_bytes=total_bytes,
    )


async def trigger_h2_multiplex_test(
    target: str, streams: int, size_per_stream: int
) -> dict[str, Any]:
    """Trigger HTTP/2 multiplexing test.

    Args:
        target: Target node TUN IP
        streams: Number of concurrent streams
        size_per_stream: Size of data per stream

    Returns:
        Test results dictionary
    """
    start_ms = time.monotonic() * 1000

    try:
        url = f"http://{target}:{FILE_SERVER_PORT}/h2/multiplex"
        payload = {"streams": streams, "size_per_stream": size_per_stream}

        # httpx with http2=True enables HTTP/2
        async with httpx.AsyncClient(http2=True, timeout=300.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            result = response.json()

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return {
            "success": True,
            "streams_completed": len(result["streams"]),
            "total_bytes": result["total_bytes"],
            "duration_ms": duration_ms,
        }

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return {
            "success": False,
            "streams_completed": 0,
            "total_bytes": 0,
            "duration_ms": duration_ms,
            "error": str(e),
        }
