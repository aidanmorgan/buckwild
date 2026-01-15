"""Server-Sent Events (SSE) handlers for streaming tests."""

import asyncio
import base64
import hashlib
import json
import time
from typing import Any

import httpx
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

router = APIRouter()

FILE_SERVER_PORT = 8081


@router.get("/sse/stream")
async def sse_stream(
    count: int = Query(default=100, ge=1, le=10000),
    interval_ms: int = Query(default=100, ge=10, le=1000),
):
    """Server-Sent Events endpoint for streaming tests.

    Args:
        count: Number of events to send
        interval_ms: Interval between events in milliseconds

    Yields:
        SSE events with format: {"seq": N, "data": "<base64>", "sha256": "<hex>"}
    """

    async def event_generator():
        for seq in range(count):
            # Generate deterministic data for this sequence number
            data = hashlib.sha256(str(seq).encode()).digest()[:1024]
            data_b64 = base64.b64encode(data).decode()
            sha256 = hashlib.sha256(data).hexdigest()

            event = {"seq": seq, "data": data_b64, "sha256": sha256}

            # SSE format: data: {json}\n\n
            yield f"data: {json.dumps(event)}\n\n"

            # Wait for interval
            if seq < count - 1:
                await asyncio.sleep(interval_ms / 1000.0)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


async def trigger_sse_test(target: str, count: int, interval_ms: int) -> dict[str, Any]:
    """Trigger SSE streaming test.

    Args:
        target: Target node TUN IP
        count: Number of events to expect
        interval_ms: Interval between events

    Returns:
        Test results dictionary
    """
    start_ms = time.monotonic() * 1000
    events_received = 0
    sequence_gaps: list[int] = []
    hash_failures = 0
    last_seq = -1

    try:
        url = f"http://{target}:{FILE_SERVER_PORT}/sse/stream"
        params = {"count": count, "interval_ms": interval_ms}

        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream("GET", url, params=params) as response:
                response.raise_for_status()

                # Read SSE events
                buffer = ""
                async for chunk in response.aiter_text():
                    buffer += chunk

                    # Process complete events (ending with \n\n)
                    while "\n\n" in buffer:
                        event_text, buffer = buffer.split("\n\n", 1)

                        # Parse SSE event (format: "data: {json}")
                        if not event_text.startswith("data: "):
                            continue

                        event_json = event_text[6:]  # Skip "data: " prefix
                        try:
                            event = json.loads(event_json)
                        except json.JSONDecodeError:
                            continue

                        # Validate sequence
                        seq = event.get("seq")
                        if seq is None:
                            continue

                        if seq != last_seq + 1:
                            sequence_gaps.append(seq)

                        last_seq = seq
                        events_received += 1

                        # Validate hash
                        data = base64.b64decode(event["data"])
                        computed_sha256 = hashlib.sha256(data).hexdigest()
                        if computed_sha256 != event.get("sha256"):
                            hash_failures += 1

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return {
            "success": True,
            "events_received": events_received,
            "sequence_gaps": sequence_gaps,
            "hash_failures": hash_failures,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return {
            "success": False,
            "events_received": events_received,
            "sequence_gaps": sequence_gaps,
            "hash_failures": hash_failures,
            "duration_ms": duration_ms,
            "error": str(e),
        }
