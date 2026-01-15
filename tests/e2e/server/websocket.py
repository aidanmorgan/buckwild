"""WebSocket handlers for bidirectional streaming tests."""

import asyncio
import base64
import hashlib
import json
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosed

router = APIRouter()

FILE_SERVER_PORT = 8081


@router.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    """WebSocket endpoint for bidirectional streaming.

    Client sends: {"data": "<base64>", "seq": N}
    Server echoes: {"data": "<base64>", "seq": N, "sha256": "<hex>"}
    """
    await websocket.accept()

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            msg = json.loads(data)

            # Validate message format
            if "data" not in msg or "seq" not in msg:
                await websocket.send_json(
                    {"error": "Invalid message format, expected {data, seq}"}
                )
                continue

            # Decode data and compute SHA256
            try:
                payload = base64.b64decode(msg["data"])
            except Exception as e:
                await websocket.send_json({"error": f"Invalid base64 data: {e}"})
                continue

            sha256 = hashlib.sha256(payload).hexdigest()

            # Echo back with hash
            response = {
                "data": msg["data"],
                "seq": msg["seq"],
                "sha256": sha256,
            }
            await websocket.send_json(response)

    except (WebSocketDisconnect, ConnectionClosed):
        pass


async def trigger_websocket_test(
    target: str, duration_seconds: int, message_size: int
) -> dict[str, Any]:
    """Trigger WebSocket bidirectional streaming test.

    Args:
        target: Target node TUN IP
        duration_seconds: Test duration in seconds
        message_size: Size of each message in bytes

    Returns:
        Test results dictionary
    """
    import websockets

    start_ms = time.monotonic() * 1000
    messages_sent = 0
    messages_received = 0
    bytes_transferred = 0
    hash_failures = 0

    try:
        uri = f"ws://{target}:{FILE_SERVER_PORT}/ws/stream"
        async with websockets.connect(uri, open_timeout=30) as ws:
            end_time = time.monotonic() + duration_seconds

            while time.monotonic() < end_time:
                # Generate random message
                data = base64.b64encode(
                    hashlib.sha256(str(messages_sent).encode()).digest()[:message_size]
                ).decode()
                source_sha256 = hashlib.sha256(base64.b64decode(data)).hexdigest()

                # Send message
                msg = {"data": data, "seq": messages_sent}
                await ws.send(json.dumps(msg))
                messages_sent += 1
                bytes_transferred += len(data)

                # Receive echo response
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                result = json.loads(response)

                # Validate response
                if result.get("seq") != msg["seq"]:
                    hash_failures += 1
                elif result.get("sha256") != source_sha256:
                    hash_failures += 1
                else:
                    messages_received += 1

        duration_ms = int(time.monotonic() * 1000 - start_ms)

        return {
            "success": True,
            "messages_sent": messages_sent,
            "messages_received": messages_received,
            "bytes_transferred": bytes_transferred,
            "hash_failures": hash_failures,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        return {
            "success": False,
            "messages_sent": messages_sent,
            "messages_received": messages_received,
            "bytes_transferred": bytes_transferred,
            "hash_failures": hash_failures,
            "duration_ms": duration_ms,
            "error": str(e),
        }
