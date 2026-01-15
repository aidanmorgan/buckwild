"""Node-to-node transfer logic for trigger endpoints."""

import secrets
import time
from hashlib import sha256

import httpx


async def trigger_upload(
    target_ip: str, size: int
) -> dict[str, int | str | bool | None]:
    """Generate random data and upload to target node.

    Args:
        target_ip: Target node TUN IP address (e.g., 10.0.0.2)
        size: Size of data to generate and send in bytes

    Returns:
        Dictionary with transfer results:
            - success: Whether transfer completed
            - source_sha256: Hash of data sent
            - target_sha256: Hash computed by target
            - size_bytes: Total bytes transferred
            - duration_ms: Transfer duration
            - error: Error message if failed
    """
    start_time = time.time()
    error = None

    try:
        # Generate random data
        data = secrets.token_bytes(size)
        source_hash = sha256(data).hexdigest()

        # Send to target node via TUN
        target_url = f"http://{target_ip}:8081/upload"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                target_url,
                content=data,
                headers={"Content-Type": "application/octet-stream"},
            )
            response.raise_for_status()
            result = response.json()
            target_hash = result["sha256"]

        success = source_hash == target_hash

    except Exception as e:
        success = False
        source_hash = ""
        target_hash = ""
        size = 0
        error = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "success": success,
        "source_sha256": source_hash,
        "target_sha256": target_hash,
        "size_bytes": size,
        "duration_ms": duration_ms,
        "error": error,
    }


async def trigger_download(
    target_ip: str, size: int
) -> dict[str, int | str | bool | None]:
    """Download data from target node and validate hash.

    Args:
        target_ip: Target node TUN IP address (e.g., 10.0.0.2)
        size: Size of data to request in bytes

    Returns:
        Dictionary with transfer results:
            - success: Whether transfer completed and hashes match
            - source_sha256: Hash from target's header
            - computed_sha256: Hash we computed from received data
            - size_bytes: Total bytes received
            - duration_ms: Transfer duration
            - error: Error message if failed
    """
    start_time = time.time()
    error = None

    try:
        # Request data from target node via TUN
        target_url = f"http://{target_ip}:8081/download?size={size}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(target_url)
            response.raise_for_status()

            # Get source hash from header
            source_hash = response.headers.get("X-Content-SHA256", "")

            # Compute hash of received data
            received_data = response.content
            computed_hash = sha256(received_data).hexdigest()
            received_size = len(received_data)

        success = source_hash == computed_hash and received_size == size

    except Exception as e:
        success = False
        source_hash = ""
        computed_hash = ""
        received_size = 0
        error = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "success": success,
        "source_sha256": source_hash,
        "target_sha256": computed_hash,  # Use consistent key name
        "size_bytes": received_size,
        "duration_ms": duration_ms,
        "error": error,
    }
