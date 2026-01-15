"""HTTP client for triggering node-to-node transfers.

This client runs on the host and communicates with nodes via Docker port mapping.
It triggers transfers between nodes that go through the TUN interface.
"""

from dataclasses import dataclass

import httpx


def get_node_port(node: str, service: str = "http") -> int:
    """Get host port for a node and service.

    Args:
        node: Node name (e.g., "node-01", "node-15", "node-50")
        service: Service type - "http", "health", "rtmp", "rtsp", "quic"

    Returns:
        Host port number

    Examples:
        get_node_port("node-01", "http")  -> 10081
        get_node_port("node-15", "rtmp")  -> 11435
        get_node_port("node-50", "quic")  -> 15043
    """
    node_index = int(node.split("-")[1])
    assert 1 <= node_index <= 50, f"Invalid node: {node}"

    base_port = 10000 + (node_index * 100)
    offsets = {
        "http": 81,
        "health": 80,
        "rtmp": 935,
        "rtsp": 554,
        "quic": 443,
    }
    return base_port + offsets[service]


def get_tun_ip(node: str) -> str:
    """Get TUN IP for a node.

    Args:
        node: Node name (e.g., "node-01", "node-50")

    Returns:
        TUN IP address (e.g., "10.0.0.1", "10.0.0.50")
    """
    node_index = int(node.split("-")[1])
    assert 1 <= node_index <= 50, f"Invalid node: {node}"
    return f"10.0.0.{node_index}"


def get_all_nodes(count: int) -> list[str]:
    """Get list of node names for a topology.

    Args:
        count: Number of nodes (1-50)

    Returns:
        List of node names (e.g., ["node-01", "node-02", ...])
    """
    assert 1 <= count <= 50, f"Invalid count: {count}"
    return [f"node-{i:02d}" for i in range(1, count + 1)]


# Convenience: pre-computed for common topologies
NODES_2 = get_all_nodes(2)
NODES_3 = get_all_nodes(3)
NODES_5 = get_all_nodes(5)
NODES_10 = get_all_nodes(10)
NODES_25 = get_all_nodes(25)
NODES_50 = get_all_nodes(50)


@dataclass
class TransferResult:
    """Result of a file transfer operation."""

    success: bool
    source_sha256: str
    target_sha256: str
    size_bytes: int
    duration_ms: int
    error: str | None = None

    def hashes_match(self) -> bool:
        """Check if source and target hashes match."""
        return self.source_sha256 == self.target_sha256


@dataclass
class WebSocketResult:
    """Result of a WebSocket test."""

    success: bool
    messages_sent: int
    messages_received: int
    bytes_transferred: int
    hash_failures: int
    duration_ms: int
    error: str | None = None


@dataclass
class SSEResult:
    """Result of an SSE test."""

    success: bool
    events_received: int
    sequence_gaps: list[int]
    hash_failures: int
    duration_ms: int
    error: str | None = None


@dataclass
class H2MultiplexResult:
    """Result of an HTTP/2 multiplexing test."""

    success: bool
    streams_completed: int
    total_bytes: int
    duration_ms: int
    error: str | None = None


async def check_node_health(node: str, timeout: float = 5.0) -> bool:
    """Check if a node's file transfer server is healthy.

    Args:
        node: Node name (e.g., "node-01")
        timeout: Request timeout in seconds

    Returns:
        True if node is healthy, False otherwise
    """
    try:
        port = get_node_port(node, "health")
    except (ValueError, AssertionError, IndexError):
        return False

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"http://localhost:{port}/health")
            return response.status_code == 200
    except Exception:
        return False


async def trigger_upload(
    source_node: str,
    target_node: str,
    size_bytes: int,
    timeout: float = 120.0,
) -> TransferResult:
    """Trigger source node to upload data to target node via TUN.

    Args:
        source_node: Node that will generate and send data (e.g., "node-01")
        target_node: Node that will receive data (e.g., "node-02")
        size_bytes: Size of random data to transfer (1KB-10MB)
        timeout: Request timeout in seconds

    Returns:
        TransferResult with success status and SHA256 values
    """
    try:
        port = get_node_port(source_node, "http")
    except (ValueError, AssertionError, IndexError):
        return TransferResult(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=size_bytes,
            duration_ms=0,
            error=f"Unknown source node: {source_node}",
        )

    try:
        target_ip = get_tun_ip(target_node)
    except (ValueError, AssertionError, IndexError):
        return TransferResult(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=size_bytes,
            duration_ms=0,
            error=f"Unknown target node: {target_node}",
        )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"http://localhost:{port}/trigger-upload",
                json={"target": target_ip, "size": size_bytes},
            )
            response.raise_for_status()
            data = response.json()

            return TransferResult(
                success=data["success"],
                source_sha256=data["source_sha256"],
                target_sha256=data["target_sha256"],
                size_bytes=data["size_bytes"],
                duration_ms=data["duration_ms"],
                error=data.get("error"),
            )

    except Exception as e:
        return TransferResult(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=size_bytes,
            duration_ms=0,
            error=str(e),
        )


async def trigger_download(
    source_node: str,
    target_node: str,
    size_bytes: int,
    timeout: float = 120.0,
) -> TransferResult:
    """Trigger source node to download data from target node via TUN.

    Args:
        source_node: Node that will request and receive data (e.g., "node-01")
        target_node: Node that will generate and send data (e.g., "node-02")
        size_bytes: Size of random data to transfer (1KB-10MB)
        timeout: Request timeout in seconds

    Returns:
        TransferResult with success status and SHA256 values
    """
    try:
        port = get_node_port(source_node, "http")
    except (ValueError, AssertionError, IndexError):
        return TransferResult(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=size_bytes,
            duration_ms=0,
            error=f"Unknown source node: {source_node}",
        )

    try:
        target_ip = get_tun_ip(target_node)
    except (ValueError, AssertionError, IndexError):
        return TransferResult(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=size_bytes,
            duration_ms=0,
            error=f"Unknown target node: {target_node}",
        )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"http://localhost:{port}/trigger-download",
                json={"target": target_ip, "size": size_bytes},
            )
            response.raise_for_status()
            data = response.json()

            return TransferResult(
                success=data["success"],
                source_sha256=data["source_sha256"],
                target_sha256=data["target_sha256"],
                size_bytes=data["size_bytes"],
                duration_ms=data["duration_ms"],
                error=data.get("error"),
            )

    except Exception as e:
        return TransferResult(
            success=False,
            source_sha256="",
            target_sha256="",
            size_bytes=size_bytes,
            duration_ms=0,
            error=str(e),
        )


async def trigger_websocket(
    source_node: str,
    target_node: str,
    duration_seconds: int = 10,
    message_size: int = 1024,
    timeout: float = 120.0,
) -> WebSocketResult:
    """Trigger WebSocket bidirectional streaming test.

    Args:
        source_node: Node that will initiate WebSocket connection
        target_node: Node that will accept connection
        duration_seconds: How long to exchange messages
        message_size: Size of each message
        timeout: Request timeout in seconds

    Returns:
        WebSocketResult with test results
    """
    try:
        port = get_node_port(source_node, "http")
    except (ValueError, AssertionError, IndexError):
        return WebSocketResult(
            success=False,
            messages_sent=0,
            messages_received=0,
            bytes_transferred=0,
            hash_failures=0,
            duration_ms=0,
            error=f"Unknown source node: {source_node}",
        )

    try:
        target_ip = get_tun_ip(target_node)
    except (ValueError, AssertionError, IndexError):
        return WebSocketResult(
            success=False,
            messages_sent=0,
            messages_received=0,
            bytes_transferred=0,
            hash_failures=0,
            duration_ms=0,
            error=f"Unknown target node: {target_node}",
        )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"http://localhost:{port}/trigger-websocket",
                json={
                    "target": target_ip,
                    "duration_seconds": duration_seconds,
                    "message_size": message_size,
                },
            )
            response.raise_for_status()
            data = response.json()

            return WebSocketResult(
                success=data["success"],
                messages_sent=data["messages_sent"],
                messages_received=data["messages_received"],
                bytes_transferred=data["bytes_transferred"],
                hash_failures=data["hash_failures"],
                duration_ms=data["duration_ms"],
                error=data.get("error"),
            )

    except Exception as e:
        return WebSocketResult(
            success=False,
            messages_sent=0,
            messages_received=0,
            bytes_transferred=0,
            hash_failures=0,
            duration_ms=0,
            error=str(e),
        )


async def trigger_sse(
    source_node: str,
    target_node: str,
    count: int = 100,
    interval_ms: int = 50,
    timeout: float = 120.0,
) -> SSEResult:
    """Trigger SSE streaming test.

    Args:
        source_node: Node that will consume SSE stream
        target_node: Node that will produce SSE events
        count: Number of events to receive
        interval_ms: Interval between events
        timeout: Request timeout in seconds

    Returns:
        SSEResult with test results
    """
    try:
        port = get_node_port(source_node, "http")
    except (ValueError, AssertionError, IndexError):
        return SSEResult(
            success=False,
            events_received=0,
            sequence_gaps=[],
            hash_failures=0,
            duration_ms=0,
            error=f"Unknown source node: {source_node}",
        )

    try:
        target_ip = get_tun_ip(target_node)
    except (ValueError, AssertionError, IndexError):
        return SSEResult(
            success=False,
            events_received=0,
            sequence_gaps=[],
            hash_failures=0,
            duration_ms=0,
            error=f"Unknown target node: {target_node}",
        )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"http://localhost:{port}/trigger-sse",
                json={
                    "target": target_ip,
                    "count": count,
                    "interval_ms": interval_ms,
                },
            )
            response.raise_for_status()
            data = response.json()

            return SSEResult(
                success=data["success"],
                events_received=data["events_received"],
                sequence_gaps=data["sequence_gaps"],
                hash_failures=data["hash_failures"],
                duration_ms=data["duration_ms"],
                error=data.get("error"),
            )

    except Exception as e:
        return SSEResult(
            success=False,
            events_received=0,
            sequence_gaps=[],
            hash_failures=0,
            duration_ms=0,
            error=str(e),
        )


async def trigger_h2_multiplex(
    source_node: str,
    target_node: str,
    streams: int = 10,
    size_per_stream: int = 102400,
    timeout: float = 120.0,
) -> H2MultiplexResult:
    """Trigger HTTP/2 multiplexing stress test.

    Args:
        source_node: Node that will open HTTP/2 connection
        target_node: Node that will handle multiplexed requests
        streams: Number of concurrent streams
        size_per_stream: Size of data per stream
        timeout: Request timeout in seconds

    Returns:
        H2MultiplexResult with test results
    """
    try:
        port = get_node_port(source_node, "http")
    except (ValueError, AssertionError, IndexError):
        return H2MultiplexResult(
            success=False,
            streams_completed=0,
            total_bytes=0,
            duration_ms=0,
            error=f"Unknown source node: {source_node}",
        )

    try:
        target_ip = get_tun_ip(target_node)
    except (ValueError, AssertionError, IndexError):
        return H2MultiplexResult(
            success=False,
            streams_completed=0,
            total_bytes=0,
            duration_ms=0,
            error=f"Unknown target node: {target_node}",
        )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"http://localhost:{port}/trigger-h2-multiplex",
                json={
                    "target": target_ip,
                    "streams": streams,
                    "size_per_stream": size_per_stream,
                },
            )
            response.raise_for_status()
            data = response.json()

            return H2MultiplexResult(
                success=data["success"],
                streams_completed=data["streams_completed"],
                total_bytes=data["total_bytes"],
                duration_ms=data["duration_ms"],
                error=data.get("error"),
            )

    except Exception as e:
        return H2MultiplexResult(
            success=False,
            streams_completed=0,
            total_bytes=0,
            duration_ms=0,
            error=str(e),
        )
