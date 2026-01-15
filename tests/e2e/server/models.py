"""Pydantic models for request/response types."""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    node_id: str
    tun_ip: str | None = None


class UploadResponse(BaseModel):
    """Response from /upload endpoint."""

    sha256: str
    size_bytes: int


class TriggerUploadRequest(BaseModel):
    """Request body for /trigger-upload."""

    target: str = Field(..., description="Target node TUN IP (e.g., 10.0.0.2)")
    size: int = Field(
        ..., ge=1024, le=10 * 1024 * 1024, description="Size in bytes (1KB-10MB)"
    )


class TriggerDownloadRequest(BaseModel):
    """Request body for /trigger-download."""

    target: str = Field(..., description="Target node TUN IP (e.g., 10.0.0.2)")
    size: int = Field(
        ..., ge=1024, le=10 * 1024 * 1024, description="Size in bytes (1KB-10MB)"
    )


class TransferResponse(BaseModel):
    """Response from /trigger-upload and /trigger-download."""

    success: bool
    source_sha256: str = Field(..., description="SHA256 computed by source node")
    target_sha256: str = Field(
        ..., description="SHA256 computed/returned by target node"
    )
    size_bytes: int
    duration_ms: int
    error: str | None = None


class TriggerWebSocketRequest(BaseModel):
    """Request body for /trigger-websocket."""

    target: str = Field(..., description="Target node TUN IP")
    duration_seconds: int = Field(default=10, ge=1, le=300)
    message_size: int = Field(default=1024, ge=64, le=65536)


class WebSocketResponse(BaseModel):
    """Response from /trigger-websocket."""

    success: bool
    messages_sent: int
    messages_received: int
    bytes_transferred: int
    hash_failures: int
    duration_ms: int
    error: str | None = None


class TriggerSSERequest(BaseModel):
    """Request body for /trigger-sse."""

    target: str = Field(..., description="Target node TUN IP")
    count: int = Field(default=100, ge=1, le=10000)
    interval_ms: int = Field(default=50, ge=10, le=1000)


class SSEResponse(BaseModel):
    """Response from /trigger-sse."""

    success: bool
    events_received: int
    sequence_gaps: list[int]
    hash_failures: int
    duration_ms: int
    error: str | None = None


class TriggerH2MultiplexRequest(BaseModel):
    """Request body for /trigger-h2-multiplex."""

    target: str = Field(..., description="Target node TUN IP")
    streams: int = Field(default=10, ge=1, le=100)
    size_per_stream: int = Field(default=102400, ge=1024, le=10 * 1024 * 1024)


class H2MultiplexResponse(BaseModel):
    """Response from /trigger-h2-multiplex."""

    success: bool
    streams_completed: int
    total_bytes: int
    duration_ms: int
    error: str | None = None


class TriggerHTTPSRequest(BaseModel):
    """Request body for /trigger-https."""

    target: str = Field(..., description="Target node TUN IP")
    size: int = Field(..., ge=1024, le=10 * 1024 * 1024)
    verify_cert: bool = Field(default=False)


class TriggerMTLSRequest(BaseModel):
    """Request body for /trigger-mtls."""

    target: str = Field(..., description="Target node TUN IP")
    size: int = Field(default=1024, ge=1024, le=10 * 1024 * 1024)


class MTLSResponse(BaseModel):
    """Response from /trigger-mtls."""

    success: bool
    client_cert_verified: bool
    server_cert_verified: bool
    sha256: str
    duration_ms: int
    error: str | None = None
