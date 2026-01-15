# Health Check Endpoints

## Overview

The daemon exposes HTTP health check endpoints for container orchestration and monitoring systems.

## Endpoints

### GET /health

Liveness probe endpoint that always returns healthy status when the server is running.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_secs": 42
}
```

**Fields:**
- `status`: Always "healthy" when the daemon is running
- `version`: Daemon version from Cargo.toml
- `uptime_secs`: Seconds since daemon started

### GET /ready

Readiness probe endpoint that indicates whether the daemon has completed initialization.

**Response (200 OK when ready):**
```json
{
  "ready": true,
  "reason": null
}
```

**Response (503 Service Unavailable when not ready):**
```json
{
  "ready": false,
  "reason": "Initializing"
}
```

**Fields:**
- `ready`: Boolean indicating readiness state
- `reason`: Optional string describing why the daemon is not ready

## Configuration

The health server listens on port 8080 by default. This is configured in `main.rs`:

```rust
let health_server = Arc::new(monitoring::health::HealthServer::new(8080));
```

## Docker Integration

The runtime Dockerfile includes a HEALTHCHECK instruction:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
```

**Parameters:**
- `interval`: Check every 30 seconds
- `timeout`: Fail if check takes more than 3 seconds
- `start-period`: Allow 5 seconds for daemon initialization
- `retries`: Mark unhealthy after 3 consecutive failures

## Kubernetes Integration

Example Kubernetes probes:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 30
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

## Testing

Test the endpoints with curl:

```bash
# Health check
curl -s http://localhost:8080/health | jq

# Ready check
curl -s http://localhost:8080/ready | jq

# Run test script
./src/monitoring/health_test.sh
```

## Implementation Details

- Uses Hyper 1.0 for HTTP server
- Async/await with Tokio runtime
- Thread-safe state management with RwLock
- Graceful shutdown on daemon termination
- No unwrap/panic - all errors properly handled
