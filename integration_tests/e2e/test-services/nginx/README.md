# Nginx Test Service

HTTP/HTTPS test service for E2E protocol testing.

## Overview

This service provides HTTP (port 80) and HTTPS (port 443) endpoints for testing the Buckwild VPN protocol's ability to handle various HTTP traffic patterns.

## Endpoints

### HTTP (port 80)

- `GET /` - Returns "HTTP Test Server"
- `GET /health` - Health check endpoint (returns "healthy")
- `GET /echo` - Echoes request information
- `GET /large` - Returns a large response for throughput testing

### HTTPS (port 443)

- `GET /` - Returns "HTTPS Test Server"
- `GET /health` - Health check endpoint (returns "healthy")
- `GET /echo` - Echoes request information
- `GET /large` - Returns a large response for throughput testing

## TLS Configuration

The service uses a self-signed certificate generated at build time:
- Certificate: `/etc/nginx/certs/server.crt`
- Key: `/etc/nginx/certs/server.key`
- Protocols: TLSv1.2, TLSv1.3
- Subject: `CN=nginx-test`

## Building

```bash
cd integration_tests/e2e/test-services/nginx
docker build -t buckwild-nginx-test .
```

## Running Standalone

```bash
docker run -p 8080:80 -p 8443:443 buckwild-nginx-test
```

## Usage in Tests

The nginx service is intended to be used within E2E test scenarios, deployed as part of a Docker Compose network alongside Buckwild nodes.

Example test pattern:
```python
@pytest.mark.e2e
@pytest.mark.http
async def test_http_through_vpn(two_node_cluster):
    node = two_node_cluster.get_node("node-1")
    returncode, stdout, _ = await node.exec_command(
        "curl -s http://nginx-test/health"
    )
    assert returncode == 0
    assert "healthy" in stdout
```

## Notes

- All endpoints use plain text responses for easy verification
- The `/echo` endpoint reflects request method, URI, and body
- The `/large` endpoint is useful for testing buffering and throughput
- Self-signed certificates require `-k` flag in curl for testing
