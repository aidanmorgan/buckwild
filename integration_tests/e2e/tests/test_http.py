"""HTTP/HTTPS protocol tests for E2E framework.

Tests HTTP and HTTPS connectivity through the Buckwild VPN,
including various request sizes and concurrent requests.
"""

import asyncio
import pytest


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_get_basic(two_node_cluster):
    """Test basic HTTP GET request through VPN."""
    node1 = two_node_cluster.get_node("node-1")

    # Execute curl to nginx service (assumes nginx is accessible)
    returncode, stdout, stderr = await node1.exec_command(
        "curl -s -o /dev/null -w '%{http_code}' http://httpbin.org/get",
        timeout=10.0,
        check=False
    )

    # Basic connectivity check - verify we can make HTTP requests
    assert returncode == 0, f"HTTP GET failed: {stderr}"
    assert "200" in stdout or "301" in stdout or "302" in stdout, f"Unexpected HTTP status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_post_small_payload(two_node_cluster):
    """Test HTTP POST with small payload."""
    node1 = two_node_cluster.get_node("node-1")

    # Test POST with small JSON payload
    cmd = """curl -s -X POST -H 'Content-Type: application/json' \
        -d '{"test":"data","size":"small"}' \
        -o /dev/null -w '%{http_code}' \
        http://httpbin.org/post"""

    returncode, stdout, stderr = await node1.exec_command(
        cmd,
        timeout=10.0,
        check=False
    )

    assert returncode == 0, f"HTTP POST failed: {stderr}"
    assert "200" in stdout, f"Unexpected HTTP status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_post_medium_payload(two_node_cluster):
    """Test HTTP POST with medium payload (1KB)."""
    node1 = two_node_cluster.get_node("node-1")

    # Generate 1KB of data
    payload = "x" * 1024

    cmd = f"""curl -s -X POST -H 'Content-Type: text/plain' \
        -d '{payload}' \
        -o /dev/null -w '%{{http_code}}' \
        http://httpbin.org/post"""

    returncode, stdout, stderr = await node1.exec_command(
        cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"HTTP POST with 1KB payload failed: {stderr}"
    assert "200" in stdout, f"Unexpected HTTP status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_post_large_payload(two_node_cluster):
    """Test HTTP POST with large payload (10KB)."""
    node1 = two_node_cluster.get_node("node-1")

    # Generate 10KB of data
    payload = "x" * (10 * 1024)

    cmd = f"""curl -s -X POST -H 'Content-Type: text/plain' \
        -d '{payload}' \
        -o /dev/null -w '%{{http_code}}' \
        http://httpbin.org/post"""

    returncode, stdout, stderr = await node1.exec_command(
        cmd,
        timeout=20.0,
        check=False
    )

    assert returncode == 0, f"HTTP POST with 10KB payload failed: {stderr}"
    assert "200" in stdout, f"Unexpected HTTP status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_https_get_basic(two_node_cluster):
    """Test basic HTTPS GET request through VPN."""
    node1 = two_node_cluster.get_node("node-1")

    # Test HTTPS with self-signed cert (using -k to skip verification)
    cmd = """curl -s -k -o /dev/null -w '%{http_code}' https://httpbin.org/get"""

    returncode, stdout, stderr = await node1.exec_command(
        cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"HTTPS GET failed: {stderr}"
    assert "200" in stdout, f"Unexpected HTTP status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_https_post_with_cert_validation(two_node_cluster):
    """Test HTTPS POST with certificate validation."""
    node1 = two_node_cluster.get_node("node-1")

    # Test HTTPS with certificate validation (httpbin.org has valid cert)
    cmd = """curl -s -X POST -H 'Content-Type: application/json' \
        -d '{"test":"https","validated":true}' \
        -o /dev/null -w '%{http_code}' \
        https://httpbin.org/post"""

    returncode, stdout, stderr = await node1.exec_command(
        cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"HTTPS POST with cert validation failed: {stderr}"
    assert "200" in stdout, f"Unexpected HTTP status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_concurrent_requests(two_node_cluster):
    """Test concurrent HTTP requests from multiple nodes."""
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    # Define concurrent request tasks
    async def make_request(node, request_id):
        cmd = f"""curl -s -o /dev/null -w '%{{http_code}}' \
            'http://httpbin.org/get?id={request_id}'"""
        returncode, stdout, stderr = await node.exec_command(
            cmd,
            timeout=10.0,
            check=False
        )
        return returncode, stdout, stderr

    # Execute concurrent requests from both nodes
    tasks = [
        make_request(node1, 1),
        make_request(node1, 2),
        make_request(node2, 3),
        make_request(node2, 4),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Verify all requests succeeded
    for i, result in enumerate(results):
        assert not isinstance(result, Exception), f"Request {i+1} raised exception: {result}"
        returncode, stdout, stderr = result
        assert returncode == 0, f"Request {i+1} failed: {stderr}"
        assert "200" in stdout, f"Request {i+1} unexpected status: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_response_size_variations(two_node_cluster):
    """Test HTTP requests with varying response sizes."""
    node1 = two_node_cluster.get_node("node-1")

    # Test different response sizes
    test_cases = [
        ("bytes/100", "100 bytes"),
        ("bytes/1024", "1KB"),
        ("bytes/10240", "10KB"),
    ]

    for endpoint, description in test_cases:
        cmd = f"""curl -s -o /dev/null -w '%{{http_code}}' \
            http://httpbin.org/{endpoint}"""

        returncode, stdout, stderr = await node1.exec_command(
            cmd,
            timeout=15.0,
            check=False
        )

        assert returncode == 0, f"HTTP GET ({description}) failed: {stderr}"
        assert "200" in stdout, f"Unexpected status for {description}: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_http_methods_variety(two_node_cluster):
    """Test various HTTP methods (GET, POST, PUT, DELETE)."""
    node1 = two_node_cluster.get_node("node-1")

    methods = [
        ("GET", "http://httpbin.org/get"),
        ("POST", "http://httpbin.org/post"),
        ("PUT", "http://httpbin.org/put"),
        ("DELETE", "http://httpbin.org/delete"),
    ]

    for method, url in methods:
        cmd = f"""curl -s -X {method} -o /dev/null -w '%{{http_code}}' {url}"""

        returncode, stdout, stderr = await node1.exec_command(
            cmd,
            timeout=10.0,
            check=False
        )

        assert returncode == 0, f"HTTP {method} failed: {stderr}"
        assert "200" in stdout, f"Unexpected status for {method}: {stdout}"


@pytest.mark.e2e
@pytest.mark.http
@pytest.mark.asyncio
async def test_https_concurrent_mixed_requests(two_node_cluster):
    """Test concurrent mixed HTTP/HTTPS requests."""
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    async def make_http_request(node, request_id):
        cmd = f"""curl -s -o /dev/null -w '%{{http_code}}' \
            'http://httpbin.org/get?id={request_id}'"""
        return await node.exec_command(cmd, timeout=10.0, check=False)

    async def make_https_request(node, request_id):
        cmd = f"""curl -s -k -o /dev/null -w '%{{http_code}}' \
            'https://httpbin.org/get?id={request_id}'"""
        return await node.exec_command(cmd, timeout=15.0, check=False)

    # Mix of HTTP and HTTPS requests
    tasks = [
        make_http_request(node1, 1),
        make_https_request(node1, 2),
        make_http_request(node2, 3),
        make_https_request(node2, 4),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        assert not isinstance(result, Exception), f"Request {i+1} raised exception: {result}"
        returncode, stdout, stderr = result
        assert returncode == 0, f"Request {i+1} failed: {stderr}"
        assert "200" in stdout, f"Request {i+1} unexpected status: {stdout}"
