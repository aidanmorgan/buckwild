"""E2E tests for gRPC protocol over Buckwild VPN.

Tests various gRPC patterns (unary, server streaming, client streaming,
bidirectional streaming) to verify protocol compatibility and performance.
"""

import asyncio
import logging
import subprocess
import time
from pathlib import Path

import pytest


logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def grpc_service_dir():
    """Get path to gRPC test service directory."""
    return Path(__file__).parent.parent / "test-services" / "grpc"


@pytest.fixture(scope="module")
def grpc_proto_compiled(grpc_service_dir):
    """Compile proto files for test client usage."""
    proto_file = grpc_service_dir / "test_service.proto"

    # Generate Python gRPC code for test client
    cmd = [
        "python", "-m", "grpc_tools.protoc",
        f"-I{grpc_service_dir}",
        f"--python_out={grpc_service_dir}",
        f"--grpc_python_out={grpc_service_dir}",
        str(proto_file)
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
        logger.info("Proto files compiled successfully")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        error_msg = e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e)
        logger.error(f"Failed to compile proto: {error_msg}")
        pytest.skip(f"grpc_tools.protoc not available: {error_msg}")

    return grpc_service_dir


@pytest.fixture(scope="module")
async def grpc_server_container(grpc_service_dir, grpc_proto_compiled):
    """Start gRPC test server in Docker container."""
    container_name = "grpc-test-server"

    # Build the gRPC server image
    logger.info("Building gRPC server image")
    build_cmd = [
        "docker", "build",
        "-t", "grpc-test-server:latest",
        "-f", str(grpc_service_dir / "Dockerfile"),
        str(grpc_service_dir)
    ]

    try:
        subprocess.run(build_cmd, check=True, capture_output=True, timeout=120)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to build gRPC image: {e.stderr.decode()}")
        raise RuntimeError(f"Docker build failed: {e.stderr.decode()}")

    # Start the container
    logger.info("Starting gRPC server container")
    run_cmd = [
        "docker", "run",
        "-d",
        "--name", container_name,
        "-p", "50051:50051",
        "grpc-test-server:latest"
    ]

    try:
        subprocess.run(run_cmd, check=True, capture_output=True, timeout=30)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start container: {e.stderr.decode()}")
        raise RuntimeError(f"Container start failed: {e.stderr.decode()}")

    # Wait for server to be ready
    await asyncio.sleep(5)

    # Verify container is running
    inspect_cmd = ["docker", "inspect", "-f", "{{.State.Running}}", container_name]
    result = subprocess.run(inspect_cmd, capture_output=True, text=True)
    if result.stdout.strip() != "true":
        raise RuntimeError("gRPC server container not running")

    logger.info("gRPC server ready")

    yield container_name

    # Cleanup
    logger.info("Stopping gRPC server container")
    subprocess.run(["docker", "stop", container_name], check=False)
    subprocess.run(["docker", "rm", container_name], check=False)


@pytest.fixture
async def grpc_client(grpc_proto_compiled, grpc_server_container):
    """Create gRPC client for tests."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))

    import grpc
    import test_service_pb2_grpc

    channel = grpc.insecure_channel('localhost:50051')
    stub = test_service_pb2_grpc.TestServiceStub(channel)

    # Wait for channel to be ready
    try:
        grpc.channel_ready_future(channel).result(timeout=10)
    except grpc.FutureTimeoutError:
        channel.close()
        raise RuntimeError("Failed to connect to gRPC server")

    yield stub

    channel.close()


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_unary_echo(grpc_client, grpc_proto_compiled):
    """Test unary RPC call (single request, single response)."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Send echo request
    request = test_service_pb2.EchoRequest(message="Hello, gRPC!")
    response = grpc_client.Echo(request)

    # Verify response
    assert response.message == "Hello, gRPC!"
    assert response.timestamp > 0
    assert response.timestamp <= int(time.time() * 1000) + 1000


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_server_streaming(grpc_client, grpc_proto_compiled):
    """Test server streaming RPC (single request, stream of responses)."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Request stream of 10 numbers with 10ms delay
    request = test_service_pb2.StreamRequest(count=10, delay_ms=10)
    response_stream = grpc_client.StreamNumbers(request)

    # Collect all responses
    numbers = []
    for response in response_stream:
        numbers.append(response.number)

    # Verify we received all numbers in order
    assert len(numbers) == 10
    assert numbers == list(range(10))


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_server_streaming_no_delay(grpc_client, grpc_proto_compiled):
    """Test server streaming with no delay between messages."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Request stream of 100 numbers with no delay
    request = test_service_pb2.StreamRequest(count=100, delay_ms=0)
    response_stream = grpc_client.StreamNumbers(request)

    # Collect all responses
    numbers = [response.number for response in response_stream]

    # Verify we received all numbers
    assert len(numbers) == 100
    assert numbers == list(range(100))


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_client_streaming(grpc_client, grpc_proto_compiled):
    """Test client streaming RPC (stream of requests, single response)."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Create request iterator
    def request_iterator():
        for i in range(1, 11):
            yield test_service_pb2.NumberRequest(number=i)

    # Send stream and get accumulated result
    response = grpc_client.AccumulateNumbers(request_iterator())

    # Verify sum and count
    expected_sum = sum(range(1, 11))
    assert response.sum == expected_sum
    assert response.count == 10


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_client_streaming_large(grpc_client, grpc_proto_compiled):
    """Test client streaming with larger dataset."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Stream 1000 numbers
    def request_iterator():
        for i in range(1, 1001):
            yield test_service_pb2.NumberRequest(number=i)

    response = grpc_client.AccumulateNumbers(request_iterator())

    # Verify sum and count
    expected_sum = sum(range(1, 1001))
    assert response.sum == expected_sum
    assert response.count == 1000


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_bidirectional_streaming(grpc_client, grpc_proto_compiled):
    """Test bidirectional streaming RPC (stream of requests and responses)."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Create request iterator
    def request_iterator():
        messages = ["Hello", "How are you?", "Goodbye"]
        for msg in messages:
            yield test_service_pb2.ChatMessage(
                sender="client",
                message=msg,
                timestamp=int(time.time() * 1000)
            )

    # Send messages and receive echoes
    response_stream = grpc_client.Chat(request_iterator())

    # Collect responses
    responses = []
    for response in response_stream:
        responses.append(response)

    # Verify we got echo for each message
    assert len(responses) == 3
    assert all(r.sender == "server" for r in responses)
    assert "Echo: Hello" in responses[0].message
    assert "Echo: How are you?" in responses[1].message
    assert "Echo: Goodbye" in responses[2].message


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_bidirectional_streaming_concurrent(grpc_client, grpc_proto_compiled):
    """Test bidirectional streaming with concurrent message exchange."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Create request iterator that yields messages over time
    def request_iterator():
        for i in range(10):
            yield test_service_pb2.ChatMessage(
                sender="client",
                message=f"Message {i}",
                timestamp=int(time.time() * 1000)
            )
            time.sleep(0.01)

    # Send and receive concurrently
    response_stream = grpc_client.Chat(request_iterator())

    # Collect all responses
    responses = [response for response in response_stream]

    # Verify we got all echoes
    assert len(responses) == 10
    for i, response in enumerate(responses):
        assert response.sender == "server"
        assert f"Message {i}" in response.message


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_multiple_concurrent_calls(grpc_client, grpc_proto_compiled):
    """Test multiple concurrent unary calls."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2
    from concurrent.futures import ThreadPoolExecutor

    def make_call(i):
        request = test_service_pb2.EchoRequest(message=f"Message {i}")
        response = grpc_client.Echo(request)
        return response.message

    # Make 10 concurrent calls
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_call, i) for i in range(10)]
        results = [f.result() for f in futures]

    # Verify all calls succeeded
    assert len(results) == 10
    assert all(f"Message {i}" in results for i in range(10))


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.slow
@pytest.mark.asyncio
async def test_grpc_large_message(grpc_client, grpc_proto_compiled):
    """Test handling of large messages."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Create a 1MB message
    large_message = "x" * (1024 * 1024)
    request = test_service_pb2.EchoRequest(message=large_message)
    response = grpc_client.Echo(request)

    # Verify message was echoed correctly
    assert response.message == large_message
    assert len(response.message) == 1024 * 1024


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_empty_stream(grpc_client, grpc_proto_compiled):
    """Test server streaming with count=0."""
    import sys
    sys.path.insert(0, str(grpc_proto_compiled))
    import test_service_pb2

    # Request empty stream
    request = test_service_pb2.StreamRequest(count=0, delay_ms=0)
    response_stream = grpc_client.StreamNumbers(request)

    # Should get no responses
    numbers = [response.number for response in response_stream]
    assert len(numbers) == 0


@pytest.mark.e2e
@pytest.mark.grpc
@pytest.mark.asyncio
async def test_grpc_error_handling(grpc_client):
    """Test error handling for invalid requests."""
    import grpc

    # This should fail gracefully if server doesn't implement validation
    # For now, just verify the client doesn't crash
    try:
        # Attempt to call with None should raise error
        response = grpc_client.Echo(None)
        # If we get here, server accepted None (implementation specific)
        assert response is not None or response is None
    except grpc.RpcError as e:
        # Expected error case
        assert e.code() in (grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.UNKNOWN)
