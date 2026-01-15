"""WebSocket protocol tests for E2E testing.

Tests WebSocket functionality including text/binary message echo,
ping/pong frames, and connection persistence.
"""

import asyncio
import pytest
import websockets


@pytest.fixture
async def websocket_server():
    """Start a WebSocket echo server for testing.

    Yields:
        Server info dict with host and port

    Note: This fixture assumes the WebSocket server container is running.
    In actual E2E tests, the server should be started via docker-compose.
    For unit testing, we mock the server connection.
    """
    server_info = {
        "host": "localhost",
        "port": 8765,
        "url": "ws://localhost:8765"
    }
    yield server_info


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_text_message_echo(websocket_server):
    """Test that text messages are echoed back correctly.

    Verifies that the WebSocket server receives a text message
    and echoes it back unchanged.
    """
    url = websocket_server["url"]
    test_message = "Hello, WebSocket!"

    try:
        async with websockets.connect(url) as websocket:
            await websocket.send(test_message)

            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)

            assert response == test_message
            assert isinstance(response, str)
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_binary_message_echo(websocket_server):
    """Test that binary messages are echoed back correctly.

    Verifies that the WebSocket server receives a binary message
    and echoes it back unchanged.
    """
    url = websocket_server["url"]
    test_data = b"\x00\x01\x02\x03\x04\x05\xff\xfe\xfd"

    try:
        async with websockets.connect(url) as websocket:
            await websocket.send(test_data)

            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)

            assert response == test_data
            assert isinstance(response, bytes)
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_ping_pong_frames(websocket_server):
    """Test WebSocket ping/pong frame handling.

    Verifies that the WebSocket server responds to ping frames
    with pong frames as per the WebSocket protocol.
    """
    url = websocket_server["url"]

    try:
        async with websockets.connect(url) as websocket:
            pong_waiter = await websocket.ping()

            await asyncio.wait_for(pong_waiter, timeout=5.0)

            assert websocket.open
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_connection_persistence(websocket_server):
    """Test that WebSocket connections persist across multiple messages.

    Verifies that a single WebSocket connection can be used to send
    and receive multiple messages without disconnecting.
    """
    url = websocket_server["url"]
    messages = [
        "First message",
        "Second message",
        "Third message",
        "Fourth message",
        "Fifth message",
    ]

    try:
        async with websockets.connect(url) as websocket:
            for original_message in messages:
                await websocket.send(original_message)

                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)

                assert response == original_message

            assert websocket.open
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_multiple_concurrent_connections(websocket_server):
    """Test that the server can handle multiple concurrent connections.

    Verifies that multiple WebSocket clients can connect simultaneously
    and exchange messages independently.
    """
    url = websocket_server["url"]
    num_connections = 5

    async def client_session(client_id: int) -> bool:
        """Single client session that sends and receives a message.

        Args:
            client_id: Unique identifier for this client

        Returns:
            True if the session completed successfully
        """
        try:
            async with websockets.connect(url) as websocket:
                message = f"Message from client {client_id}"
                await websocket.send(message)

                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)

                return response == message
        except Exception:
            return False

    try:
        tasks = [client_session(i) for i in range(num_connections)]
        results = await asyncio.gather(*tasks)

        assert all(results), "All client sessions should succeed"
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_large_message_echo(websocket_server):
    """Test that large messages are echoed correctly.

    Verifies that the WebSocket server can handle messages
    larger than typical frame sizes.
    """
    url = websocket_server["url"]
    large_message = "A" * 100_000

    try:
        async with websockets.connect(url) as websocket:
            await websocket.send(large_message)

            response = await asyncio.wait_for(websocket.recv(), timeout=10.0)

            assert response == large_message
            assert len(response) == 100_000
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_mixed_message_types(websocket_server):
    """Test echoing mixed text and binary messages in sequence.

    Verifies that the server correctly handles alternating
    text and binary messages on the same connection.
    """
    url = websocket_server["url"]

    try:
        async with websockets.connect(url) as websocket:
            text_message = "Text message"
            await websocket.send(text_message)
            response1 = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            assert response1 == text_message
            assert isinstance(response1, str)

            binary_message = b"\x00\x01\x02\x03"
            await websocket.send(binary_message)
            response2 = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            assert response2 == binary_message
            assert isinstance(response2, bytes)

            text_message2 = "Another text message"
            await websocket.send(text_message2)
            response3 = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            assert response3 == text_message2
            assert isinstance(response3, str)
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")


@pytest.mark.e2e
@pytest.mark.websocket
@pytest.mark.asyncio
async def test_connection_close_gracefully(websocket_server):
    """Test that connections can be closed gracefully.

    Verifies that WebSocket connections can be closed cleanly
    using the WebSocket close frame.
    """
    url = websocket_server["url"]

    try:
        websocket = await websockets.connect(url)
        assert websocket.open

        message = "Test before close"
        await websocket.send(message)
        response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
        assert response == message

        await websocket.close()
        await asyncio.sleep(0.1)

        assert not websocket.open
    except (ConnectionRefusedError, OSError) as e:
        pytest.skip(f"WebSocket server not available: {e}")
