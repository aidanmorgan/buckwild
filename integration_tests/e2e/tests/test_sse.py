"""SSE (Server-Sent Events) protocol tests for E2E testing.

Tests SSE functionality including event streaming, named events,
reconnection, and long-lived connections.
"""

import asyncio
import pytest
import aiohttp


@pytest.fixture
async def sse_server():
    """Start an SSE server for testing.

    Yields:
        Server info dict with host, port, and URL

    Note: This fixture assumes the SSE server container is running.
    In actual E2E tests, the server should be started via docker-compose.
    """
    server_info = {
        "host": "localhost",
        "port": 8766,
        "base_url": "http://localhost:8766"
    }
    yield server_info


async def read_sse_events(url: str, max_events: int = 10, timeout: float = 10.0):
    """Read SSE events from a URL.

    Args:
        url: SSE endpoint URL
        max_events: Maximum number of events to read
        timeout: Total timeout for reading events

    Returns:
        List of event dictionaries with 'id', 'event', and 'data' fields
    """
    events = []
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            assert response.status == 200
            assert response.headers.get('Content-Type') == 'text/event-stream'

            current_event = {}
            async for line in response.content:
                line = line.decode('utf-8').rstrip('\n\r')

                if not line:
                    if current_event:
                        events.append(current_event)
                        current_event = {}
                        if len(events) >= max_events:
                            break
                    continue

                if ':' in line:
                    field, value = line.split(':', 1)
                    value = value.lstrip()
                    current_event[field] = value

            if current_event:
                events.append(current_event)

    return events


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_connection(sse_server):
    """Test establishing an SSE connection.

    Verifies that SSE connections can be established and
    the correct content type is returned.
    """
    url = f"{sse_server['base_url']}/events"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                assert response.status == 200
                assert response.headers.get('Content-Type') == 'text/event-stream'
                assert response.headers.get('Cache-Control') == 'no-cache'
    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_receive_events(sse_server):
    """Test receiving multiple SSE events.

    Verifies that multiple events can be received in order
    from an SSE stream.
    """
    url = f"{sse_server['base_url']}/events"

    try:
        events = await read_sse_events(url, max_events=5, timeout=10.0)

        assert len(events) >= 5, f"Expected at least 5 events, got {len(events)}"

        for i, event in enumerate(events[:5]):
            assert 'data' in event, f"Event {i} missing data field"
            assert 'id' in event, f"Event {i} missing id field"

        event_ids = [int(event['id']) for event in events if 'id' in event]
        assert len(event_ids) == len(set(event_ids)), "Event IDs should be unique"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_event_types(sse_server):
    """Test SSE named events with types.

    Verifies that SSE streams can send named events with
    the 'event:' field and that different event types are
    correctly distinguished.
    """
    url = f"{sse_server['base_url']}/events/typed"

    try:
        events = await read_sse_events(url, max_events=10, timeout=10.0)

        assert len(events) >= 3, f"Expected at least 3 typed events, got {len(events)}"

        event_types = [event.get('event') for event in events if 'event' in event]
        assert len(event_types) > 0, "Should have events with event type field"

        assert 'heartbeat' in event_types or 'message' in event_types or 'update' in event_types, \
            f"Expected known event types, got: {event_types}"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_reconnection(sse_server):
    """Test SSE reconnection with Last-Event-ID.

    Verifies that SSE clients can reconnect after disconnect
    by sending the Last-Event-ID header.
    """
    url = f"{sse_server['base_url']}/events"

    try:
        events_first = await read_sse_events(url, max_events=3, timeout=5.0)
        assert len(events_first) >= 1, "Should receive at least one event in first connection"

        last_event_id = events_first[-1].get('id', '0')

        headers = {'Last-Event-ID': last_event_id}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                assert response.status == 200

                first_event = None
                async for line in response.content:
                    line = line.decode('utf-8').rstrip('\n\r')
                    if line.startswith('data:'):
                        first_event = line.split(':', 1)[1].lstrip()
                        break

                assert first_event is not None, "Should receive at least one event after reconnect"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_long_lived(sse_server):
    """Test SSE connection survives for extended time.

    Verifies that SSE connections can remain open for
    multiple seconds and continue receiving events.
    """
    url = f"{sse_server['base_url']}/events/periodic?duration=10&interval=0.5"

    try:
        start_time = asyncio.get_event_loop().time()
        events = await read_sse_events(url, max_events=15, timeout=15.0)
        elapsed = asyncio.get_event_loop().time() - start_time

        assert len(events) >= 5, f"Expected at least 5 events, got {len(events)}"
        assert elapsed >= 2.0, f"Connection should last at least 2 seconds, lasted {elapsed:.2f}s"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_concurrent(sse_server):
    """Test multiple concurrent SSE connections.

    Verifies that the server can handle multiple SSE clients
    connected simultaneously.
    """
    url = f"{sse_server['base_url']}/events"

    async def read_events(client_id: int):
        """Read events for a single client.

        Args:
            client_id: Unique client identifier

        Returns:
            Tuple of (client_id, events)
        """
        try:
            events = await read_sse_events(url, max_events=3, timeout=10.0)
            return client_id, events
        except Exception as e:
            return client_id, []

    try:
        tasks = [read_events(i) for i in range(3)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_clients = 0
        for client_id, events in results:
            if isinstance(events, list) and len(events) >= 1:
                successful_clients += 1

        assert successful_clients >= 2, \
            f"Expected at least 2 successful concurrent connections, got {successful_clients}"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_event_ordering(sse_server):
    """Test that SSE events arrive in correct order.

    Verifies that events are received in the order they
    were sent, as guaranteed by SSE protocol.
    """
    url = f"{sse_server['base_url']}/events"

    try:
        events = await read_sse_events(url, max_events=5, timeout=10.0)

        assert len(events) >= 3, f"Expected at least 3 events, got {len(events)}"

        event_ids = [int(event['id']) for event in events if 'id' in event]
        assert len(event_ids) >= 3, "Should have at least 3 events with IDs"

        for i in range(len(event_ids) - 1):
            assert event_ids[i] < event_ids[i+1], \
                f"Events should be in order: {event_ids[i]} should be < {event_ids[i+1]}"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_health_check(sse_server):
    """Test SSE server health check endpoint.

    Verifies that the health check endpoint returns
    correct status information.
    """
    url = f"{sse_server['base_url']}/health"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                assert response.status == 200
                data = await response.json()

                assert 'status' in data
                assert data['status'] == 'healthy'
                assert 'active_connections' in data
                assert 'event_counter' in data

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")


@pytest.mark.e2e
@pytest.mark.sse
@pytest.mark.asyncio
async def test_sse_event_id_persistence(sse_server):
    """Test that event IDs persist across connections.

    Verifies that the server maintains a global event counter
    and doesn't reset IDs for each new connection.
    """
    url = f"{sse_server['base_url']}/events"

    try:
        events1 = await read_sse_events(url, max_events=2, timeout=5.0)
        assert len(events1) >= 1, "First connection should receive events"
        first_max_id = max(int(e['id']) for e in events1 if 'id' in e)

        events2 = await read_sse_events(url, max_events=2, timeout=5.0)
        assert len(events2) >= 1, "Second connection should receive events"
        second_min_id = min(int(e['id']) for e in events2 if 'id' in e)

        assert second_min_id > first_max_id, \
            f"Event IDs should continue from previous connection: {second_min_id} should be > {first_max_id}"

    except (aiohttp.ClientError, OSError) as e:
        pytest.skip(f"SSE server not available: {e}")
