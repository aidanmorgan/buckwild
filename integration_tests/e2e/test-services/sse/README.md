# SSE Test Server

Server-Sent Events (SSE) test server for E2E testing.

## Overview

This server provides SSE endpoints for testing long-lived HTTP connections, event streaming, and reconnection behavior in the Buckwild VPN.

## Endpoints

### GET /events

Basic SSE stream that sends 10 events with event IDs and then completes.

**Features:**
- Event IDs for tracking
- Supports Last-Event-ID reconnection header
- Auto-completes after 10 events

**Example:**
```bash
curl -N http://localhost:8766/events
```

### GET /events/typed

SSE stream with named event types (heartbeat, message, update).

**Features:**
- Named events using `event:` field
- Event IDs for tracking
- Multiple event types in single stream

**Example:**
```bash
curl -N http://localhost:8766/events/typed
```

### GET /events/periodic

Long-lived SSE stream that sends events periodically.

**Query Parameters:**
- `duration` - Stream duration in seconds (default: 30)
- `interval` - Interval between events in seconds (default: 1.0)

**Example:**
```bash
curl -N "http://localhost:8766/events/periodic?duration=60&interval=2.0"
```

### GET /health

Health check endpoint that returns server status.

**Response:**
```json
{
  "status": "healthy",
  "active_connections": 2,
  "event_counter": 142
}
```

## SSE Protocol

Server-Sent Events use the `text/event-stream` content type and send events in this format:

```
id: 1
event: message
data: Hello, world!

id: 2
data: Simple event (no event type)

```

Each event ends with a blank line (`\n\n`).

## Reconnection

Clients can reconnect after disconnection by sending the `Last-Event-ID` header. The server will acknowledge the reconnection and continue sending events.

## Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
python server.py
```

Server listens on `http://0.0.0.0:8766`.

## Docker

```bash
# Build
docker build -t sse-server .

# Run
docker run -p 8766:8766 sse-server
```

## Testing

See `integration_tests/e2e/tests/test_sse.py` for test examples.
