"""SSE (Server-Sent Events) server for E2E testing.

This server provides Server-Sent Events endpoints for testing
long-lived connections, event streaming, and reconnection behavior.
"""

import asyncio
import logging
import signal
import sys
import time
from typing import Optional

from aiohttp import web


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SSEServer:
    """SSE server that streams events to connected clients."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8766):
        """Initialize the SSE server.

        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.active_connections: set[web.StreamResponse] = set()
        self.event_counter = 0

        self.app.router.add_get("/events", self.handle_events)
        self.app.router.add_get("/events/typed", self.handle_typed_events)
        self.app.router.add_get("/events/periodic", self.handle_periodic_events)
        self.app.router.add_get("/health", self.handle_health)

    async def handle_events(self, request: web.Request) -> web.StreamResponse:
        """Handle basic SSE connection that sends events on demand.

        Args:
            request: HTTP request

        Returns:
            StreamResponse with SSE events
        """
        response = web.StreamResponse()
        response.headers['Content-Type'] = 'text/event-stream'
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['Connection'] = 'keep-alive'
        response.headers['Access-Control-Allow-Origin'] = '*'

        await response.prepare(request)
        self.active_connections.add(response)

        client_id = f"{request.remote}"
        logger.info(f"SSE client connected: {client_id}")

        try:
            last_event_id = request.headers.get('Last-Event-ID')
            if last_event_id:
                logger.info(f"Client {client_id} reconnecting from event {last_event_id}")
                await response.write(f"data: Reconnected from event {last_event_id}\n\n".encode())

            for i in range(10):
                self.event_counter += 1
                event_id = self.event_counter
                message = f"id: {event_id}\ndata: Event {i+1} at {time.time()}\n\n"
                await response.write(message.encode())
                await asyncio.sleep(0.1)

            await response.write(b"data: Stream complete\n\n")
            await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            logger.info(f"SSE client {client_id} connection cancelled")
        except Exception as e:
            logger.error(f"Error handling SSE connection from {client_id}: {e}", exc_info=True)
        finally:
            self.active_connections.discard(response)
            logger.info(f"SSE client {client_id} disconnected. Active: {len(self.active_connections)}")

        return response

    async def handle_typed_events(self, request: web.Request) -> web.StreamResponse:
        """Handle SSE connection that sends named event types.

        Args:
            request: HTTP request

        Returns:
            StreamResponse with typed SSE events
        """
        response = web.StreamResponse()
        response.headers['Content-Type'] = 'text/event-stream'
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['Connection'] = 'keep-alive'
        response.headers['Access-Control-Allow-Origin'] = '*'

        await response.prepare(request)
        self.active_connections.add(response)

        client_id = f"{request.remote}"
        logger.info(f"SSE typed client connected: {client_id}")

        try:
            events = [
                ("heartbeat", "ping"),
                ("message", "Hello from SSE"),
                ("update", "Status: OK"),
                ("heartbeat", "pong"),
                ("message", "Another message"),
            ]

            for event_type, data in events:
                self.event_counter += 1
                event_id = self.event_counter
                message = f"id: {event_id}\nevent: {event_type}\ndata: {data}\n\n"
                await response.write(message.encode())
                await asyncio.sleep(0.1)

            await response.write(b"event: complete\ndata: Stream finished\n\n")
            await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            logger.info(f"SSE typed client {client_id} connection cancelled")
        except Exception as e:
            logger.error(f"Error handling typed SSE connection from {client_id}: {e}", exc_info=True)
        finally:
            self.active_connections.discard(response)
            logger.info(f"SSE typed client {client_id} disconnected. Active: {len(self.active_connections)}")

        return response

    async def handle_periodic_events(self, request: web.Request) -> web.StreamResponse:
        """Handle SSE connection that sends events periodically for extended time.

        Args:
            request: HTTP request

        Returns:
            StreamResponse with periodic SSE events
        """
        response = web.StreamResponse()
        response.headers['Content-Type'] = 'text/event-stream'
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['Connection'] = 'keep-alive'
        response.headers['Access-Control-Allow-Origin'] = '*'

        await response.prepare(request)
        self.active_connections.add(response)

        client_id = f"{request.remote}"
        logger.info(f"SSE periodic client connected: {client_id}")

        try:
            duration = int(request.query.get('duration', '30'))
            interval = float(request.query.get('interval', '1.0'))

            start_time = time.time()
            event_num = 0

            while (time.time() - start_time) < duration:
                event_num += 1
                self.event_counter += 1
                event_id = self.event_counter
                elapsed = time.time() - start_time
                message = f"id: {event_id}\ndata: Event {event_num} at {elapsed:.2f}s\n\n"
                await response.write(message.encode())
                await asyncio.sleep(interval)

            await response.write(b"data: Periodic stream complete\n\n")
            await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            logger.info(f"SSE periodic client {client_id} connection cancelled")
        except Exception as e:
            logger.error(f"Error handling periodic SSE connection from {client_id}: {e}", exc_info=True)
        finally:
            self.active_connections.discard(response)
            logger.info(f"SSE periodic client {client_id} disconnected. Active: {len(self.active_connections)}")

        return response

    async def handle_health(self, request: web.Request) -> web.Response:
        """Handle health check requests.

        Args:
            request: HTTP request

        Returns:
            JSON response with server status
        """
        return web.json_response({
            "status": "healthy",
            "active_connections": len(self.active_connections),
            "event_counter": self.event_counter,
        })

    async def start(self) -> None:
        """Start the SSE server."""
        logger.info(f"Starting SSE server on {self.host}:{self.port}")

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

        logger.info(f"SSE server listening on http://{self.host}:{self.port}")
        logger.info("Available endpoints:")
        logger.info("  GET /events - Basic SSE stream")
        logger.info("  GET /events/typed - SSE stream with named events")
        logger.info("  GET /events/periodic - Long-lived periodic SSE stream")
        logger.info("  GET /health - Health check")

    async def stop(self) -> None:
        """Stop the SSE server."""
        if self.runner:
            logger.info("Stopping SSE server")
            await self.runner.cleanup()
            logger.info("SSE server stopped")


async def main() -> None:
    """Main entry point for the SSE server."""
    server = SSEServer(host="0.0.0.0", port=8766)

    shutdown_event = asyncio.Event()

    def signal_handler() -> None:
        logger.info("Received shutdown signal")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    try:
        await server.start()
        await shutdown_event.wait()
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        await server.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
