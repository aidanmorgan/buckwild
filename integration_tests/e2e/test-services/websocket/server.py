"""WebSocket echo server for E2E testing.

This server echoes back all text and binary messages it receives,
supports ping/pong frames, and maintains persistent connections.
"""

import asyncio
import logging
import signal
import sys
from typing import Optional

import websockets
from websockets.server import WebSocketServerProtocol


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WebSocketEchoServer:
    """WebSocket echo server that handles text and binary messages."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        """Initialize the WebSocket echo server.

        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.server: Optional[websockets.server.WebSocketServer] = None
        self.active_connections: set[WebSocketServerProtocol] = set()

    async def handle_connection(self, websocket: WebSocketServerProtocol) -> None:
        """Handle a WebSocket connection.

        Args:
            websocket: WebSocket connection protocol
        """
        client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        logger.info(f"Client connected: {client_id}")
        self.active_connections.add(websocket)

        try:
            async for message in websocket:
                if isinstance(message, str):
                    logger.debug(f"Received text message from {client_id}: {message[:100]}")
                    await websocket.send(message)
                elif isinstance(message, bytes):
                    logger.debug(f"Received binary message from {client_id}: {len(message)} bytes")
                    await websocket.send(message)
                else:
                    logger.warning(f"Received unexpected message type from {client_id}: {type(message)}")

        except websockets.exceptions.ConnectionClosed as e:
            logger.info(f"Client {client_id} disconnected: {e.code} {e.reason}")
        except Exception as e:
            logger.error(f"Error handling connection from {client_id}: {e}", exc_info=True)
        finally:
            self.active_connections.discard(websocket)
            logger.info(f"Client {client_id} connection closed. Active: {len(self.active_connections)}")

    async def start(self) -> None:
        """Start the WebSocket server."""
        logger.info(f"Starting WebSocket echo server on {self.host}:{self.port}")

        self.server = await websockets.serve(
            self.handle_connection,
            self.host,
            self.port,
            ping_interval=20,
            ping_timeout=20,
        )

        logger.info(f"WebSocket server listening on ws://{self.host}:{self.port}")
        logger.info("Server ready to accept connections")

    async def stop(self) -> None:
        """Stop the WebSocket server."""
        if self.server:
            logger.info("Stopping WebSocket server")
            self.server.close()
            await self.server.wait_closed()
            logger.info("WebSocket server stopped")

    async def wait_closed(self) -> None:
        """Wait for the server to be closed."""
        if self.server:
            await self.server.wait_closed()


async def main() -> None:
    """Main entry point for the WebSocket echo server."""
    server = WebSocketEchoServer(host="0.0.0.0", port=8765)

    loop = asyncio.get_event_loop()

    shutdown_event = asyncio.Event()

    def signal_handler() -> None:
        logger.info("Received shutdown signal")
        shutdown_event.set()

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
