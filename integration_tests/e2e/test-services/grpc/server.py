#!/usr/bin/env python3
"""gRPC test service implementation for E2E protocol testing."""

import asyncio
import logging
import time
from concurrent import futures

import grpc
from grpc_reflection.v1alpha import reflection

import test_service_pb2
import test_service_pb2_grpc


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestServiceServicer(test_service_pb2_grpc.TestServiceServicer):
    """Implementation of TestService."""

    def Echo(self, request, context):
        """Unary RPC: echo back the message with timestamp."""
        logger.info(f"Echo received: {request.message}")
        return test_service_pb2.EchoResponse(
            message=request.message,
            timestamp=int(time.time() * 1000)
        )

    def StreamNumbers(self, request, context):
        """Server streaming: send a stream of numbers."""
        logger.info(f"StreamNumbers: count={request.count}, delay_ms={request.delay_ms}")

        for i in range(request.count):
            if context.is_active():
                yield test_service_pb2.NumberResponse(number=i)
                if request.delay_ms > 0 and i < request.count - 1:
                    time.sleep(request.delay_ms / 1000.0)
            else:
                logger.warning("Client disconnected during stream")
                break

    def AccumulateNumbers(self, request_iterator, context):
        """Client streaming: accumulate numbers from client stream."""
        total = 0
        count = 0

        for request in request_iterator:
            total += request.number
            count += 1
            logger.debug(f"Received number: {request.number}, running total: {total}")

        logger.info(f"AccumulateNumbers complete: sum={total}, count={count}")
        return test_service_pb2.AccumulateResponse(sum=total, count=count)

    def Chat(self, request_iterator, context):
        """Bidirectional streaming: echo chat messages back."""
        logger.info("Chat session started")

        for message in request_iterator:
            logger.info(f"Chat message from {message.sender}: {message.message}")

            # Echo back with server timestamp
            yield test_service_pb2.ChatMessage(
                sender="server",
                message=f"Echo: {message.message}",
                timestamp=int(time.time() * 1000)
            )

        logger.info("Chat session ended")


async def serve():
    """Start the gRPC server."""
    server = grpc.aio.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ('grpc.max_send_message_length', 50 * 1024 * 1024),
            ('grpc.max_receive_message_length', 50 * 1024 * 1024),
        ]
    )

    test_service_pb2_grpc.add_TestServiceServicer_to_server(
        TestServiceServicer(), server
    )

    # Enable server reflection for debugging
    SERVICE_NAMES = (
        test_service_pb2.DESCRIPTOR.services_by_name['TestService'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)

    listen_addr = '[::]:50051'
    server.add_insecure_port(listen_addr)

    logger.info(f"Starting gRPC server on {listen_addr}")
    await server.start()
    logger.info("gRPC server ready")

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down gRPC server")
        await server.stop(grace=5)


if __name__ == '__main__':
    asyncio.run(serve())
