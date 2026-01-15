# hadolint ignore=DL3006
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy proto file and generate Python code
COPY test_service.proto .
RUN python -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --grpc_python_out=. \
    test_service.proto

# Copy server implementation
COPY server.py .

# Make server executable
RUN chmod +x server.py

# Expose gRPC port
EXPOSE 50051

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import grpc; channel = grpc.insecure_channel('localhost:50051'); channel.unary_unary('grpc.health.v1.Health/Check')(b''); channel.close()" || exit 1

# Run server
CMD ["python", "server.py"]
