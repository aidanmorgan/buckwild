#!/bin/sh
set -e

# Usage: wait-for-healthy.sh <hostname>
# Polls health endpoint until 200 or timeout
# 30s timeout accommodates Rust daemon crypto initialization (5-10s) with margin for slow CI

if [ -z "$1" ]; then
    echo "ERROR: hostname required" >&2
    echo "Usage: $0 <hostname>" >&2
    exit 1
fi

HOST="$1"
HEALTH_URL="http://${HOST}:8080/health"
TIMEOUT=30
INTERVAL=1
ELAPSED=0

echo "Waiting for ${HOST} to become healthy (timeout: ${TIMEOUT}s)..."

while [ $ELAPSED -lt $TIMEOUT ]; do
    if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
        echo "✓ ${HOST} is healthy (after ${ELAPSED}s)"
        exit 0
    fi

    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))

    if [ $((ELAPSED % 5)) -eq 0 ]; then
        echo "  Still waiting for ${HOST}... (${ELAPSED}s elapsed)"
    fi
done

echo "ERROR: ${HOST} failed to become healthy within ${TIMEOUT}s" >&2
exit 1
