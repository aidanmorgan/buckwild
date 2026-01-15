#!/bin/bash
# Health endpoint test script
# This script verifies that the health and ready endpoints work correctly

set -e

HEALTH_URL="${HEALTH_URL:-http://localhost:8080/health}"
READY_URL="${READY_URL:-http://localhost:8080/ready}"

echo "Testing health endpoint..."
if curl -s "$HEALTH_URL" | jq -e '.status == "healthy"'; then
    echo "✓ Health endpoint returns healthy status"
else
    echo "✗ Health endpoint test failed"
    exit 1
fi

if curl -s "$HEALTH_URL" | jq -e '.version'; then
    echo "✓ Health endpoint returns version"
else
    echo "✗ Health endpoint missing version"
    exit 1
fi

if curl -s "$HEALTH_URL" | jq -e '.uptime_secs >= 0'; then
    echo "✓ Health endpoint returns uptime"
else
    echo "✗ Health endpoint missing uptime"
    exit 1
fi

echo ""
echo "Testing ready endpoint..."
if curl -s "$READY_URL" | jq -e 'has("ready")'; then
    echo "✓ Ready endpoint returns ready field"
else
    echo "✗ Ready endpoint missing ready field"
    exit 1
fi

echo ""
echo "All tests passed!"
