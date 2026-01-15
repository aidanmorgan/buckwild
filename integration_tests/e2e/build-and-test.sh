#!/bin/bash
set -euo pipefail

# Helper script to build daemon and run E2E file transfer tests
# Should be run from the devcontainer at /workspace

WORKSPACE_ROOT="/workspace"
E2E_DIR="/workspace/integration_tests/e2e"
BUILD_OUTPUT="${E2E_DIR}/build/linux-arm64"

echo "=== Building Buckwild Daemon for E2E Tests ==="

# Check we're in the right location
if [ ! -f "${WORKSPACE_ROOT}/Cargo.toml" ]; then
    echo "ERROR: Must be run from workspace root"
    echo "Current directory: $(pwd)"
    exit 1
fi

cd "$WORKSPACE_ROOT"

# Build the daemon
echo "Building buckwild-daemon (release mode)..."
cargo build --release --bin buckwild-daemon

# Create output directory
mkdir -p "$BUILD_OUTPUT"

# Determine target architecture
if [ -f "target/release/buckwild-daemon" ]; then
    TARGET_DIR="target/release"
elif [ -f "target/aarch64-unknown-linux-gnu/release/buckwild-daemon" ]; then
    TARGET_DIR="target/aarch64-unknown-linux-gnu/release"
elif [ -f "target/x86_64-unknown-linux-gnu/release/buckwild-daemon" ]; then
    TARGET_DIR="target/x86_64-unknown-linux-gnu/release"
else
    echo "ERROR: Could not find buckwild-daemon binary"
    ls -la target/release/ 2>/dev/null || echo "target/release/ not found"
    exit 1
fi

# Copy binary
echo "Copying binary from ${TARGET_DIR}..."
cp "${TARGET_DIR}/buckwild-daemon" "$BUILD_OUTPUT/"
chmod +x "${BUILD_OUTPUT}/buckwild-daemon"

echo "✓ Binary copied to: ${BUILD_OUTPUT}/buckwild-daemon"

# Verify binary
echo ""
echo "Binary info:"
file "${BUILD_OUTPUT}/buckwild-daemon"
ls -lh "${BUILD_OUTPUT}/buckwild-daemon"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Next steps:"
echo "1. Exit devcontainer or open new terminal on host"
echo "2. cd integration_tests/e2e"
echo "3. ./scripts/run-all-file-transfer-tests.sh"
echo ""
echo "Or to run a single topology:"
echo "  docker-compose -f docker-compose.2-node.yml up -d"
echo "  docker-compose -f docker-compose.2-node.yml run --rm test-runner /scripts/file-transfer-test.sh 2-node"
echo "  docker-compose -f docker-compose.2-node.yml down"
