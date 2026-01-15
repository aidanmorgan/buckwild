#!/bin/bash
set -euo pipefail

# File Transfer E2E Test Script
# Tests file transfers through buckwild protocol with various sizes
# Verifies network isolation and collects comprehensive metrics

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_FILE="${RESULTS_FILE:-/tmp/file_transfer_results.txt}"
TEST_DATA_DIR="/tmp/test_files"

# Test file sizes in bytes
declare -A FILE_SIZES=(
    ["128KB"]=131072
    ["512KB"]=524288
    ["1MB"]=1048576
    ["5MB"]=5242880
    ["10MB"]=10485760
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Generate test file of specified size
generate_test_file() {
    local size=$1
    local filename=$2

    log_info "Generating test file: $filename ($size bytes)"
    dd if=/dev/urandom of="$filename" bs=1024 count=$((size / 1024)) 2>/dev/null

    # Calculate SHA256 checksum
    sha256sum "$filename" | awk '{print $1}'
}

# Convert file to base64 for JSON transport
encode_file() {
    local filename=$1
    base64 -w 0 "$filename"
}

# Initiate file transfer via HTTP POST
initiate_transfer() {
    local source_node=$1
    local target_node=$2
    local input_file=$3
    local transfer_id=$4

    # Build JSON payload using jq to avoid argument list too long error
    local payload_file="/tmp/transfer_payload_${transfer_id}.json"

    # Use jq to properly construct JSON with file content
    jq -n \
        --arg target "$target_node" \
        --arg data "$(base64 -w 0 "$input_file")" \
        --arg id "$transfer_id" \
        '{target: $target, data: $data, transfer_id: $id}' > "$payload_file"

    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "@${payload_file}" \
        "http://${source_node}:8080/transfer"

    rm -f "$payload_file"
}

# Check transfer status
check_transfer_status() {
    local node=$1
    local transfer_id=$2

    curl -s "http://${node}:8080/transfer/${transfer_id}"
}

# Get received data from target node
get_received_data() {
    local node=$1
    local transfer_id=$2

    curl -s "http://${node}:8080/received/${transfer_id}"
}

# Wait for transfer to complete
wait_for_transfer() {
    local node=$1
    local transfer_id=$2
    local timeout=${3:-60}

    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local status=$(check_transfer_status "$node" "$transfer_id")
        local completed=$(echo "$status" | jq -r '.completed // false')

        if [ "$completed" = "true" ]; then
            echo "$status"
            return 0
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "Transfer $transfer_id timed out after ${timeout}s"
    return 1
}

# Verify checksum of received data
verify_transfer() {
    local target_node=$1
    local transfer_id=$2
    local expected_checksum=$3

    log_info "Verifying transfer $transfer_id on $target_node"

    local received=$(get_received_data "$target_node" "$transfer_id")

    if echo "$received" | jq -e '.error' >/dev/null 2>&1; then
        log_error "No data received: $(echo "$received" | jq -r '.error')"
        return 1
    fi

    local actual_checksum=$(echo "$received" | jq -r '.checksum')
    local bytes_received=$(echo "$received" | jq -r '.total_bytes')
    local chunks_received=$(echo "$received" | jq -r '.chunks_received')

    log_info "Received: $bytes_received bytes in $chunks_received chunks"
    log_info "Expected checksum: $expected_checksum"
    log_info "Actual checksum:   $actual_checksum"

    if [ "$actual_checksum" = "$expected_checksum" ]; then
        log_success "✓ Checksum verified"
        return 0
    else
        log_error "✗ Checksum mismatch!"
        return 1
    fi
}

# Get node health metrics
get_node_health() {
    local node=$1
    curl -s "http://${node}:8080/health"
}

# Test network isolation by attempting non-buckwild communication
test_network_isolation() {
    local node=$1

    log_info "Testing network isolation for $node"

    # Try to ping (should fail - ICMP blocked)
    if timeout 2 docker exec "$node" ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "✗ ICMP ping succeeded (should be blocked)"
        return 1
    else
        log_success "✓ ICMP blocked"
    fi

    # Try TCP connection to external host (should fail)
    if timeout 2 docker exec "$node" nc -zv 8.8.8.8 80 >/dev/null 2>&1; then
        log_error "✗ External TCP connection succeeded (should be blocked)"
        return 1
    else
        log_success "✓ External TCP blocked"
    fi

    # Health endpoint should work (localhost)
    if curl -sf "http://${node}:8080/health" >/dev/null; then
        log_success "✓ Health endpoint accessible"
    else
        log_error "✗ Health endpoint not accessible"
        return 1
    fi

    return 0
}

# Run single file transfer test
run_transfer_test() {
    local source_node=$1
    local target_node=$2
    local size_name=$3
    local size_bytes=$4

    log_info "========================================"
    log_info "Testing: $source_node → $target_node ($size_name)"
    log_info "========================================"

    # Generate test file
    local test_file="${TEST_DATA_DIR}/${size_name}_${source_node}_${target_node}.bin"
    local checksum=$(generate_test_file "$size_bytes" "$test_file")

    # Encode file
    log_info "Encoding file to base64..."
    local data_b64=$(encode_file "$test_file")

    # Create transfer ID
    local transfer_id="${source_node}_to_${target_node}_${size_name}_$(date +%s)"

    # Get initial metrics
    local health_before=$(get_node_health "$source_node")
    local packets_sent_before=$(echo "$health_before" | jq -r '.packets_sent')
    local port_hops_before=$(echo "$health_before" | jq -r '.port_hops')

    # Initiate transfer
    log_info "Initiating transfer..."
    local start_time=$(date +%s.%N)
    local init_response=$(initiate_transfer "$source_node" "$target_node" "$data_b64" "$transfer_id")

    if ! echo "$init_response" | jq -e '.status' >/dev/null 2>&1; then
        log_error "Failed to initiate transfer: $init_response"
        return 1
    fi

    log_success "Transfer initiated: $transfer_id"

    # Wait for completion
    log_info "Waiting for transfer to complete..."
    if ! wait_for_transfer "$source_node" "$transfer_id" 120; then
        return 1
    fi

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)

    # Get final metrics
    local health_after=$(get_node_health "$source_node")
    local packets_sent_after=$(echo "$health_after" | jq -r '.packets_sent')
    local port_hops_after=$(echo "$health_after" | jq -r '.port_hops')
    local hmac_verified=$(echo "$health_after" | jq -r '.hmac_verified')

    local packets_used=$((packets_sent_after - packets_sent_before))
    local port_hops=$((port_hops_after - port_hops_before))

    # Wait a moment for receiver to process all chunks
    sleep 2

    # Verify on receiver
    if ! verify_transfer "$target_node" "$transfer_id" "$checksum"; then
        return 1
    fi

    # Calculate throughput
    local throughput_kbps=$(echo "scale=2; ($size_bytes / 1024) / $elapsed" | bc)
    local throughput_mbps=$(echo "scale=2; $throughput_kbps / 1024" | bc)

    # Record results
    echo "${source_node},${target_node},${size_name},${size_bytes},${elapsed},${throughput_kbps},${packets_used},${port_hops},${hmac_verified},PASS" >> "$RESULTS_FILE"

    log_success "Transfer completed successfully!"
    log_info "  Size: $size_bytes bytes"
    log_info "  Time: ${elapsed}s"
    log_info "  Throughput: ${throughput_kbps} KB/s (${throughput_mbps} MB/s)"
    log_info "  Packets: $packets_used"
    log_info "  Port hops: $port_hops"
    log_info "  HMAC verifications: $hmac_verified"

    return 0
}

# Main test execution
main() {
    log_info "=== Buckwild File Transfer E2E Tests ==="

    # Parse arguments
    local topology="${1:-2-node}"

    # Create test data directory
    mkdir -p "$TEST_DATA_DIR"

    # Initialize results file
    echo "Source,Target,Size,Bytes,Time(s),Throughput(KB/s),Packets,PortHops,HMAC,Status" > "$RESULTS_FILE"

    # Define node pairs based on topology
    declare -a NODE_PAIRS

    case "$topology" in
        "2-node")
            NODE_PAIRS=("node-a:node-b" "node-b:node-a")
            ;;
        "3-node")
            NODE_PAIRS=("node-a:node-b" "node-b:node-c" "node-c:node-a")
            ;;
        "4-node")
            NODE_PAIRS=("node-a:node-b" "node-b:node-c" "node-c:node-d" "node-d:node-a")
            ;;
        "5-node")
            NODE_PAIRS=("node-a:node-b" "node-b:node-c" "node-c:node-d" "node-d:node-e" "node-e:node-a")
            ;;
        *)
            log_error "Unknown topology: $topology"
            exit 1
            ;;
    esac

    log_info "Testing topology: $topology"
    log_info "Node pairs: ${#NODE_PAIRS[@]}"

    # Test network isolation first
    log_info ""
    log_info "=== Testing Network Isolation ==="
    for pair in "${NODE_PAIRS[@]}"; do
        local source_node="${pair%%:*}"
        if ! test_network_isolation "$source_node"; then
            log_error "Network isolation test failed for $source_node"
            exit 1
        fi
    done
    log_success "All network isolation tests passed"

    # Run transfer tests for each size
    local total_tests=0
    local passed_tests=0

    for size_name in "${!FILE_SIZES[@]}"; do
        local size_bytes=${FILE_SIZES[$size_name]}

        for pair in "${NODE_PAIRS[@]}"; do
            local source_node="${pair%%:*}"
            local target_node="${pair##*:}"

            total_tests=$((total_tests + 1))

            if run_transfer_test "$source_node" "$target_node" "$size_name" "$size_bytes"; then
                passed_tests=$((passed_tests + 1))
            else
                log_error "Test failed: $source_node → $target_node ($size_name)"
            fi

            # Small delay between tests
            sleep 2
        done
    done

    # Summary
    log_info ""
    log_info "=== Test Summary ==="
    log_info "Total tests: $total_tests"
    log_info "Passed: $passed_tests"
    log_info "Failed: $((total_tests - passed_tests))"
    log_info "Results saved to: $RESULTS_FILE"

    if [ $passed_tests -eq $total_tests ]; then
        log_success "All tests passed!"
        return 0
    else
        log_error "Some tests failed"
        return 1
    fi
}

# Run main function
main "$@"
