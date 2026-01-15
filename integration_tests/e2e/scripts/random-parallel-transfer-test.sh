#!/bin/bash
set -euo pipefail

# Random Parallel File Transfer E2E Test Script
# - Randomized file sizes from defined list
# - Random source/target node pairs
# - Up to 5 concurrent transfers per node
# - Runs for a configurable duration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_FILE="${RESULTS_FILE:-/tmp/random_transfer_results.txt}"
TEST_DATA_DIR="/tmp/test_files"
TRANSFER_LOG="/tmp/active_transfers.log"

# Test parameters
MAX_TRANSFERS_PER_NODE=5
TEST_DURATION_SECS=${TEST_DURATION_SECS:-120}
POLL_INTERVAL=2

# Test file sizes in bytes
FILE_SIZES=("131072" "524288" "1048576" "5242880" "10485760")
FILE_SIZE_NAMES=("128KB" "512KB" "1MB" "5MB" "10MB")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_transfer() { echo -e "${CYAN}[TRANSFER]${NC} $*"; }

# Node list will be populated based on topology
declare -a NODES

# Track active transfers per node: node -> count
declare -A ACTIVE_OUTGOING
declare -A ACTIVE_INCOMING

# Track all active transfer IDs
declare -a ACTIVE_TRANSFERS
declare -A TRANSFER_INFO  # transfer_id -> "source:target:size:start_time"

# Statistics
TOTAL_INITIATED=0
TOTAL_COMPLETED=0
TOTAL_FAILED=0
TOTAL_BYTES_TRANSFERRED=0

# Generate random test file
generate_random_file() {
    local size=$1
    local filename=$2
    dd if=/dev/urandom of="$filename" bs=1024 count=$((size / 1024)) 2>/dev/null
    sha256sum "$filename" | awk '{print $1}'
}

# Get random element from array
random_element() {
    local arr=("$@")
    local idx=$((RANDOM % ${#arr[@]}))
    echo "${arr[$idx]}"
}

# Get random file size
random_file_size() {
    local idx=$((RANDOM % ${#FILE_SIZES[@]}))
    echo "${FILE_SIZES[$idx]}:${FILE_SIZE_NAMES[$idx]}"
}

# Get random target node (different from source)
random_target_node() {
    local source=$1
    local target
    while true; do
        target=$(random_element "${NODES[@]}")
        if [ "$target" != "$source" ]; then
            echo "$target"
            return
        fi
    done
}

# Check if node can accept more outgoing transfers
can_start_outgoing() {
    local node=$1
    local count=${ACTIVE_OUTGOING[$node]:-0}
    [ "$count" -lt "$MAX_TRANSFERS_PER_NODE" ]
}

# Check if node can accept more incoming transfers
can_accept_incoming() {
    local node=$1
    local count=${ACTIVE_INCOMING[$node]:-0}
    [ "$count" -lt "$MAX_TRANSFERS_PER_NODE" ]
}

# Initiate a transfer
initiate_transfer() {
    local source=$1
    local target=$2
    local size_bytes=$3
    local size_name=$4
    local transfer_id=$5
    local data_b64=$6

    local json_payload="{\"target\":\"${target}\",\"data\":\"${data_b64}\",\"transfer_id\":\"${transfer_id}\"}"

    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "http://${source}:8080/transfer" 2>/dev/null || echo '{"error":"connection failed"}'
}

# Check transfer status
check_transfer_status() {
    local node=$1
    local transfer_id=$2
    curl -s "http://${node}:8080/transfer/${transfer_id}" 2>/dev/null || echo '{"completed":false}'
}

# Verify transfer checksum
verify_transfer() {
    local target=$1
    local transfer_id=$2
    local expected_checksum=$3

    local received=$(curl -s "http://${target}:8080/received/${transfer_id}" 2>/dev/null)
    local actual_checksum=$(echo "$received" | jq -r '.checksum // "none"')

    if [ "$actual_checksum" = "$expected_checksum" ]; then
        return 0
    else
        return 1
    fi
}

# Start a new random transfer
start_random_transfer() {
    # Pick random source node that can send
    local eligible_sources=()
    for node in "${NODES[@]}"; do
        if can_start_outgoing "$node"; then
            eligible_sources+=("$node")
        fi
    done

    if [ ${#eligible_sources[@]} -eq 0 ]; then
        return 1  # No nodes can send
    fi

    local source=$(random_element "${eligible_sources[@]}")

    # Pick random target that can receive (and is different from source)
    local eligible_targets=()
    for node in "${NODES[@]}"; do
        if [ "$node" != "$source" ] && can_accept_incoming "$node"; then
            eligible_targets+=("$node")
        fi
    done

    if [ ${#eligible_targets[@]} -eq 0 ]; then
        return 1  # No nodes can receive
    fi

    local target=$(random_element "${eligible_targets[@]}")

    # Pick random file size
    local size_info=$(random_file_size)
    local size_bytes="${size_info%%:*}"
    local size_name="${size_info##*:}"

    # Generate transfer ID
    local transfer_id="${source}_${target}_${size_name}_$$_$RANDOM"

    # Generate test file
    local test_file="${TEST_DATA_DIR}/${transfer_id}.bin"
    local checksum=$(generate_random_file "$size_bytes" "$test_file")

    # Encode to base64
    local data_b64=$(base64 -w 0 "$test_file")

    # Record start time
    local start_time=$(date +%s)

    log_transfer "Starting: $source -> $target ($size_name, $size_bytes bytes)"

    # Initiate transfer
    local response=$(initiate_transfer "$source" "$target" "$size_bytes" "$size_name" "$transfer_id" "$data_b64")

    if echo "$response" | jq -e '.status' >/dev/null 2>&1; then
        # Update counters
        ACTIVE_OUTGOING[$source]=$((${ACTIVE_OUTGOING[$source]:-0} + 1))
        ACTIVE_INCOMING[$target]=$((${ACTIVE_INCOMING[$target]:-0} + 1))

        # Track transfer
        ACTIVE_TRANSFERS+=("$transfer_id")
        TRANSFER_INFO[$transfer_id]="$source:$target:$size_bytes:$size_name:$checksum:$start_time:$test_file"

        TOTAL_INITIATED=$((TOTAL_INITIATED + 1))

        log_success "Initiated: $transfer_id (active: ${#ACTIVE_TRANSFERS[@]})"
        return 0
    else
        log_error "Failed to initiate transfer: $response"
        rm -f "$test_file"
        return 1
    fi
}

# Check and process completed transfers
check_completed_transfers() {
    local new_active=()

    for transfer_id in "${ACTIVE_TRANSFERS[@]}"; do
        local info="${TRANSFER_INFO[$transfer_id]}"
        IFS=':' read -r source target size_bytes size_name checksum start_time test_file <<< "$info"

        local status=$(check_transfer_status "$source" "$transfer_id")
        local completed=$(echo "$status" | jq -r '.completed // false')

        if [ "$completed" = "true" ]; then
            local end_time=$(date +%s)
            local elapsed=$((end_time - start_time))

            # Verify checksum (wait a moment for receiver to process)
            sleep 1
            if verify_transfer "$target" "$transfer_id" "$checksum"; then
                local throughput_kbps=$((size_bytes / 1024 / (elapsed + 1)))
                log_success "Completed: $transfer_id ($size_name in ${elapsed}s, ${throughput_kbps} KB/s)"
                TOTAL_COMPLETED=$((TOTAL_COMPLETED + 1))
                TOTAL_BYTES_TRANSFERRED=$((TOTAL_BYTES_TRANSFERRED + size_bytes))

                # Record to results
                echo "$source,$target,$size_name,$size_bytes,$elapsed,$throughput_kbps,PASS" >> "$RESULTS_FILE"
            else
                log_error "Checksum mismatch: $transfer_id"
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
                echo "$source,$target,$size_name,$size_bytes,$elapsed,0,FAIL-CHECKSUM" >> "$RESULTS_FILE"
            fi

            # Update counters
            ACTIVE_OUTGOING[$source]=$((${ACTIVE_OUTGOING[$source]:-1} - 1))
            ACTIVE_INCOMING[$target]=$((${ACTIVE_INCOMING[$target]:-1} - 1))

            # Clean up test file
            rm -f "$test_file"

            # Remove from TRANSFER_INFO
            unset TRANSFER_INFO[$transfer_id]
        else
            # Still active
            new_active+=("$transfer_id")
        fi
    done

    ACTIVE_TRANSFERS=("${new_active[@]+"${new_active[@]}"}")
}

# Print current status
print_status() {
    local elapsed=$1
    local remaining=$((TEST_DURATION_SECS - elapsed))

    echo ""
    log_info "=== Status (${elapsed}s elapsed, ${remaining}s remaining) ==="
    log_info "Active transfers: ${#ACTIVE_TRANSFERS[@]}"
    log_info "Initiated: $TOTAL_INITIATED | Completed: $TOTAL_COMPLETED | Failed: $TOTAL_FAILED"

    # Per-node status
    echo -n "  Per-node (out/in): "
    for node in "${NODES[@]}"; do
        echo -n "$node(${ACTIVE_OUTGOING[$node]:-0}/${ACTIVE_INCOMING[$node]:-0}) "
    done
    echo ""
}

# Get node health metrics
get_final_metrics() {
    log_info ""
    log_info "=== Final Node Metrics ==="

    for node in "${NODES[@]}"; do
        local health=$(curl -s "http://${node}:8080/health" 2>/dev/null || echo '{}')
        local packets_sent=$(echo "$health" | jq -r '.packets_sent // 0')
        local packets_recv=$(echo "$health" | jq -r '.packets_received // 0')
        local bytes_sent=$(echo "$health" | jq -r '.bytes_sent // 0')
        local bytes_recv=$(echo "$health" | jq -r '.bytes_received // 0')
        local port_hops=$(echo "$health" | jq -r '.port_hops // 0')
        local hmac_verified=$(echo "$health" | jq -r '.hmac_verified // 0')
        local hmac_failed=$(echo "$health" | jq -r '.hmac_failed // 0')

        log_info "$node:"
        log_info "  Packets: sent=$packets_sent recv=$packets_recv"
        log_info "  Bytes: sent=$bytes_sent recv=$bytes_recv"
        log_info "  Port hops: $port_hops"
        log_info "  HMAC: verified=$hmac_verified failed=$hmac_failed"
    done
}

# Main test loop
main() {
    local topology="${1:-3-node}"

    log_info "=== Random Parallel Transfer E2E Test ==="
    log_info "Topology: $topology"
    log_info "Max transfers per node: $MAX_TRANSFERS_PER_NODE"
    log_info "Test duration: ${TEST_DURATION_SECS}s"

    # Set up nodes based on topology
    case "$topology" in
        "2-node") NODES=("node-a" "node-b") ;;
        "3-node") NODES=("node-a" "node-b" "node-c") ;;
        "4-node") NODES=("node-a" "node-b" "node-c" "node-d") ;;
        "5-node") NODES=("node-a" "node-b" "node-c" "node-d" "node-e") ;;
        *) log_error "Unknown topology: $topology"; exit 1 ;;
    esac

    log_info "Nodes: ${NODES[*]}"
    log_info "File sizes: ${FILE_SIZE_NAMES[*]}"

    # Initialize
    mkdir -p "$TEST_DATA_DIR"
    echo "Source,Target,Size,Bytes,Time(s),Throughput(KB/s),Status" > "$RESULTS_FILE"

    for node in "${NODES[@]}"; do
        ACTIVE_OUTGOING[$node]=0
        ACTIVE_INCOMING[$node]=0
    done

    # Wait for all nodes to be healthy
    log_info "Waiting for nodes to be healthy..."
    for node in "${NODES[@]}"; do
        local attempts=0
        while ! curl -sf "http://${node}:8080/health" >/dev/null 2>&1; do
            attempts=$((attempts + 1))
            if [ $attempts -gt 30 ]; then
                log_error "Node $node not healthy after 30s"
                exit 1
            fi
            sleep 1
        done
        log_success "$node is healthy"
    done

    # Main test loop
    local start_time=$(date +%s)
    local last_status=0

    log_info ""
    log_info "=== Starting Transfer Test ==="

    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        # Check if test is complete
        if [ $elapsed -ge $TEST_DURATION_SECS ]; then
            log_info "Test duration reached"
            break
        fi

        # Check completed transfers
        check_completed_transfers

        # Start new transfers if possible (try to keep nodes busy)
        local started=0
        for _ in $(seq 1 3); do  # Try to start up to 3 new transfers per cycle
            if start_random_transfer; then
                started=$((started + 1))
            fi
        done

        # Print status every 10 seconds
        if [ $((elapsed - last_status)) -ge 10 ]; then
            print_status $elapsed
            last_status=$elapsed
        fi

        # Small delay
        sleep $POLL_INTERVAL
    done

    # Wait for remaining transfers to complete
    log_info ""
    log_info "=== Waiting for remaining transfers to complete ==="
    local wait_start=$(date +%s)
    local max_wait=60

    while [ ${#ACTIVE_TRANSFERS[@]} -gt 0 ]; do
        local wait_elapsed=$(($(date +%s) - wait_start))
        if [ $wait_elapsed -ge $max_wait ]; then
            log_warn "Timeout waiting for ${#ACTIVE_TRANSFERS[@]} transfers"
            TOTAL_FAILED=$((TOTAL_FAILED + ${#ACTIVE_TRANSFERS[@]}))
            break
        fi

        check_completed_transfers
        log_info "Waiting for ${#ACTIVE_TRANSFERS[@]} transfers..."
        sleep 2
    done

    # Get final metrics
    get_final_metrics

    # Summary
    log_info ""
    log_info "========================================="
    log_info "=== Final Summary ==="
    log_info "========================================="
    log_info "Total initiated: $TOTAL_INITIATED"
    log_info "Total completed: $TOTAL_COMPLETED"
    log_info "Total failed: $TOTAL_FAILED"
    log_info "Total bytes transferred: $TOTAL_BYTES_TRANSFERRED"

    local total_mb=$((TOTAL_BYTES_TRANSFERRED / 1048576))
    local avg_throughput=0
    if [ $TOTAL_COMPLETED -gt 0 ]; then
        avg_throughput=$((TOTAL_BYTES_TRANSFERRED / 1024 / TEST_DURATION_SECS))
    fi
    log_info "Total data transferred: ${total_mb} MB"
    log_info "Average throughput: ${avg_throughput} KB/s"

    log_info ""
    log_info "Results saved to: $RESULTS_FILE"

    # Clean up
    rm -rf "$TEST_DATA_DIR"

    if [ $TOTAL_FAILED -eq 0 ] && [ $TOTAL_COMPLETED -gt 0 ]; then
        log_success "All transfers completed successfully!"
        return 0
    elif [ $TOTAL_COMPLETED -gt 0 ]; then
        log_warn "Some transfers failed"
        return 1
    else
        log_error "No transfers completed"
        return 1
    fi
}

main "$@"
