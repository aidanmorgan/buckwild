#!/bin/bash
# Generate unique PSKs for each peer-to-peer connection
# Each node pair (alphabetically sorted) gets a unique PSK file

set -e

PSK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../psk" && pwd)"

echo "Generating per-peer PSKs in $PSK_DIR"

# Remove old shared PSK if it exists
rm -f "$PSK_DIR/shared.psk"

# Generate PSK for a pair of nodes (alphabetically sorted)
generate_psk() {
    local node1=$1
    local node2=$2

    # Sort nodes alphabetically to ensure consistent naming
    if [[ "$node1" > "$node2" ]]; then
        local temp=$node1
        node1=$node2
        node2=$temp
    fi

    local psk_file="$PSK_DIR/${node1}-${node2}.psk"

    # Generate 32 random bytes and convert to hex
    openssl rand -hex 32 > "$psk_file"

    echo "Generated: ${node1}-${node2}.psk"
}

# Generate PSKs for all peer pairs in each topology

# 2-node topology: a-b
echo "=== 2-node topology ==="
generate_psk "node-a" "node-b"

# 3-node topology: a-b, a-c, b-c
echo "=== 3-node topology ==="
generate_psk "node-a" "node-c"
generate_psk "node-b" "node-c"

# 4-node topology: all pairs between a,b,c,d
echo "=== 4-node topology ==="
generate_psk "node-a" "node-d"
generate_psk "node-b" "node-d"
generate_psk "node-c" "node-d"

# 5-node topology: all pairs between a,b,c,d,e
echo "=== 5-node topology ==="
generate_psk "node-a" "node-e"
generate_psk "node-b" "node-e"
generate_psk "node-c" "node-e"
generate_psk "node-d" "node-e"

echo ""
echo "PSK generation complete!"
echo "Generated files:"
ls -1 "$PSK_DIR"/*.psk | sort
