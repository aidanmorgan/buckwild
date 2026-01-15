#!/usr/bin/env python3
"""
Verify routing configuration for buckwild E2E tests.
"""
import subprocess
import sys
import argparse

# Node to TUN IP mapping
TUN_IPS = {
    "node-a": "10.0.0.1",
    "node-b": "10.0.0.2",
    "node-c": "10.0.0.3",
    "node-d": "10.0.0.4",
    "node-e": "10.0.0.5",
}

# Docker IPs (for blocking verification)
DOCKER_IPS = {
    "node-a": "172.30.0.10",
    "node-b": "172.30.0.11",
    "node-c": "172.30.0.12",
    "node-d": "172.30.0.13",
    "node-e": "172.30.0.14",
}


def exec_in_container(node: str, cmd: str) -> str:
    """Execute command in a node's container."""
    result = subprocess.run(
        ["docker", "exec", node, "bash", "-c", cmd],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {result.stderr}")
    return result.stdout


def verify_tun_exists(node: str) -> bool:
    """Check if TUN interface bw0 exists."""
    try:
        output = exec_in_container(node, "ip link show bw0")
        return "state UP" in output
    except RuntimeError:
        return False


def verify_routes(node: str) -> dict:
    """Verify routes for peer TUN IPs."""
    results = {}
    my_ip = TUN_IPS[node]

    for peer, peer_ip in TUN_IPS.items():
        if peer == node:
            continue

        try:
            output = exec_in_container(node, f"ip route get {peer_ip}")
            # Should contain "dev bw0"
            results[peer] = "dev bw0" in output
        except RuntimeError:
            results[peer] = False

    return results


def get_tun_rx_bytes(node: str) -> int:
    """Get RX bytes counter for bw0 interface."""
    try:
        output = exec_in_container(node, "cat /sys/class/net/bw0/statistics/rx_bytes")
        return int(output.strip())
    except (RuntimeError, ValueError):
        return 0


def get_tun_tx_bytes(node: str) -> int:
    """Get TX bytes counter for bw0 interface."""
    try:
        output = exec_in_container(node, "cat /sys/class/net/bw0/statistics/tx_bytes")
        return int(output.strip())
    except (RuntimeError, ValueError):
        return 0


def verify_all_nodes(nodes: list) -> bool:
    """Verify routing on all nodes."""
    all_passed = True

    for node in nodes:
        print(f"\n=== {node} ===")

        # Check TUN exists
        if verify_tun_exists(node):
            print(f"  ✓ TUN bw0 is UP")
        else:
            print(f"  ✗ TUN bw0 not found or DOWN")
            all_passed = False
            continue

        # Check routes
        routes = verify_routes(node)
        for peer, ok in routes.items():
            if ok:
                print(f"  ✓ Route to {peer} ({TUN_IPS[peer]}) via bw0")
            else:
                print(f"  ✗ Route to {peer} NOT via bw0")
                all_passed = False

        # Check counters
        rx = get_tun_rx_bytes(node)
        tx = get_tun_tx_bytes(node)
        print(f"  TUN stats: RX={rx} bytes, TX={tx} bytes")

    return all_passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify routing configuration for buckwild E2E tests"
    )
    parser.add_argument(
        "topology",
        choices=["2-node", "3-node", "4-node", "5-node"],
        help="Topology to verify"
    )
    args = parser.parse_args()

    topologies = {
        "2-node": ["node-a", "node-b"],
        "3-node": ["node-a", "node-b", "node-c"],
        "4-node": ["node-a", "node-b", "node-c", "node-d"],
        "5-node": ["node-a", "node-b", "node-c", "node-d", "node-e"],
    }

    nodes = topologies[args.topology]
    print(f"Verifying routing for {args.topology}: {nodes}")

    success = verify_all_nodes(nodes)
    sys.exit(0 if success else 1)
