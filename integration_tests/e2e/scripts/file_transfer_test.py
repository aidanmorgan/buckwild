#!/usr/bin/env python3
"""
Buckwild File Transfer E2E Test

Validates packet fragmentation and reassembly by:
1. Picking random file sizes from a fixed list
2. Picking random source and target nodes
3. Sending file to source node, which forwards to target via TUN/buckwild
4. Verifying SHA256 matches to confirm integrity

The file transfer goes through the buckwild protocol because:
- Source node forwards to target node's TUN IP (10.0.0.x)
- Routing table directs TUN IPs through the TUN interface
- Buckwild daemon encapsulates traffic in its UDP protocol
- Target daemon decapsulates and injects into TUN
"""

import argparse
import hashlib
import http.client
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from typing import Optional


# Fixed list of file sizes to test
FILE_SIZES = {
    "1KB": 1024,
    "4KB": 4 * 1024,
    "8KB": 8 * 1024,
    "16KB": 16 * 1024,
    "32KB": 32 * 1024,
    "64KB": 64 * 1024,
    "128KB": 128 * 1024,
    "256KB": 256 * 1024,
    "512KB": 512 * 1024,
    "1MB": 1024 * 1024,
    "2MB": 2 * 1024 * 1024,
    "5MB": 5 * 1024 * 1024,
}

FILE_SERVER_PORT = 8081
CHUNK_SIZE = 8192


@dataclass
class TransferResult:
    """Result of a file transfer test."""
    source_node: str
    target_node: str
    size_name: str
    size_bytes: int
    success: bool
    duration_seconds: float
    expected_sha256: str
    local_sha256: Optional[str]
    remote_sha256: Optional[str]
    error: Optional[str] = None


def send_transfer_request(
    source_node: str,
    target_node: str,
    data: bytes,
    timeout: int = 120,
) -> dict:
    """
    Send file to source node with instruction to forward to target.

    The source node will forward via TUN IP, routing through buckwild.
    """
    conn = http.client.HTTPConnection(source_node, FILE_SERVER_PORT, timeout=timeout)

    try:
        conn.putrequest("POST", f"/transfer?target={target_node}")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Content-Type", "application/octet-stream")
        conn.endheaders()

        # Send in chunks
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + CHUNK_SIZE]
            chunk_header = f"{len(chunk):x}\r\n".encode()
            conn.send(chunk_header)
            conn.send(chunk)
            conn.send(b"\r\n")
            offset += len(chunk)

        conn.send(b"0\r\n\r\n")

        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError(f"Server returned {response.status}: {response.reason}")

        body = response.read().decode()
        return json.loads(body)

    finally:
        conn.close()


def check_node_health(host: str, port: int) -> bool:
    """Check if a node's file server is healthy."""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/health")
        response = conn.getresponse()
        conn.close()
        return response.status == 200
    except Exception:
        return False


def run_single_transfer(
    source_node: str,
    target_node: str,
    size_name: str,
    size_bytes: int,
    verbose: bool = True,
) -> TransferResult:
    """Run a single file transfer test via buckwild."""
    if verbose:
        print(f"\n{'='*60}")
        print(f"Transfer: {source_node} -> {target_node} ({size_name})")
        print(f"{'='*60}")

    # Generate random test data
    data = os.urandom(size_bytes)
    expected_sha256 = hashlib.sha256(data).hexdigest()

    if verbose:
        print(f"  Generated {size_bytes} bytes")
        print(f"  Expected SHA256: {expected_sha256[:16]}...")

    start_time = time.time()

    try:
        if verbose:
            print(f"  Sending to {source_node} for forwarding to {target_node}...")

        result = send_transfer_request(source_node, target_node, data)
        duration = time.time() - start_time

        local_sha256 = result.get("local_sha256")
        remote_sha256 = result.get("remote_sha256")
        transfer_success = result.get("transfer_success", False)

        if verbose:
            print(f"  Local SHA256:  {local_sha256[:16] if local_sha256 else 'N/A'}...")
            print(f"  Remote SHA256: {remote_sha256[:16] if remote_sha256 else 'N/A'}...")

        # Verify local storage matched
        if local_sha256 != expected_sha256:
            if verbose:
                print(f"  FAILED: Local SHA256 mismatch!")
            return TransferResult(
                source_node=source_node,
                target_node=target_node,
                size_name=size_name,
                size_bytes=size_bytes,
                success=False,
                duration_seconds=duration,
                expected_sha256=expected_sha256,
                local_sha256=local_sha256,
                remote_sha256=remote_sha256,
                error="Local SHA256 mismatch",
            )

        # Verify remote storage matched
        if remote_sha256 != expected_sha256:
            if verbose:
                print(f"  FAILED: Remote SHA256 mismatch!")
                print(f"    Expected: {expected_sha256}")
                print(f"    Remote:   {remote_sha256}")
            return TransferResult(
                source_node=source_node,
                target_node=target_node,
                size_name=size_name,
                size_bytes=size_bytes,
                success=False,
                duration_seconds=duration,
                expected_sha256=expected_sha256,
                local_sha256=local_sha256,
                remote_sha256=remote_sha256,
                error="Remote SHA256 mismatch - buckwild transfer corrupted data",
            )

        # Success
        throughput_kbps = (size_bytes / 1024) / duration if duration > 0 else 0
        if verbose:
            print(f"  SUCCESS! Data transferred correctly via buckwild")
            print(f"    Duration: {duration:.3f}s")
            print(f"    Throughput: {throughput_kbps:.2f} KB/s")

        return TransferResult(
            source_node=source_node,
            target_node=target_node,
            size_name=size_name,
            size_bytes=size_bytes,
            success=True,
            duration_seconds=duration,
            expected_sha256=expected_sha256,
            local_sha256=local_sha256,
            remote_sha256=remote_sha256,
        )

    except Exception as e:
        duration = time.time() - start_time
        if verbose:
            print(f"  FAILED: {e}")
        return TransferResult(
            source_node=source_node,
            target_node=target_node,
            size_name=size_name,
            size_bytes=size_bytes,
            success=False,
            duration_seconds=duration,
            expected_sha256=expected_sha256,
            local_sha256=None,
            remote_sha256=None,
            error=str(e),
        )


def get_topology_nodes(topology: str) -> list[str]:
    """Get list of nodes for a topology."""
    topologies = {
        "2-node": ["node-a", "node-b"],
        "3-node": ["node-a", "node-b", "node-c"],
        "4-node": ["node-a", "node-b", "node-c", "node-d"],
        "5-node": ["node-a", "node-b", "node-c", "node-d", "node-e"],
    }
    if topology not in topologies:
        raise ValueError(f"Unknown topology: {topology}. Valid: {list(topologies.keys())}")
    return topologies[topology]


def run_random_tests(
    nodes: list[str],
    num_tests: int,
    size_filter: Optional[list[str]] = None,
    verbose: bool = True,
) -> list[TransferResult]:
    """
    Run random file transfer tests through buckwild.

    Picks random source/target node pairs and file sizes.
    """
    if len(nodes) < 2:
        raise ValueError("Need at least 2 nodes for transfer tests")

    # Filter sizes if specified
    if size_filter:
        available_sizes = [(name, size) for name, size in FILE_SIZES.items() if name in size_filter]
    else:
        available_sizes = list(FILE_SIZES.items())

    if not available_sizes:
        raise ValueError("No valid sizes available")

    results = []

    for i in range(num_tests):
        # Pick random size
        size_name, size_bytes = random.choice(available_sizes)

        # Pick random source and target (must be different)
        source_node = random.choice(nodes)
        target_candidates = [n for n in nodes if n != source_node]
        target_node = random.choice(target_candidates)

        if verbose:
            print(f"\n[Test {i+1}/{num_tests}]")

        result = run_single_transfer(source_node, target_node, size_name, size_bytes, verbose)
        results.append(result)

        # Small delay between tests
        time.sleep(0.5)

    return results


def print_summary(results: list[TransferResult]):
    """Print test summary."""
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")

    passed = sum(1 for r in results if r.success)
    failed = len(results) - passed
    total_bytes = sum(r.size_bytes for r in results if r.success)
    total_duration = sum(r.duration_seconds for r in results if r.success)

    print(f"\nTotal tests: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if total_duration > 0:
        avg_throughput = (total_bytes / 1024) / total_duration
        print(f"Total transferred: {total_bytes / 1024:.2f} KB")
        print(f"Average throughput: {avg_throughput:.2f} KB/s")

    # Group by size
    print(f"\nResults by size:")
    size_results = {}
    for r in results:
        if r.size_name not in size_results:
            size_results[r.size_name] = {"passed": 0, "failed": 0}
        if r.success:
            size_results[r.size_name]["passed"] += 1
        else:
            size_results[r.size_name]["failed"] += 1

    for size_name in sorted(size_results.keys(), key=lambda x: FILE_SIZES.get(x, 0)):
        stats = size_results[size_name]
        print(f"  {size_name}: {stats['passed']} passed, {stats['failed']} failed")

    # Group by route
    print(f"\nResults by route:")
    route_results = {}
    for r in results:
        route = f"{r.source_node} -> {r.target_node}"
        if route not in route_results:
            route_results[route] = {"passed": 0, "failed": 0}
        if r.success:
            route_results[route]["passed"] += 1
        else:
            route_results[route]["failed"] += 1

    for route in sorted(route_results.keys()):
        stats = route_results[route]
        print(f"  {route}: {stats['passed']} passed, {stats['failed']} failed")

    if failed > 0:
        print(f"\nFailed tests:")
        for r in results:
            if not r.success:
                print(f"  {r.source_node} -> {r.target_node} ({r.size_name}): {r.error}")


def main():
    parser = argparse.ArgumentParser(
        description="Buckwild File Transfer E2E Test - validates packet fragmentation/reassembly via TUN"
    )
    parser.add_argument(
        "topology",
        choices=["2-node", "3-node", "4-node", "5-node"],
        help="Network topology to test",
    )
    parser.add_argument(
        "-n", "--num-tests",
        type=int,
        default=10,
        help="Number of random tests to run (default: 10)",
    )
    parser.add_argument(
        "--sizes",
        help="Comma-separated list of sizes to use (default: all). Example: 1KB,32KB,1MB",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick test: 5 tests with small sizes only (1KB-32KB)",
    )
    parser.add_argument(
        "--stress",
        action="store_true",
        help="Stress test: 50 tests with all sizes",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only show summary",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    # Set random seed if specified
    if args.seed is not None:
        random.seed(args.seed)
        print(f"Using random seed: {args.seed}")

    # Determine test parameters
    if args.quick:
        num_tests = 5
        size_filter = ["1KB", "4KB", "8KB", "16KB", "32KB"]
    elif args.stress:
        num_tests = 50
        size_filter = None
    else:
        num_tests = args.num_tests
        size_filter = args.sizes.split(",") if args.sizes else None

    verbose = not args.quiet

    print(f"\n{'='*60}")
    print("Buckwild File Transfer E2E Test")
    print("Data travels: test-runner -> source -> (TUN/buckwild) -> target")
    print(f"{'='*60}")
    print(f"Topology: {args.topology}")
    print(f"Number of tests: {num_tests}")
    print(f"Sizes: {size_filter if size_filter else 'all'}")

    nodes = get_topology_nodes(args.topology)
    print(f"Nodes: {nodes}")

    # Check node health
    print(f"\nChecking node health...")
    healthy_nodes = []
    for node in nodes:
        if check_node_health(node, FILE_SERVER_PORT):
            print(f"  {node}: HEALTHY")
            healthy_nodes.append(node)
        else:
            print(f"  {node}: UNREACHABLE")

    if len(healthy_nodes) < 2:
        print("\nERROR: Need at least 2 healthy nodes for transfer tests!")
        sys.exit(1)

    if len(healthy_nodes) < len(nodes):
        print(f"\nWARNING: Only {len(healthy_nodes)}/{len(nodes)} nodes are healthy")
        print(f"Continuing with healthy nodes: {healthy_nodes}")

    # Run tests
    results = run_random_tests(healthy_nodes, num_tests, size_filter, verbose)

    # Print summary
    print_summary(results)

    # Exit with error if any tests failed
    failed = sum(1 for r in results if not r.success)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
