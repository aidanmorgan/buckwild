"""HTTP file transfer tests.

These tests verify that file transfers work correctly through the VPN tunnel.
Each test runs for a configurable duration (default 30s), randomly selecting
nodes and operations (upload/download), and asserting that SHA256 hashes match.
"""

import os
import random
import time

import pytest

# Import from parent directory
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from conftest import TransferStats, get_test_duration
from framework.transfer_client import (
    NODE_PORTS,
    check_node_health,
    trigger_download,
    trigger_upload,
)

# File size range: 1KB to 10MB
MIN_SIZE = 1024
MAX_SIZE = 10 * 1024 * 1024


def random_size() -> int:
    """Generate random file size between 1KB and 10MB."""
    return random.randint(MIN_SIZE, MAX_SIZE)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_continuous_transfer_2node(stats: TransferStats):
    """Run random node-to-node transfers for configured duration on 2-node topology."""
    nodes = ["node-a", "node-b"]
    duration = get_test_duration()

    # Verify nodes are healthy (skip if not available)
    for node in nodes:
        if not await check_node_health(node):
            pytest.skip(f"Node {node} not available (port {NODE_PORTS[node]})")

    print(f"\nRunning 2-node transfer test for {duration} seconds...")
    start = time.monotonic()
    iteration = 0

    while time.monotonic() - start < duration:
        iteration += 1

        # Random source and target (must be different)
        source = random.choice(nodes)
        target = random.choice([n for n in nodes if n != source])
        size = random_size()
        operation = random.choice(["upload", "download"])

        if operation == "upload":
            result = await trigger_upload(source, target, size)

            assert result.success, f"Upload {source}→{target} failed: {result.error}"
            assert result.hashes_match(), (
                f"SHA256 MISMATCH on upload {source}→{target}: "
                f"source={result.source_sha256[:16]}... "
                f"target={result.target_sha256[:16]}..."
            )

            stats.record_upload(result.size_bytes, result.duration_ms, result.success)
            print(f"  [{iteration}] Upload {source}→{target}: {size/1024:.1f}KB in {result.duration_ms}ms ✓")

        else:
            result = await trigger_download(source, target, size)

            assert result.success, f"Download {source}←{target} failed: {result.error}"
            assert result.hashes_match(), (
                f"SHA256 MISMATCH on download {source}←{target}: "
                f"server={result.source_sha256[:16]}... "
                f"computed={result.target_sha256[:16]}..."
            )

            stats.record_download(result.size_bytes, result.duration_ms, result.success)
            print(f"  [{iteration}] Download {source}←{target}: {size/1024:.1f}KB in {result.duration_ms}ms ✓")

    stats.print_summary()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_continuous_transfer_3node(stats: TransferStats):
    """Run random node-to-node transfers for configured duration on 3-node topology."""
    nodes = ["node-a", "node-b", "node-c"]
    duration = get_test_duration()

    # Verify nodes are healthy
    available_nodes = []
    for node in nodes:
        if await check_node_health(node):
            available_nodes.append(node)

    if len(available_nodes) < 2:
        pytest.skip(f"Need at least 2 nodes, only {len(available_nodes)} available")

    print(f"\nRunning 3-node transfer test for {duration} seconds with {len(available_nodes)} nodes...")
    start = time.monotonic()
    iteration = 0

    while time.monotonic() - start < duration:
        iteration += 1

        source = random.choice(available_nodes)
        target = random.choice([n for n in available_nodes if n != source])
        size = random_size()
        operation = random.choice(["upload", "download"])

        if operation == "upload":
            result = await trigger_upload(source, target, size)

            assert result.success, f"Upload {source}→{target} failed: {result.error}"
            assert result.hashes_match(), (
                f"SHA256 MISMATCH on upload {source}→{target}: "
                f"source={result.source_sha256[:16]}... "
                f"target={result.target_sha256[:16]}..."
            )

            stats.record_upload(result.size_bytes, result.duration_ms, result.success)

        else:
            result = await trigger_download(source, target, size)

            assert result.success, f"Download {source}←{target} failed: {result.error}"
            assert result.hashes_match(), (
                f"SHA256 MISMATCH on download {source}←{target}: "
                f"server={result.source_sha256[:16]}... "
                f"computed={result.target_sha256[:16]}..."
            )

            stats.record_download(result.size_bytes, result.duration_ms, result.success)

    stats.print_summary()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_continuous_transfer_5node(stats: TransferStats):
    """Run random node-to-node transfers for configured duration on 5-node topology."""
    nodes = ["node-a", "node-b", "node-c", "node-d", "node-e"]
    duration = get_test_duration()

    # Verify nodes are healthy
    available_nodes = []
    for node in nodes:
        if await check_node_health(node):
            available_nodes.append(node)

    if len(available_nodes) < 2:
        pytest.skip(f"Need at least 2 nodes, only {len(available_nodes)} available")

    print(f"\nRunning 5-node transfer test for {duration} seconds with {len(available_nodes)} nodes...")
    start = time.monotonic()
    iteration = 0

    while time.monotonic() - start < duration:
        iteration += 1

        source = random.choice(available_nodes)
        target = random.choice([n for n in available_nodes if n != source])
        size = random_size()
        operation = random.choice(["upload", "download"])

        if operation == "upload":
            result = await trigger_upload(source, target, size)

            assert result.success, f"Upload {source}→{target} failed: {result.error}"
            assert result.hashes_match(), (
                f"SHA256 MISMATCH on upload {source}→{target}: "
                f"source={result.source_sha256[:16]}... "
                f"target={result.target_sha256[:16]}..."
            )

            stats.record_upload(result.size_bytes, result.duration_ms, result.success)

        else:
            result = await trigger_download(source, target, size)

            assert result.success, f"Download {source}←{target} failed: {result.error}"
            assert result.hashes_match(), (
                f"SHA256 MISMATCH on download {source}←{target}: "
                f"server={result.source_sha256[:16]}... "
                f"computed={result.target_sha256[:16]}..."
            )

            stats.record_download(result.size_bytes, result.duration_ms, result.success)

    stats.print_summary()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_upload_specific_sizes():
    """Test uploads with specific file sizes to verify fragmentation handling."""
    nodes = ["node-a", "node-b"]

    # Verify nodes are healthy
    for node in nodes:
        if not await check_node_health(node):
            pytest.skip(f"Node {node} not available")

    # Test specific sizes that exercise fragmentation boundaries
    sizes = [
        1024,           # 1KB - single packet
        8 * 1024,       # 8KB - typical MTU boundary
        64 * 1024,      # 64KB - larger transfer
        256 * 1024,     # 256KB - multi-packet
        1024 * 1024,    # 1MB - significant transfer
    ]

    for size in sizes:
        result = await trigger_upload("node-a", "node-b", size)

        assert result.success, f"Upload of {size} bytes failed: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch for {size} bytes: "
            f"source={result.source_sha256[:16]}..., "
            f"target={result.target_sha256[:16]}..."
        )
        print(f"  Upload {size/1024:.0f}KB: {result.duration_ms}ms ✓")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_download_specific_sizes():
    """Test downloads with specific file sizes to verify fragmentation handling."""
    nodes = ["node-a", "node-b"]

    # Verify nodes are healthy
    for node in nodes:
        if not await check_node_health(node):
            pytest.skip(f"Node {node} not available")

    # Test specific sizes
    sizes = [
        1024,           # 1KB
        8 * 1024,       # 8KB
        64 * 1024,      # 64KB
        256 * 1024,     # 256KB
        1024 * 1024,    # 1MB
    ]

    for size in sizes:
        result = await trigger_download("node-a", "node-b", size)

        assert result.success, f"Download of {size} bytes failed: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch for {size} bytes: "
            f"server={result.source_sha256[:16]}..., "
            f"computed={result.target_sha256[:16]}..."
        )
        print(f"  Download {size/1024:.0f}KB: {result.duration_ms}ms ✓")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_bidirectional_transfers():
    """Test simultaneous transfers in both directions."""
    nodes = ["node-a", "node-b"]

    # Verify nodes are healthy
    for node in nodes:
        if not await check_node_health(node):
            pytest.skip(f"Node {node} not available")

    size = 100 * 1024  # 100KB

    # A uploads to B
    result_ab = await trigger_upload("node-a", "node-b", size)
    assert result_ab.success, f"A→B failed: {result_ab.error}"
    assert result_ab.hashes_match(), "A→B hash mismatch"

    # B uploads to A
    result_ba = await trigger_upload("node-b", "node-a", size)
    assert result_ba.success, f"B→A failed: {result_ba.error}"
    assert result_ba.hashes_match(), "B→A hash mismatch"

    print(f"  A→B: {result_ab.duration_ms}ms, B→A: {result_ba.duration_ms}ms ✓")
