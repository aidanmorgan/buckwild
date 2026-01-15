"""Data transfer tests for 2-node Buckwild VPN.

Tests data transfer between two nodes over the Buckwild tunnel,
verifying integrity using SHA256 checksums and measuring throughput
for various file sizes (1KB to 10MB).
"""

import asyncio
import hashlib
import time
import pytest

from ..framework.ssh import SSHClient


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_transfer_1kb(two_node_cluster):
    """Test transferring 1KB of data with SHA256 verification.

    Generates random data, transfers via netcat over VPN tunnel,
    verifies integrity with SHA256, and measures throughput.
    """
    await _run_transfer_test(two_node_cluster, "1KB", 1024, timeout=30.0)


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_transfer_10kb(two_node_cluster):
    """Test transferring 10KB of data with SHA256 verification."""
    await _run_transfer_test(two_node_cluster, "10KB", 10 * 1024, timeout=30.0)


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_transfer_100kb(two_node_cluster):
    """Test transferring 100KB of data with SHA256 verification."""
    await _run_transfer_test(two_node_cluster, "100KB", 100 * 1024, timeout=45.0)


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_transfer_1mb(two_node_cluster):
    """Test transferring 1MB of data with SHA256 verification."""
    await _run_transfer_test(two_node_cluster, "1MB", 1024 * 1024, timeout=60.0)


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_transfer_5mb(two_node_cluster):
    """Test transferring 5MB of data with SHA256 verification.

    Marked as slow due to transfer duration.
    """
    await _run_transfer_test(two_node_cluster, "5MB", 5 * 1024 * 1024, timeout=120.0)


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_transfer_10mb(two_node_cluster):
    """Test transferring 10MB of data with SHA256 verification.

    Marked as slow due to transfer duration.
    """
    await _run_transfer_test(two_node_cluster, "10MB", 10 * 1024 * 1024, timeout=180.0)


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_bidirectional_transfer(two_node_cluster):
    """Test transferring data in both directions simultaneously.

    Transfers 100KB from node-1 to node-2 and from node-2 to node-1
    at the same time, verifying both transfers complete successfully.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    size_bytes = 100 * 1024
    port1 = 9900
    port2 = 9901

    # Generate test files on both nodes
    result1 = await ssh1.exec_command(
        f"dd if=/dev/urandom of=/tmp/test_fwd.bin bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum /tmp/test_fwd.bin | awk '{{print $1}}'",
        timeout=20.0
    )
    checksum1_expected = result1.stdout.strip()

    result2 = await ssh2.exec_command(
        f"dd if=/dev/urandom of=/tmp/test_rev.bin bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum /tmp/test_rev.bin | awk '{{print $1}}'",
        timeout=20.0
    )
    checksum2_expected = result2.stdout.strip()

    # Start receivers
    receiver1_task = ssh1.exec_command_async(
        f"nc -l -p {port1} > /tmp/received_rev.bin",
        timeout=60.0
    )
    receiver2_task = ssh2.exec_command_async(
        f"nc -l -p {port2} > /tmp/received_fwd.bin",
        timeout=60.0
    )

    # Wait for listeners to be ready
    await asyncio.sleep(2)

    # Send files in both directions simultaneously
    sender1_task = ssh1.exec_command_async(
        f"nc -w 10 10.0.0.2 {port2} < /tmp/test_fwd.bin",
        timeout=45.0
    )
    sender2_task = ssh2.exec_command_async(
        f"nc -w 10 10.0.0.1 {port1} < /tmp/test_rev.bin",
        timeout=45.0
    )

    # Wait for all transfers to complete
    await asyncio.wait_for(asyncio.gather(
        sender1_task,
        sender2_task,
        receiver1_task,
        receiver2_task
    ), timeout=60.0)

    # Verify checksums
    result1_check = await ssh2.exec_command(
        "sha256sum /tmp/received_fwd.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum1_received = result1_check.stdout.strip()

    result2_check = await ssh1.exec_command(
        "sha256sum /tmp/received_rev.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum2_received = result2_check.stdout.strip()

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test_fwd.bin /tmp/received_rev.bin", check=False)
    await ssh2.exec_command("rm -f /tmp/test_rev.bin /tmp/received_fwd.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Assert both transfers succeeded
    assert checksum1_expected == checksum1_received, \
        f"Node1->Node2 checksum mismatch: expected={checksum1_expected}, received={checksum1_received}"
    assert checksum2_expected == checksum2_received, \
        f"Node2->Node1 checksum mismatch: expected={checksum2_expected}, received={checksum2_received}"


async def _run_transfer_test(
    cluster,
    size_name: str,
    size_bytes: int,
    timeout: float
) -> None:
    """Helper function to run a data transfer test.

    Args:
        cluster: Cluster fixture
        size_name: Human-readable size name (e.g., "1KB")
        size_bytes: Size in bytes
        timeout: Transfer timeout in seconds
    """
    node1 = cluster.get_node("node-1")
    node2 = cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    # Generate random test file on node-1 and compute SHA256
    test_file = f"/tmp/test_{size_name.lower()}.bin"
    received_file = f"/tmp/received_{size_name.lower()}.bin"

    _, stdout, _ = await ssh1.exec_command(
        f"dd if=/dev/urandom of={test_file} bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum {test_file} | awk '{{print $1}}'",
        timeout=max(30.0, timeout / 3)
    )
    expected_checksum = stdout.strip()

    # Allocate unique port for this test
    port = 9950 + (size_bytes % 50)

    # Start receiver on node-2
    receiver_task = ssh2.exec_command_async(
        f"nc -l -p {port} > {received_file}",
        timeout=timeout
    )

    # Wait for listener to be ready
    await asyncio.sleep(2)

    # Record start time
    start_time = time.time()

    # Send file from node-1 to node-2's VPN IP
    await ssh1.exec_command(
        f"nc -w 15 10.0.0.2 {port} < {test_file}",
        timeout=timeout - 5,
        check=False
    )

    # Wait for receiver to finish
    await asyncio.wait_for(receiver_task, timeout=timeout / 2)

    # Record end time
    end_time = time.time()
    duration = end_time - start_time

    # Verify checksum on node-2
    _, stdout, _ = await ssh2.exec_command(
        f"sha256sum {received_file} | awk '{{print $1}}'",
        timeout=20.0
    )
    received_checksum = stdout.strip()

    # Calculate throughput
    throughput_mbps = (size_bytes * 8) / (duration * 1_000_000) if duration > 0 else 0
    throughput_kbps = (size_bytes / 1024) / duration if duration > 0 else 0

    # Cleanup
    await ssh1.exec_command(f"rm -f {test_file}", check=False)
    await ssh2.exec_command(f"rm -f {received_file}", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Assert checksum matches
    assert expected_checksum == received_checksum, \
        f"SHA256 mismatch for {size_name}: expected={expected_checksum}, received={received_checksum}"

    # Log throughput for visibility
    print(f"\n{size_name} transfer: {duration:.3f}s, {throughput_kbps:.2f} KB/s ({throughput_mbps:.3f} Mbps)")
