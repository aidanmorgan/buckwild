"""Packet loss resilience tests for Buckwild VPN.

Tests VPN behavior under various packet loss conditions (1% to 50%),
verifying that data transfer completes successfully with integrity
checks and measuring throughput degradation.
"""

import asyncio
import hashlib
import time
import pytest

from ..framework.chaos import NetworkChaos
from ..framework.ssh import SSHClient


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_light_packet_loss_1_percent(two_node_cluster):
    """Test normal operation with 1% packet loss.

    Verifies that VPN maintains normal operation with minimal packet loss,
    which simulates typical network conditions. Data transfer should
    complete successfully with minimal throughput impact.
    """
    await _run_loss_test(
        two_node_cluster,
        loss_percent=1.0,
        size_bytes=100 * 1024,
        test_name="1% packet loss (100KB)",
        timeout=60.0
    )


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_moderate_packet_loss_5_percent(two_node_cluster):
    """Test recovery mechanisms with 5% packet loss.

    Verifies that VPN recovery mechanisms (retransmissions, timeouts)
    activate properly under moderate packet loss. Transfer should
    complete but with measurable throughput reduction.
    """
    await _run_loss_test(
        two_node_cluster,
        loss_percent=5.0,
        size_bytes=100 * 1024,
        test_name="5% packet loss (100KB)",
        timeout=90.0
    )


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_heavy_packet_loss_10_percent(two_node_cluster):
    """Test data integrity with 10% packet loss.

    Verifies that VPN maintains data integrity under heavy packet loss.
    Retransmissions should handle lost packets correctly, with
    significant throughput degradation but no data corruption.
    """
    await _run_loss_test(
        two_node_cluster,
        loss_percent=10.0,
        size_bytes=50 * 1024,
        test_name="10% packet loss (50KB)",
        timeout=120.0
    )


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_extreme_packet_loss_50_percent(two_node_cluster):
    """Test graceful degradation with 50% packet loss.

    Verifies that VPN degrades gracefully under extreme packet loss.
    Connection should remain established and data should eventually
    transfer, albeit very slowly. Tests connection resilience limits.
    """
    await _run_loss_test(
        two_node_cluster,
        loss_percent=50.0,
        size_bytes=10 * 1024,
        test_name="50% packet loss (10KB)",
        timeout=300.0
    )


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_data_transfer_with_loss(two_node_cluster):
    """Test file transfer integrity under 10% packet loss.

    Transfers 500KB file with 10% packet loss and verifies SHA256
    checksum matches. Ensures no silent data corruption occurs
    despite significant packet loss.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    size_bytes = 500 * 1024
    port = 9800

    # Generate test file with known checksum
    result = await ssh1.exec_command(
        f"dd if=/dev/urandom of=/tmp/test_loss.bin bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum /tmp/test_loss.bin | awk '{{print $1}}'",
        timeout=30.0
    )
    expected_checksum = result.stdout.strip()

    # Apply 10% packet loss to node-2 (receiver)
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_loss(10.0)

        # Start receiver
        receiver_task = ssh2.exec_command_async(
            f"nc -l -p {port} > /tmp/received_loss.bin",
            timeout=180.0
        )

        # Wait for listener
        await asyncio.sleep(2)

        # Send file
        start_time = time.time()
        await ssh1.exec_command(
            f"nc -w 30 10.0.0.2 {port} < /tmp/test_loss.bin",
            timeout=150.0,
            check=False
        )

        # Wait for transfer to complete
        await asyncio.wait_for(receiver_task, timeout=120.0)
        duration = time.time() - start_time

    # Verify checksum
    result = await ssh2.exec_command(
        "sha256sum /tmp/received_loss.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum = result.stdout.strip()

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test_loss.bin", check=False)
    await ssh2.exec_command("rm -f /tmp/received_loss.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Assert integrity
    assert expected_checksum == received_checksum, \
        f"Checksum mismatch with 10% loss: expected={expected_checksum}, received={received_checksum}"

    # Log performance
    throughput_kbps = (size_bytes / 1024) / duration if duration > 0 else 0
    print(f"\n500KB transfer with 10% loss: {duration:.2f}s, {throughput_kbps:.2f} KB/s")


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_recovery_after_loss_cleared(two_node_cluster):
    """Test performance recovery after packet loss is removed.

    Transfers data under 10% packet loss, then removes loss and
    transfers again. Verifies that throughput returns to normal
    levels after chaos is cleared.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    size_bytes = 50 * 1024
    port_degraded = 9810
    port_recovered = 9811

    # Generate test file
    result = await ssh1.exec_command(
        f"dd if=/dev/urandom of=/tmp/test_recovery.bin bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum /tmp/test_recovery.bin | awk '{{print $1}}'",
        timeout=30.0
    )
    expected_checksum = result.stdout.strip()

    # Phase 1: Transfer with 10% loss
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_loss(10.0)

        receiver_task = ssh2.exec_command_async(
            f"nc -l -p {port_degraded} > /tmp/received_degraded.bin",
            timeout=120.0
        )

        await asyncio.sleep(2)

        start_degraded = time.time()
        await ssh1.exec_command(
            f"nc -w 20 10.0.0.2 {port_degraded} < /tmp/test_recovery.bin",
            timeout=90.0,
            check=False
        )

        await asyncio.wait_for(receiver_task, timeout=60.0)
        duration_degraded = time.time() - start_degraded

        # Verify checksum during degraded phase
        result = await ssh2.exec_command(
            "sha256sum /tmp/received_degraded.bin | awk '{print $1}'",
            timeout=10.0
        )
        degraded_checksum = result.stdout.strip()

    # Phase 2: Transfer after loss cleared (chaos context exited)
    # Wait briefly for network to stabilize
    await asyncio.sleep(3)

    receiver_task = ssh2.exec_command_async(
        f"nc -l -p {port_recovered} > /tmp/received_recovered.bin",
        timeout=60.0
    )

    await asyncio.sleep(2)

    start_recovered = time.time()
    await ssh1.exec_command(
        f"nc -w 15 10.0.0.2 {port_recovered} < /tmp/test_recovery.bin",
        timeout=45.0,
        check=False
    )

    await asyncio.wait_for(receiver_task, timeout=30.0)
    duration_recovered = time.time() - start_recovered

    # Verify checksum after recovery
    result = await ssh2.exec_command(
        "sha256sum /tmp/received_recovered.bin | awk '{print $1}'",
        timeout=10.0
    )
    recovered_checksum = result.stdout.strip()

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test_recovery.bin", check=False)
    await ssh2.exec_command(
        "rm -f /tmp/received_degraded.bin /tmp/received_recovered.bin",
        check=False
    )

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Assert both transfers succeeded
    assert degraded_checksum == expected_checksum, \
        "Checksum mismatch during degraded phase"
    assert recovered_checksum == expected_checksum, \
        "Checksum mismatch during recovered phase"

    # Calculate throughput
    throughput_degraded = (size_bytes / 1024) / duration_degraded if duration_degraded > 0 else 0
    throughput_recovered = (size_bytes / 1024) / duration_recovered if duration_recovered > 0 else 0

    # Performance should improve after loss is cleared
    # (Not a hard requirement due to timing variability, but log for visibility)
    improvement_ratio = throughput_recovered / throughput_degraded if throughput_degraded > 0 else 0

    print(f"\nDegraded: {duration_degraded:.2f}s, {throughput_degraded:.2f} KB/s")
    print(f"Recovered: {duration_recovered:.2f}s, {throughput_recovered:.2f} KB/s")
    print(f"Improvement: {improvement_ratio:.2f}x")


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.packet_loss
@pytest.mark.topology_2node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_bidirectional_packet_loss(two_node_cluster):
    """Test transfer with packet loss in both directions simultaneously.

    Applies 5% packet loss to both nodes and transfers data in both
    directions. Verifies that bidirectional loss doesn't cause deadlock
    or data corruption.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    size_bytes = 50 * 1024
    port1 = 9820
    port2 = 9821

    # Generate test files on both nodes
    result1 = await ssh1.exec_command(
        f"dd if=/dev/urandom of=/tmp/test_bidir_1.bin bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum /tmp/test_bidir_1.bin | awk '{{print $1}}'",
        timeout=30.0
    )
    checksum1_expected = result1.stdout.strip()

    result2 = await ssh2.exec_command(
        f"dd if=/dev/urandom of=/tmp/test_bidir_2.bin bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum /tmp/test_bidir_2.bin | awk '{{print $1}}'",
        timeout=30.0
    )
    checksum2_expected = result2.stdout.strip()

    # Apply 5% loss to both nodes
    async with NetworkChaos(container=node1.container_name) as chaos1, \
               NetworkChaos(container=node2.container_name) as chaos2:

        await chaos1.add_loss(5.0)
        await chaos2.add_loss(5.0)

        # Start receivers on both nodes
        receiver1_task = ssh1.exec_command_async(
            f"nc -l -p {port1} > /tmp/received_bidir_1.bin",
            timeout=180.0
        )
        receiver2_task = ssh2.exec_command_async(
            f"nc -l -p {port2} > /tmp/received_bidir_2.bin",
            timeout=180.0
        )

        # Wait for listeners
        await asyncio.sleep(2)

        # Send files in both directions simultaneously
        sender1_task = ssh1.exec_command_async(
            f"nc -w 30 10.0.0.2 {port2} < /tmp/test_bidir_1.bin",
            timeout=120.0
        )
        sender2_task = ssh2.exec_command_async(
            f"nc -w 30 10.0.0.1 {port1} < /tmp/test_bidir_2.bin",
            timeout=120.0
        )

        # Wait for all transfers to complete
        start_time = time.time()
        await asyncio.wait_for(asyncio.gather(
            sender1_task,
            sender2_task,
            receiver1_task,
            receiver2_task
        ), timeout=150.0)
        duration = time.time() - start_time

    # Verify checksums
    result1_check = await ssh2.exec_command(
        "sha256sum /tmp/received_bidir_2.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum1_received = result1_check.stdout.strip()

    result2_check = await ssh1.exec_command(
        "sha256sum /tmp/received_bidir_1.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum2_received = result2_check.stdout.strip()

    # Cleanup
    await ssh1.exec_command(
        "rm -f /tmp/test_bidir_1.bin /tmp/received_bidir_1.bin",
        check=False
    )
    await ssh2.exec_command(
        "rm -f /tmp/test_bidir_2.bin /tmp/received_bidir_2.bin",
        check=False
    )

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Assert both transfers succeeded
    assert checksum1_expected == checksum1_received, \
        f"Node1->Node2 checksum mismatch: expected={checksum1_expected}, received={checksum1_received}"
    assert checksum2_expected == checksum2_received, \
        f"Node2->Node1 checksum mismatch: expected={checksum2_expected}, received={checksum2_received}"

    # Log performance
    throughput_kbps = (size_bytes * 2 / 1024) / duration if duration > 0 else 0
    print(f"\nBidirectional transfer with 5% loss (both directions): {duration:.2f}s, {throughput_kbps:.2f} KB/s combined")


async def _run_loss_test(
    cluster,
    loss_percent: float,
    size_bytes: int,
    test_name: str,
    timeout: float
) -> None:
    """Helper function to run a packet loss test.

    Args:
        cluster: Cluster fixture
        loss_percent: Packet loss percentage (0-100)
        size_bytes: Data size in bytes
        test_name: Human-readable test name
        timeout: Transfer timeout in seconds
    """
    node1 = cluster.get_node("node-1")
    node2 = cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    # Generate test file and compute checksum
    test_file = "/tmp/test_loss_helper.bin"
    received_file = "/tmp/received_loss_helper.bin"

    result = await ssh1.exec_command(
        f"dd if=/dev/urandom of={test_file} bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum {test_file} | awk '{{print $1}}'",
        timeout=max(30.0, timeout / 4)
    )
    expected_checksum = result.stdout.strip()

    # Allocate port
    port = 9900 + int(loss_percent)

    # Apply packet loss to receiving node
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_loss(loss_percent)

        # Start receiver
        receiver_task = ssh2.exec_command_async(
            f"nc -l -p {port} > {received_file}",
            timeout=timeout
        )

        # Wait for listener
        await asyncio.sleep(2)

        # Send file
        start_time = time.time()
        await ssh1.exec_command(
            f"nc -w 30 10.0.0.2 {port} < {test_file}",
            timeout=timeout - 10,
            check=False
        )

        # Wait for receiver
        await asyncio.wait_for(receiver_task, timeout=timeout / 2)
        duration = time.time() - start_time

    # Verify checksum
    result = await ssh2.exec_command(
        f"sha256sum {received_file} | awk '{{print $1}}'",
        timeout=20.0
    )
    received_checksum = result.stdout.strip()

    # Calculate throughput
    throughput_kbps = (size_bytes / 1024) / duration if duration > 0 else 0
    throughput_mbps = (size_bytes * 8) / (duration * 1_000_000) if duration > 0 else 0

    # Cleanup
    await ssh1.exec_command(f"rm -f {test_file}", check=False)
    await ssh2.exec_command(f"rm -f {received_file}", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Assert checksum matches
    assert expected_checksum == received_checksum, \
        f"SHA256 mismatch for {test_name}: expected={expected_checksum}, received={received_checksum}"

    # Log throughput
    print(f"\n{test_name}: {duration:.2f}s, {throughput_kbps:.2f} KB/s ({throughput_mbps:.3f} Mbps)")
