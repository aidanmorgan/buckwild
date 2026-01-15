"""Latency injection resilience tests for Buckwild VPN.

Tests network latency scenarios using tc (traffic control) to inject
delays and verify that the VPN protocol adapts correctly and maintains
connectivity under various latency conditions.
"""

import asyncio
import time
import pytest

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck
from ..framework.chaos import NetworkChaos


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_baseline_latency(two_node_cluster):
    """Measure baseline latency without any network impairment.

    Establishes baseline RTT measurements for comparison with
    latency injection tests.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)
    result = await net.ping("10.0.0.2", count=10, timeout=15.0)

    assert result.success, f"Baseline ping failed: {result.error}"
    assert result.avg_rtt_ms is not None, "No RTT information"
    assert result.avg_rtt_ms < 50.0, f"Baseline latency too high: {result.avg_rtt_ms}ms"

    print(f"\nBaseline RTT: avg={result.avg_rtt_ms:.2f}ms, min={result.min_rtt_ms:.2f}ms, max={result.max_rtt_ms:.2f}ms")

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_low_latency_10ms(two_node_cluster):
    """Test VPN behavior with 10ms added latency.

    Low latency should have minimal impact on connectivity.
    Verifies that protocol remains functional with slight delay.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)

    # Measure baseline
    baseline_result = await net.ping("10.0.0.2", count=5, timeout=10.0)
    baseline_rtt = baseline_result.avg_rtt_ms if baseline_result.avg_rtt_ms else 0.0

    # Inject 10ms latency on node-2
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_latency(10)

        # Wait for tc to take effect
        await asyncio.sleep(2)

        # Test ping with latency
        result = await net.ping("10.0.0.2", count=10, timeout=20.0)

        assert result.success, f"Ping failed with 10ms latency: {result.error}"
        assert result.packet_loss < 25.0, f"High packet loss: {result.packet_loss}%"
        assert result.avg_rtt_ms is not None, "No RTT information"

        # Verify latency increased by approximately 10ms (allowing for jitter)
        expected_min_rtt = baseline_rtt + 5.0
        expected_max_rtt = baseline_rtt + 20.0
        assert expected_min_rtt <= result.avg_rtt_ms <= expected_max_rtt, \
            f"RTT {result.avg_rtt_ms}ms not in expected range [{expected_min_rtt:.1f}, {expected_max_rtt:.1f}]ms"

        print(f"\n10ms latency: baseline={baseline_rtt:.2f}ms, with_latency={result.avg_rtt_ms:.2f}ms, delta={result.avg_rtt_ms - baseline_rtt:.2f}ms")

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_medium_latency_100ms(two_node_cluster):
    """Test VPN behavior with 100ms added latency.

    Medium latency is noticeable but should not break connectivity.
    Verifies that timeout handling adapts to higher latency.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)

    # Measure baseline
    baseline_result = await net.ping("10.0.0.2", count=5, timeout=10.0)
    baseline_rtt = baseline_result.avg_rtt_ms if baseline_result.avg_rtt_ms else 0.0

    # Inject 100ms latency on node-2
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_latency(100)

        # Wait for tc to take effect
        await asyncio.sleep(2)

        # Test ping with latency
        result = await net.ping("10.0.0.2", count=10, timeout=30.0)

        assert result.success, f"Ping failed with 100ms latency: {result.error}"
        assert result.packet_loss < 25.0, f"High packet loss: {result.packet_loss}%"
        assert result.avg_rtt_ms is not None, "No RTT information"

        # Verify latency increased by approximately 100ms
        expected_min_rtt = baseline_rtt + 80.0
        expected_max_rtt = baseline_rtt + 150.0
        assert expected_min_rtt <= result.avg_rtt_ms <= expected_max_rtt, \
            f"RTT {result.avg_rtt_ms}ms not in expected range [{expected_min_rtt:.1f}, {expected_max_rtt:.1f}]ms"

        print(f"\n100ms latency: baseline={baseline_rtt:.2f}ms, with_latency={result.avg_rtt_ms:.2f}ms, delta={result.avg_rtt_ms - baseline_rtt:.2f}ms")

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_high_latency_500ms(two_node_cluster):
    """Test VPN behavior with 500ms added latency.

    High latency tests timeout handling and protocol resilience.
    Verifies that connection remains functional despite significant delay.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)

    # Measure baseline
    baseline_result = await net.ping("10.0.0.2", count=5, timeout=10.0)
    baseline_rtt = baseline_result.avg_rtt_ms if baseline_result.avg_rtt_ms else 0.0

    # Inject 500ms latency on node-2
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_latency(500)

        # Wait for tc to take effect
        await asyncio.sleep(2)

        # Test ping with latency (need longer timeout)
        result = await net.ping("10.0.0.2", count=10, timeout=60.0)

        assert result.success, f"Ping failed with 500ms latency: {result.error}"
        assert result.packet_loss < 50.0, f"Excessive packet loss: {result.packet_loss}%"
        assert result.avg_rtt_ms is not None, "No RTT information"

        # Verify latency increased by approximately 500ms
        expected_min_rtt = baseline_rtt + 400.0
        expected_max_rtt = baseline_rtt + 650.0
        assert expected_min_rtt <= result.avg_rtt_ms <= expected_max_rtt, \
            f"RTT {result.avg_rtt_ms}ms not in expected range [{expected_min_rtt:.1f}, {expected_max_rtt:.1f}]ms"

        print(f"\n500ms latency: baseline={baseline_rtt:.2f}ms, with_latency={result.avg_rtt_ms:.2f}ms, delta={result.avg_rtt_ms - baseline_rtt:.2f}ms")

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_latency_with_jitter(two_node_cluster):
    """Test VPN behavior with 100ms latency plus 50ms jitter.

    Jitter creates variable latency (50ms-150ms range).
    Verifies protocol handles latency variation correctly.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)

    # Measure baseline
    baseline_result = await net.ping("10.0.0.2", count=5, timeout=10.0)
    baseline_rtt = baseline_result.avg_rtt_ms if baseline_result.avg_rtt_ms else 0.0

    # Inject 100ms latency with 50ms jitter on node-2
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_latency(100, jitter_ms=50)

        # Wait for tc to take effect
        await asyncio.sleep(2)

        # Test ping with jitter
        result = await net.ping("10.0.0.2", count=20, timeout=45.0)

        assert result.success, f"Ping failed with jitter: {result.error}"
        assert result.packet_loss < 30.0, f"High packet loss: {result.packet_loss}%"
        assert result.avg_rtt_ms is not None, "No RTT information"

        # With jitter, expect wider RTT range
        expected_min_rtt = baseline_rtt + 40.0
        expected_max_rtt = baseline_rtt + 180.0
        assert expected_min_rtt <= result.avg_rtt_ms <= expected_max_rtt, \
            f"RTT {result.avg_rtt_ms}ms not in expected range [{expected_min_rtt:.1f}, {expected_max_rtt:.1f}]ms"

        # Verify jitter created RTT variation
        if result.min_rtt_ms and result.max_rtt_ms:
            rtt_range = result.max_rtt_ms - result.min_rtt_ms
            assert rtt_range > 20.0, f"Insufficient RTT variation with jitter: {rtt_range:.2f}ms"

        print(f"\nJitter test: baseline={baseline_rtt:.2f}ms, avg={result.avg_rtt_ms:.2f}ms, min={result.min_rtt_ms:.2f}ms, max={result.max_rtt_ms:.2f}ms, range={rtt_range:.2f}ms")

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_asymmetric_latency(two_node_cluster):
    """Test asymmetric latency conditions.

    Adds latency to only one direction (node-2).
    Verifies protocol handles different RTTs in each direction.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    net1 = NetworkCheck(ssh1)
    net2 = NetworkCheck(ssh2)

    # Add latency only on node-2 (affects packets sent FROM node-2)
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_latency(100)

        # Wait for tc to take effect
        await asyncio.sleep(2)

        # Ping from both directions
        result1_task = net1.ping("10.0.0.2", count=10, timeout=30.0)
        result2_task = net2.ping("10.0.0.1", count=10, timeout=30.0)

        result1, result2 = await asyncio.gather(result1_task, result2_task)

        assert result1.success, f"Node1->Node2 ping failed: {result1.error}"
        assert result2.success, f"Node2->Node1 ping failed: {result2.error}"

        # Both directions experience latency (round trip includes both paths)
        # but asymmetry may be visible in packet loss or jitter patterns
        assert result1.packet_loss < 30.0, f"High packet loss node1->node2: {result1.packet_loss}%"
        assert result2.packet_loss < 30.0, f"High packet loss node2->node1: {result2.packet_loss}%"

        print(f"\nAsymmetric latency: node1->node2 RTT={result1.avg_rtt_ms:.2f}ms, node2->node1 RTT={result2.avg_rtt_ms:.2f}ms")

    await ssh1.disconnect()
    await ssh2.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_data_transfer_under_latency(two_node_cluster):
    """Test file transfer with 100ms latency.

    Transfers 100KB file with added latency.
    Verifies throughput degradation but maintains correctness.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    size_bytes = 100 * 1024
    test_file = "/tmp/test_latency.bin"
    received_file = "/tmp/received_latency.bin"

    # Generate test file
    result = await ssh1.exec_command(
        f"dd if=/dev/urandom of={test_file} bs={size_bytes} count=1 2>/dev/null && "
        f"sha256sum {test_file} | awk '{{print $1}}'",
        timeout=20.0
    )
    expected_checksum = result.stdout.strip()

    # Inject latency on node-2
    async with NetworkChaos(container=node2.container_name) as chaos:
        await chaos.add_latency(100)

        # Wait for tc to take effect
        await asyncio.sleep(2)

        # Start receiver
        receiver_task = ssh2.exec_command_async(
            f"nc -l -p 9995 > {received_file}",
            timeout=120.0
        )

        # Wait for listener
        await asyncio.sleep(2)

        # Measure transfer time
        start_time = time.time()

        # Send file
        await ssh1.exec_command(
            f"nc -w 20 10.0.0.2 9995 < {test_file}",
            timeout=90.0,
            check=False
        )

        # Wait for receiver
        await asyncio.wait_for(receiver_task, timeout=60.0)

        end_time = time.time()
        duration = end_time - start_time

        # Verify checksum
        result = await ssh2.exec_command(
            f"sha256sum {received_file} | awk '{{print $1}}'",
            timeout=20.0
        )
        received_checksum = result.stdout.strip()

        assert expected_checksum == received_checksum, \
            f"Checksum mismatch: expected={expected_checksum}, received={received_checksum}"

        # Calculate throughput
        throughput_kbps = (size_bytes / 1024) / duration if duration > 0 else 0

        print(f"\n100KB transfer with 100ms latency: {duration:.3f}s, {throughput_kbps:.2f} KB/s")

        # Cleanup
        await ssh1.exec_command(f"rm -f {test_file}", check=False)
        await ssh2.exec_command(f"rm -f {received_file}", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.latency
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_recovery_after_latency_cleared(two_node_cluster):
    """Test recovery after latency is removed.

    Verifies that performance returns to baseline after
    network conditions normalize.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)

    # Measure baseline
    baseline_result = await net.ping("10.0.0.2", count=10, timeout=15.0)
    baseline_rtt = baseline_result.avg_rtt_ms if baseline_result.avg_rtt_ms else 0.0

    # Inject latency
    chaos = NetworkChaos(container=node2.container_name)
    await chaos.add_latency(200)

    # Wait for tc to take effect
    await asyncio.sleep(2)

    # Test with latency
    latency_result = await net.ping("10.0.0.2", count=10, timeout=30.0)
    latency_rtt = latency_result.avg_rtt_ms if latency_result.avg_rtt_ms else 0.0

    # Clear latency
    await chaos.clear()

    # Wait for tc to clear and connections to stabilize
    await asyncio.sleep(3)

    # Test after recovery
    recovery_result = await net.ping("10.0.0.2", count=10, timeout=15.0)
    recovery_rtt = recovery_result.avg_rtt_ms if recovery_result.avg_rtt_ms else 0.0

    assert recovery_result.success, f"Ping failed after recovery: {recovery_result.error}"
    assert recovery_result.packet_loss < 25.0, f"High packet loss after recovery: {recovery_result.packet_loss}%"

    # Verify RTT returned to near-baseline levels
    rtt_difference = abs(recovery_rtt - baseline_rtt)
    assert rtt_difference < 30.0, \
        f"RTT did not recover: baseline={baseline_rtt:.2f}ms, recovery={recovery_rtt:.2f}ms, diff={rtt_difference:.2f}ms"

    print(f"\nRecovery: baseline={baseline_rtt:.2f}ms, with_latency={latency_rtt:.2f}ms, after_clear={recovery_rtt:.2f}ms")

    await ssh1.disconnect()
