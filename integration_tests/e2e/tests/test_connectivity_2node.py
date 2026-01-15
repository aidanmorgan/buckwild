"""2-node connectivity tests for Buckwild VPN.

Tests basic connectivity between two nodes over the Buckwild tunnel,
including ping, data transfer, and port hopping verification.
"""

import asyncio
import pytest

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck


@pytest.mark.e2e
@pytest.mark.smoke
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_ping_between_nodes(two_node_cluster):
    """Test basic ping connectivity between two nodes via buckwild tunnel.

    Verifies that nodes can reach each other over the VPN tunnel
    using their VPN IP addresses (10.0.0.X).
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net = NetworkCheck(ssh1)

    # Ping node-2's VPN IP from node-1
    result = await net.ping("10.0.0.2", count=4, timeout=15.0)

    assert result.success, f"Ping failed: {result.error}"
    assert result.packet_loss < 25.0, f"High packet loss: {result.packet_loss}%"
    assert result.avg_rtt_ms is not None, "No RTT information"
    assert result.avg_rtt_ms < 100.0, f"High latency: {result.avg_rtt_ms}ms"

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.smoke
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_bidirectional_ping(two_node_cluster):
    """Test bidirectional ping connectivity.

    Verifies that both nodes can ping each other, ensuring
    the tunnel works in both directions.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    net1 = NetworkCheck(ssh1)
    net2 = NetworkCheck(ssh2)

    # Ping in both directions simultaneously
    result1_task = net1.ping("10.0.0.2", count=3, timeout=15.0)
    result2_task = net2.ping("10.0.0.1", count=3, timeout=15.0)

    result1, result2 = await asyncio.gather(result1_task, result2_task)

    assert result1.success, f"Node1->Node2 ping failed: {result1.error}"
    assert result2.success, f"Node2->Node1 ping failed: {result2.error}"
    assert result1.packet_loss < 25.0, f"High packet loss node1->node2: {result1.packet_loss}%"
    assert result2.packet_loss < 25.0, f"High packet loss node2->node1: {result2.packet_loss}%"

    await ssh1.disconnect()
    await ssh2.disconnect()


@pytest.mark.e2e
@pytest.mark.smoke
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_small_data_transfer(two_node_cluster):
    """Test transferring 1KB of data between nodes.

    Creates a 1KB file on node-1, transfers it to node-2 via netcat
    over the VPN tunnel, and verifies integrity using checksums.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    # Create 1KB test file on node-1
    _, stdout, _ = await ssh1.exec_command(
        "dd if=/dev/urandom of=/tmp/test1k.bin bs=1024 count=1 2>/dev/null && "
        "md5sum /tmp/test1k.bin | awk '{print $1}'",
        timeout=10.0
    )
    original_checksum = stdout.strip()

    # Start receiver on node-2
    receiver_task = ssh2.exec_command_async(
        "nc -l -p 9999 > /tmp/received1k.bin",
        timeout=30.0
    )

    # Wait for listener to be ready
    await asyncio.sleep(2)

    # Send file from node-1 to node-2's VPN IP
    _, stdout, stderr = await ssh1.exec_command(
        "nc -w 5 10.0.0.2 9999 < /tmp/test1k.bin",
        timeout=20.0,
        check=False
    )

    # Wait for receiver to finish
    await asyncio.wait_for(receiver_task, timeout=10.0)

    # Verify checksum on node-2
    _, stdout, _ = await ssh2.exec_command(
        "md5sum /tmp/received1k.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum = stdout.strip()

    assert original_checksum == received_checksum, \
        f"Checksum mismatch: sent={original_checksum}, received={received_checksum}"

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test1k.bin", check=False)
    await ssh2.exec_command("rm -f /tmp/received1k.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_medium_data_transfer(two_node_cluster):
    """Test transferring 1MB of data between nodes.

    Creates a 1MB file on node-1, transfers it to node-2 via netcat
    over the VPN tunnel, and verifies integrity using checksums.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    # Create 1MB test file on node-1
    _, stdout, _ = await ssh1.exec_command(
        "dd if=/dev/urandom of=/tmp/test1m.bin bs=1024 count=1024 2>/dev/null && "
        "md5sum /tmp/test1m.bin | awk '{print $1}'",
        timeout=15.0
    )
    original_checksum = stdout.strip()

    # Start receiver on node-2
    receiver_task = ssh2.exec_command_async(
        "nc -l -p 9998 > /tmp/received1m.bin",
        timeout=60.0
    )

    # Wait for listener to be ready
    await asyncio.sleep(2)

    # Send file from node-1 to node-2's VPN IP
    _, stdout, stderr = await ssh1.exec_command(
        "nc -w 10 10.0.0.2 9998 < /tmp/test1m.bin",
        timeout=45.0,
        check=False
    )

    # Wait for receiver to finish
    await asyncio.wait_for(receiver_task, timeout=20.0)

    # Verify checksum on node-2
    _, stdout, _ = await ssh2.exec_command(
        "md5sum /tmp/received1m.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum = stdout.strip()

    assert original_checksum == received_checksum, \
        f"Checksum mismatch: sent={original_checksum}, received={received_checksum}"

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test1m.bin", check=False)
    await ssh2.exec_command("rm -f /tmp/received1m.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()


@pytest.mark.e2e
@pytest.mark.smoke
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_port_hopping_occurs(two_node_cluster):
    """Test that port hopping occurs during a session.

    Monitors the source/destination ports on packets sent over the VPN
    to verify that the frequency hopping mechanism is changing ports.
    Uses tcpdump to capture packets and verify port changes.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    # Start packet capture on node-2 (capture UDP packets from node-1's Docker IP)
    node1_docker_ip = node1.get_ip()
    capture_task = ssh2.exec_command_async(
        f"timeout 15 tcpdump -i eth0 -n 'udp and src host {node1_docker_ip}' -c 20 2>&1",
        timeout=20.0
    )

    # Wait for tcpdump to start
    await asyncio.sleep(2)

    # Send continuous pings from node-1 to node-2 to generate traffic
    ping_task = ssh1.exec_command_async(
        "ping -c 10 -i 0.5 10.0.0.2",
        timeout=15.0
    )

    # Wait for both to complete
    capture_result = await asyncio.wait_for(capture_task, timeout=20.0)
    await asyncio.wait_for(ping_task, timeout=15.0)

    # Parse tcpdump output to extract ports
    # Expected format: "HH:MM:SS.mmmmmm IP 172.30.0.10.SPORT > 172.30.0.11.DPORT: UDP"
    capture_output = capture_result.stdout if hasattr(capture_result, 'stdout') else str(capture_result)

    ports_seen = set()
    for line in capture_output.split('\n'):
        if 'UDP' in line and node1_docker_ip in line:
            parts = line.split()
            for part in parts:
                if node1_docker_ip in part and '.' in part:
                    # Extract source port (last component after IP)
                    components = part.split('.')
                    if len(components) >= 5:
                        try:
                            port = int(components[-1].rstrip(':'))
                            if 1024 <= port <= 65535:
                                ports_seen.add(port)
                        except (ValueError, IndexError):
                            continue

    # Verify that multiple different ports were used
    assert len(ports_seen) >= 2, \
        f"Port hopping not detected. Only {len(ports_seen)} unique ports seen: {ports_seen}"

    await ssh1.disconnect()
    await ssh2.disconnect()


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_vpn_status_endpoints(two_node_cluster):
    """Test that VPN status endpoints are accessible and return valid data.

    Verifies that both nodes expose their VPN status via HTTP endpoints
    and that the status contains expected information.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    status1 = await node1.get_vpn_status()
    status2 = await node2.get_vpn_status()

    assert status1 is not None, "Node 1 status is None"
    assert status2 is not None, "Node 2 status is None"

    # Verify status is not empty
    assert len(status1) > 0, "Node 1 status is empty"
    assert len(status2) > 0, "Node 2 status is empty"


@pytest.mark.e2e
@pytest.mark.topology_2node
@pytest.mark.asyncio
async def test_metrics_endpoints(two_node_cluster):
    """Test that metrics endpoints are accessible.

    Verifies that both nodes expose Prometheus-compatible metrics.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    metrics1 = await node1.get_metrics()
    metrics2 = await node2.get_metrics()

    assert metrics1 is not None, "Node 1 metrics is None"
    assert metrics2 is not None, "Node 2 metrics is None"

    # Verify metrics contain data
    assert len(metrics1) > 0, "Node 1 metrics is empty"
    assert len(metrics2) > 0, "Node 2 metrics is empty"

    # Check for raw metrics output
    if "raw" in metrics1:
        assert len(metrics1["raw"]) > 0, "Node 1 raw metrics is empty"
    if "raw" in metrics2:
        assert len(metrics2["raw"]) > 0, "Node 2 raw metrics is empty"
