"""3-node topology tests for Buckwild VPN.

Tests triangle connectivity, concurrent sessions, and multi-hop routing
in a 3-node cluster configuration.
"""

import asyncio
import pytest

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck


@pytest.mark.e2e
@pytest.mark.topology_3node
@pytest.mark.asyncio
async def test_triangle_connectivity(three_node_cluster):
    """Test full mesh connectivity between all three nodes.

    Verifies that all three nodes can reach each other in a triangle:
    - node-1 ↔ node-2
    - node-2 ↔ node-3
    - node-1 ↔ node-3

    This ensures the VPN mesh is fully connected.
    """
    node1 = three_node_cluster.get_node("node-1")
    node2 = three_node_cluster.get_node("node-2")
    node3 = three_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh2.connect()
    await ssh3.connect()

    net1 = NetworkCheck(ssh1)
    net2 = NetworkCheck(ssh2)
    net3 = NetworkCheck(ssh3)

    # Test all 6 directional paths in parallel
    tasks = [
        net1.ping("10.0.0.2", count=3, timeout=15.0),  # node-1 -> node-2
        net1.ping("10.0.0.3", count=3, timeout=15.0),  # node-1 -> node-3
        net2.ping("10.0.0.1", count=3, timeout=15.0),  # node-2 -> node-1
        net2.ping("10.0.0.3", count=3, timeout=15.0),  # node-2 -> node-3
        net3.ping("10.0.0.1", count=3, timeout=15.0),  # node-3 -> node-1
        net3.ping("10.0.0.2", count=3, timeout=15.0),  # node-3 -> node-2
    ]

    results = await asyncio.gather(*tasks)

    # Verify all paths work
    path_names = [
        "node-1 -> node-2",
        "node-1 -> node-3",
        "node-2 -> node-1",
        "node-2 -> node-3",
        "node-3 -> node-1",
        "node-3 -> node-2",
    ]

    for i, (result, path_name) in enumerate(zip(results, path_names)):
        assert result.success, f"{path_name} ping failed: {result.error}"
        assert result.packet_loss < 25.0, f"{path_name} high packet loss: {result.packet_loss}%"
        assert result.avg_rtt_ms is not None, f"{path_name} no RTT information"

    await ssh1.disconnect()
    await ssh2.disconnect()
    await ssh3.disconnect()


@pytest.mark.e2e
@pytest.mark.topology_3node
@pytest.mark.asyncio
async def test_concurrent_sessions(three_node_cluster):
    """Test multiple concurrent data transfer sessions.

    Creates three simultaneous transfers:
    - node-1 -> node-2
    - node-2 -> node-3
    - node-3 -> node-1

    Verifies that the VPN can handle concurrent sessions without
    interference or data corruption.
    """
    node1 = three_node_cluster.get_node("node-1")
    node2 = three_node_cluster.get_node("node-2")
    node3 = three_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh2.connect()
    await ssh3.connect()

    # Create test files on each node
    _, stdout1, _ = await ssh1.exec_command(
        "dd if=/dev/urandom of=/tmp/test_n1.bin bs=1024 count=512 2>/dev/null && "
        "md5sum /tmp/test_n1.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum1 = stdout1.strip()

    _, stdout2, _ = await ssh2.exec_command(
        "dd if=/dev/urandom of=/tmp/test_n2.bin bs=1024 count=512 2>/dev/null && "
        "md5sum /tmp/test_n2.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum2 = stdout2.strip()

    _, stdout3, _ = await ssh3.exec_command(
        "dd if=/dev/urandom of=/tmp/test_n3.bin bs=1024 count=512 2>/dev/null && "
        "md5sum /tmp/test_n3.bin | awk '{print $1}'",
        timeout=10.0
    )
    checksum3 = stdout3.strip()

    # Start all receivers
    receiver1_task = ssh1.exec_command_async(
        "nc -l -p 9001 > /tmp/received_from_n3.bin",
        timeout=60.0
    )
    receiver2_task = ssh2.exec_command_async(
        "nc -l -p 9002 > /tmp/received_from_n1.bin",
        timeout=60.0
    )
    receiver3_task = ssh3.exec_command_async(
        "nc -l -p 9003 > /tmp/received_from_n2.bin",
        timeout=60.0
    )

    # Wait for receivers to be ready
    await asyncio.sleep(2)

    # Start all senders simultaneously
    sender_tasks = [
        ssh1.exec_command("nc -w 10 10.0.0.2 9002 < /tmp/test_n1.bin", timeout=30.0, check=False),
        ssh2.exec_command("nc -w 10 10.0.0.3 9003 < /tmp/test_n2.bin", timeout=30.0, check=False),
        ssh3.exec_command("nc -w 10 10.0.0.1 9001 < /tmp/test_n3.bin", timeout=30.0, check=False),
    ]

    # Wait for all transfers to complete
    await asyncio.gather(*sender_tasks)
    await asyncio.gather(receiver1_task, receiver2_task, receiver3_task)

    # Verify all checksums
    _, recv_stdout1, _ = await ssh1.exec_command(
        "md5sum /tmp/received_from_n3.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum1 = recv_stdout1.strip()

    _, recv_stdout2, _ = await ssh2.exec_command(
        "md5sum /tmp/received_from_n1.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum2 = recv_stdout2.strip()

    _, recv_stdout3, _ = await ssh3.exec_command(
        "md5sum /tmp/received_from_n2.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum3 = recv_stdout3.strip()

    # Verify data integrity
    assert checksum3 == received_checksum1, \
        f"node-3 -> node-1 checksum mismatch: sent={checksum3}, received={received_checksum1}"
    assert checksum1 == received_checksum2, \
        f"node-1 -> node-2 checksum mismatch: sent={checksum1}, received={received_checksum2}"
    assert checksum2 == received_checksum3, \
        f"node-2 -> node-3 checksum mismatch: sent={checksum2}, received={received_checksum3}"

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test_n1.bin /tmp/received_from_n3.bin", check=False)
    await ssh2.exec_command("rm -f /tmp/test_n2.bin /tmp/received_from_n1.bin", check=False)
    await ssh3.exec_command("rm -f /tmp/test_n3.bin /tmp/received_from_n2.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()
    await ssh3.disconnect()


@pytest.mark.e2e
@pytest.mark.topology_3node
@pytest.mark.asyncio
async def test_data_transfer_all_pairs(three_node_cluster):
    """Test data transfer between all node pairs.

    Transfers 1MB files between each pair of nodes sequentially:
    - node-1 -> node-2
    - node-2 -> node-3
    - node-1 -> node-3

    Verifies data integrity using checksums for all transfers.
    """
    node1 = three_node_cluster.get_node("node-1")
    node2 = three_node_cluster.get_node("node-2")
    node3 = three_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh2.connect()
    await ssh3.connect()

    # Test 1: node-1 -> node-2
    _, stdout, _ = await ssh1.exec_command(
        "dd if=/dev/urandom of=/tmp/test12.bin bs=1024 count=1024 2>/dev/null && "
        "md5sum /tmp/test12.bin | awk '{print $1}'",
        timeout=15.0
    )
    checksum12 = stdout.strip()

    receiver_task = ssh2.exec_command_async(
        "nc -l -p 9012 > /tmp/received12.bin",
        timeout=60.0
    )
    await asyncio.sleep(2)

    await ssh1.exec_command("nc -w 10 10.0.0.2 9012 < /tmp/test12.bin", timeout=45.0, check=False)
    await asyncio.wait_for(receiver_task, timeout=20.0)

    _, stdout, _ = await ssh2.exec_command(
        "md5sum /tmp/received12.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum12 = stdout.strip()

    assert checksum12 == received_checksum12, \
        f"node-1 -> node-2 checksum mismatch: sent={checksum12}, received={received_checksum12}"

    # Test 2: node-2 -> node-3
    _, stdout, _ = await ssh2.exec_command(
        "dd if=/dev/urandom of=/tmp/test23.bin bs=1024 count=1024 2>/dev/null && "
        "md5sum /tmp/test23.bin | awk '{print $1}'",
        timeout=15.0
    )
    checksum23 = stdout.strip()

    receiver_task = ssh3.exec_command_async(
        "nc -l -p 9023 > /tmp/received23.bin",
        timeout=60.0
    )
    await asyncio.sleep(2)

    await ssh2.exec_command("nc -w 10 10.0.0.3 9023 < /tmp/test23.bin", timeout=45.0, check=False)
    await asyncio.wait_for(receiver_task, timeout=20.0)

    _, stdout, _ = await ssh3.exec_command(
        "md5sum /tmp/received23.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum23 = stdout.strip()

    assert checksum23 == received_checksum23, \
        f"node-2 -> node-3 checksum mismatch: sent={checksum23}, received={received_checksum23}"

    # Test 3: node-1 -> node-3
    _, stdout, _ = await ssh1.exec_command(
        "dd if=/dev/urandom of=/tmp/test13.bin bs=1024 count=1024 2>/dev/null && "
        "md5sum /tmp/test13.bin | awk '{print $1}'",
        timeout=15.0
    )
    checksum13 = stdout.strip()

    receiver_task = ssh3.exec_command_async(
        "nc -l -p 9013 > /tmp/received13.bin",
        timeout=60.0
    )
    await asyncio.sleep(2)

    await ssh1.exec_command("nc -w 10 10.0.0.3 9013 < /tmp/test13.bin", timeout=45.0, check=False)
    await asyncio.wait_for(receiver_task, timeout=20.0)

    _, stdout, _ = await ssh3.exec_command(
        "md5sum /tmp/received13.bin | awk '{print $1}'",
        timeout=10.0
    )
    received_checksum13 = stdout.strip()

    assert checksum13 == received_checksum13, \
        f"node-1 -> node-3 checksum mismatch: sent={checksum13}, received={received_checksum13}"

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/test12.bin /tmp/test13.bin", check=False)
    await ssh2.exec_command("rm -f /tmp/received12.bin /tmp/test23.bin", check=False)
    await ssh3.exec_command("rm -f /tmp/received23.bin /tmp/received13.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()
    await ssh3.disconnect()


@pytest.mark.e2e
@pytest.mark.topology_3node
@pytest.mark.asyncio
async def test_all_nodes_status(three_node_cluster):
    """Test that all three nodes expose status endpoints.

    Verifies that status and metrics endpoints are accessible
    on all nodes in the cluster.
    """
    node1 = three_node_cluster.get_node("node-1")
    node2 = three_node_cluster.get_node("node-2")
    node3 = three_node_cluster.get_node("node-3")

    # Get status from all nodes in parallel
    status_tasks = [
        node1.get_vpn_status(),
        node2.get_vpn_status(),
        node3.get_vpn_status()
    ]
    statuses = await asyncio.gather(*status_tasks)

    for i, status in enumerate(statuses, 1):
        assert status is not None, f"Node {i} status is None"
        assert len(status) > 0, f"Node {i} status is empty"

    # Get metrics from all nodes in parallel
    metrics_tasks = [
        node1.get_metrics(),
        node2.get_metrics(),
        node3.get_metrics()
    ]
    metrics = await asyncio.gather(*metrics_tasks)

    for i, metric in enumerate(metrics, 1):
        assert metric is not None, f"Node {i} metrics is None"
        assert len(metric) > 0, f"Node {i} metrics is empty"


@pytest.mark.e2e
@pytest.mark.topology_3node
@pytest.mark.asyncio
async def test_simultaneous_ping_all_directions(three_node_cluster):
    """Test simultaneous pings in all directions.

    Sends pings simultaneously between all node pairs to verify
    the VPN can handle concurrent bidirectional traffic without
    packet loss or interference.
    """
    node1 = three_node_cluster.get_node("node-1")
    node2 = three_node_cluster.get_node("node-2")
    node3 = three_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh2.connect()
    await ssh3.connect()

    # Create continuous ping tasks for all pairs
    ping_tasks = [
        ssh1.exec_command("ping -c 20 -i 0.2 10.0.0.2", timeout=30.0, check=False),
        ssh1.exec_command("ping -c 20 -i 0.2 10.0.0.3", timeout=30.0, check=False),
        ssh2.exec_command("ping -c 20 -i 0.2 10.0.0.1", timeout=30.0, check=False),
        ssh2.exec_command("ping -c 20 -i 0.2 10.0.0.3", timeout=30.0, check=False),
        ssh3.exec_command("ping -c 20 -i 0.2 10.0.0.1", timeout=30.0, check=False),
        ssh3.exec_command("ping -c 20 -i 0.2 10.0.0.2", timeout=30.0, check=False),
    ]

    results = await asyncio.gather(*ping_tasks)

    # Verify all pings succeeded
    for result in results:
        assert result.returncode == 0, f"Ping failed: {result.stderr}"
        # Parse packet loss from output
        packet_loss = 100.0
        for line in result.stdout.splitlines():
            if "packet loss" in line:
                parts = line.split(",")
                for part in parts:
                    if "% packet loss" in part:
                        loss_str = part.strip().split("%")[0].split()[-1]
                        packet_loss = float(loss_str)
                        break
        assert packet_loss < 25.0, f"High packet loss during concurrent pings: {packet_loss}%"

    await ssh1.disconnect()
    await ssh2.disconnect()
    await ssh3.disconnect()
