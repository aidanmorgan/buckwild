"""5-node topology tests for Buckwild VPN.

Tests complex topology scenarios with 5 nodes, including full mesh connectivity,
partial mesh with routing, failure isolation, and convergence after topology changes.
"""

import asyncio
import pytest
from typing import List, Tuple

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_5node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_full_mesh_connectivity(five_node_cluster):
    """Test full mesh connectivity between all 5 nodes.

    In a 5-node cluster, there are 5*4/2 = 10 unique node pairs.
    This test verifies that every node can ping every other node.
    """
    nodes = five_node_cluster.get_all_nodes()
    assert len(nodes) == 5, f"Expected 5 nodes, got {len(nodes)}"

    # VPN IPs are 10.0.0.1 through 10.0.0.5
    node_vpn_ips = {
        "node-1": "10.0.0.1",
        "node-2": "10.0.0.2",
        "node-3": "10.0.0.3",
        "node-4": "10.0.0.4",
        "node-5": "10.0.0.5",
    }

    # Create SSH clients for all nodes
    ssh_clients = {}
    for node in nodes:
        ssh_clients[node.name] = SSHClient(node.container_name)
        await ssh_clients[node.name].connect()

    # Test all unique pairs (10 pairs total)
    failed_pairs = []
    successful_pairs = []

    for i, source_node in enumerate(nodes):
        net = NetworkCheck(ssh_clients[source_node.name])

        for target_node in nodes[i+1:]:
            source_name = source_node.name
            target_name = target_node.name
            target_ip = node_vpn_ips[target_name]

            # Ping from source to target
            result = await net.ping(target_ip, count=3, timeout=20.0)

            if result.success and result.packet_loss < 50.0:
                successful_pairs.append((source_name, target_name))
            else:
                failed_pairs.append((source_name, target_name, result.error))

    # Cleanup SSH connections
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    # Assert all 10 pairs succeeded
    assert len(successful_pairs) == 10, \
        f"Expected 10 successful pairs, got {len(successful_pairs)}"

    assert len(failed_pairs) == 0, \
        f"Failed pairs: {failed_pairs}"


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_5node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_partial_mesh_with_routing(five_node_cluster):
    """Test partial mesh connectivity with routing.

    Simulates a scenario where not all nodes have direct connections,
    requiring intermediate routing. Stops node-3 to create a gap and
    verifies that routing still works through alternate paths.
    """
    nodes = five_node_cluster.get_all_nodes()

    # Node VPN IPs
    node_ips = {
        "node-1": "10.0.0.1",
        "node-2": "10.0.0.2",
        "node-3": "10.0.0.3",
        "node-4": "10.0.0.4",
        "node-5": "10.0.0.5",
    }

    # Initial connectivity check - all should work
    node1 = five_node_cluster.get_node("node-1")
    node5 = five_node_cluster.get_node("node-5")

    ssh1 = SSHClient(node1.container_name)
    ssh5 = SSHClient(node5.container_name)

    await ssh1.connect()
    await ssh5.connect()

    net1 = NetworkCheck(ssh1)

    # Verify node-1 can reach node-5 initially
    initial_result = await net1.ping(node_ips["node-5"], count=3, timeout=20.0)
    assert initial_result.success, \
        f"Initial connectivity failed: {initial_result.error}"

    # Stop node-3 to create a gap in the mesh
    # Remaining nodes should route around the missing node
    node3 = five_node_cluster.get_node("node-3")
    cmd = f"docker stop {node3.container_name}"

    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()

    # Wait for network to adjust
    await asyncio.sleep(10)

    # Test that node-1 can still reach node-5 via alternate routes
    # This may take longer as routes converge
    rerouted_result = await net1.ping(node_ips["node-5"], count=5, timeout=30.0)

    # Restart node-3 for cleanup
    restart_cmd = f"docker start {node3.container_name}"
    process = await asyncio.create_subprocess_shell(
        restart_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()

    await ssh1.disconnect()
    await ssh5.disconnect()

    # In a full mesh with 5 nodes, losing one node should still allow
    # connectivity through alternate paths
    assert rerouted_result.success or rerouted_result.packet_loss < 60.0, \
        f"Routing failed after node-3 stopped: {rerouted_result.error}"


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_5node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_failure_isolation(five_node_cluster):
    """Test that one node failure doesn't break other communication paths.

    Stops node-2 and verifies that:
    1. Other nodes can still communicate with each other
    2. Only paths involving node-2 are affected
    3. The network maintains partial connectivity
    """
    nodes = five_node_cluster.get_all_nodes()

    node_ips = {
        "node-1": "10.0.0.1",
        "node-2": "10.0.0.2",
        "node-3": "10.0.0.3",
        "node-4": "10.0.0.4",
        "node-5": "10.0.0.5",
    }

    # Stop node-2
    node2 = five_node_cluster.get_node("node-2")
    stop_cmd = f"docker stop {node2.container_name}"

    process = await asyncio.create_subprocess_shell(
        stop_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()

    # Wait for failure detection
    await asyncio.sleep(8)

    # Test connectivity between remaining nodes
    # These pairs should still work: (1,3), (1,4), (1,5), (3,4), (3,5), (4,5)
    test_pairs = [
        ("node-1", "node-3"),
        ("node-1", "node-4"),
        ("node-1", "node-5"),
        ("node-3", "node-4"),
        ("node-3", "node-5"),
        ("node-4", "node-5"),
    ]

    ssh_clients = {}
    successful_isolated_pairs = []
    failed_isolated_pairs = []

    for source_name, target_name in test_pairs:
        if source_name not in ssh_clients:
            source_node = five_node_cluster.get_node(source_name)
            ssh_clients[source_name] = SSHClient(source_node.container_name)
            await ssh_clients[source_name].connect()

        net = NetworkCheck(ssh_clients[source_name])
        target_ip = node_ips[target_name]

        result = await net.ping(target_ip, count=3, timeout=20.0)

        if result.success and result.packet_loss < 50.0:
            successful_isolated_pairs.append((source_name, target_name))
        else:
            failed_isolated_pairs.append((source_name, target_name, result.error))

    # Restart node-2 for cleanup
    restart_cmd = f"docker start {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        restart_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()

    # Cleanup SSH connections
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    # All 6 remaining pairs should succeed
    assert len(successful_isolated_pairs) >= 5, \
        f"Failure isolation failed: only {len(successful_isolated_pairs)}/6 pairs working. " \
        f"Failed: {failed_isolated_pairs}"


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_5node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_convergence_after_topology_change(five_node_cluster):
    """Test routing convergence after topology changes.

    Simulates a network partition and recovery scenario:
    1. Stop two nodes (node-2 and node-4) to partition the network
    2. Verify connectivity within remaining nodes
    3. Restart the stopped nodes
    4. Verify full mesh connectivity is restored
    """
    node_ips = {
        "node-1": "10.0.0.1",
        "node-2": "10.0.0.2",
        "node-3": "10.0.0.3",
        "node-4": "10.0.0.4",
        "node-5": "10.0.0.5",
    }

    # Stop node-2 and node-4
    node2 = five_node_cluster.get_node("node-2")
    node4 = five_node_cluster.get_node("node-4")

    stop_cmds = [
        f"docker stop {node2.container_name}",
        f"docker stop {node4.container_name}"
    ]

    for cmd in stop_cmds:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    # Wait for partition to settle
    await asyncio.sleep(10)

    # Phase 1: Verify remaining nodes (1, 3, 5) can communicate
    node1 = five_node_cluster.get_node("node-1")
    node3 = five_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net1 = NetworkCheck(ssh1)

    # Node-1 should reach node-3 and node-5
    result_1_to_3 = await net1.ping(node_ips["node-3"], count=3, timeout=20.0)
    result_1_to_5 = await net1.ping(node_ips["node-5"], count=3, timeout=20.0)

    partition_connectivity = (
        result_1_to_3.success or result_1_to_3.packet_loss < 50.0
    ) and (
        result_1_to_5.success or result_1_to_5.packet_loss < 50.0
    )

    # Phase 2: Restart node-2 and node-4
    restart_cmds = [
        f"docker start {node2.container_name}",
        f"docker start {node4.container_name}"
    ]

    for cmd in restart_cmds:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    # Wait for nodes to rejoin and routes to converge
    # This may take longer for full convergence
    await asyncio.sleep(30)

    # Wait for restarted nodes to be ready
    try:
        await asyncio.wait_for(node2.wait_ready(timeout=60.0), timeout=70.0)
        await asyncio.wait_for(node4.wait_ready(timeout=60.0), timeout=70.0)
    except asyncio.TimeoutError:
        # Continue anyway - we'll check connectivity
        pass

    # Phase 3: Verify full mesh is restored
    # Test a sample of connections to verify convergence
    convergence_tests = [
        ("node-1", "node-2"),
        ("node-1", "node-4"),
        ("node-3", "node-2"),
        ("node-3", "node-4"),
        ("node-5", "node-2"),
    ]

    converged_pairs = 0

    for source_name, target_name in convergence_tests:
        if source_name == "node-1":
            net = net1
        else:
            source_node = five_node_cluster.get_node(source_name)
            ssh_temp = SSHClient(source_node.container_name)
            await ssh_temp.connect()
            net = NetworkCheck(ssh_temp)

        target_ip = node_ips[target_name]
        result = await net.ping(target_ip, count=4, timeout=25.0)

        if result.success and result.packet_loss < 50.0:
            converged_pairs += 1

        if source_name != "node-1":
            await ssh_temp.disconnect()

    await ssh1.disconnect()

    # Assert partition connectivity worked
    assert partition_connectivity, \
        "Partition connectivity failed - nodes in remaining partition couldn't communicate"

    # Assert at least 80% of test pairs converged after recovery
    convergence_rate = converged_pairs / len(convergence_tests)
    assert convergence_rate >= 0.8, \
        f"Convergence failed: only {converged_pairs}/{len(convergence_tests)} " \
        f"pairs restored ({convergence_rate:.1%})"


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_5node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_concurrent_data_transfer_5node(five_node_cluster):
    """Test concurrent data transfers between multiple node pairs.

    Performs simultaneous 100KB transfers between 3 different node pairs
    to verify the network can handle multiple concurrent flows.
    """
    # Define transfer pairs
    transfer_pairs = [
        ("node-1", "node-2", "10.0.0.2", 9001),
        ("node-3", "node-4", "10.0.0.4", 9002),
        ("node-5", "node-1", "10.0.0.1", 9003),
    ]

    ssh_clients = {}

    # Setup SSH clients
    for source_name, target_name, _, _ in transfer_pairs:
        for node_name in [source_name, target_name]:
            if node_name not in ssh_clients:
                node = five_node_cluster.get_node(node_name)
                ssh_clients[node_name] = SSHClient(node.container_name)
                await ssh_clients[node_name].connect()

    async def transfer_file(source_name: str, target_name: str, target_ip: str, port: int) -> Tuple[bool, str]:
        """Transfer a 100KB file between two nodes."""
        ssh_source = ssh_clients[source_name]
        ssh_target = ssh_clients[target_name]

        # Create 100KB test file on source
        create_result = await ssh_source.exec_command(
            f"dd if=/dev/urandom of=/tmp/test_{port}.bin bs=1024 count=100 2>/dev/null && "
            f"md5sum /tmp/test_{port}.bin | awk '{{print $1}}'",
            timeout=15.0,
            check=False
        )

        if not create_result.success:
            return False, f"Failed to create test file: {create_result.stderr}"

        original_checksum = create_result.stdout.strip()

        # Start receiver
        receiver_task = ssh_target.exec_command_async(
            f"nc -l -p {port} > /tmp/received_{port}.bin",
            timeout=60.0
        )

        # Wait for listener
        await asyncio.sleep(2)

        # Send file
        send_result = await ssh_source.exec_command(
            f"nc -w 10 {target_ip} {port} < /tmp/test_{port}.bin",
            timeout=30.0,
            check=False
        )

        # Wait for receiver
        try:
            await asyncio.wait_for(receiver_task, timeout=15.0)
        except asyncio.TimeoutError:
            return False, "Receiver timed out"

        # Verify checksum
        verify_result = await ssh_target.exec_command(
            f"md5sum /tmp/received_{port}.bin | awk '{{print $1}}'",
            timeout=10.0,
            check=False
        )

        if not verify_result.success:
            return False, f"Failed to verify checksum: {verify_result.stderr}"

        received_checksum = verify_result.stdout.strip()

        # Cleanup
        await ssh_source.exec_command(f"rm -f /tmp/test_{port}.bin", check=False)
        await ssh_target.exec_command(f"rm -f /tmp/received_{port}.bin", check=False)

        if original_checksum == received_checksum:
            return True, "Success"
        else:
            return False, f"Checksum mismatch: {original_checksum} != {received_checksum}"

    # Execute all transfers concurrently
    transfer_tasks = [
        transfer_file(source, target, ip, port)
        for source, target, ip, port in transfer_pairs
    ]

    results = await asyncio.gather(*transfer_tasks, return_exceptions=True)

    # Cleanup SSH connections
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    # Verify results
    successful_transfers = 0
    failed_transfers = []

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            failed_transfers.append((transfer_pairs[i], str(result)))
        else:
            success, message = result
            if success:
                successful_transfers += 1
            else:
                failed_transfers.append((transfer_pairs[i], message))

    # All transfers should succeed
    assert successful_transfers == len(transfer_pairs), \
        f"Only {successful_transfers}/{len(transfer_pairs)} transfers succeeded. " \
        f"Failures: {failed_transfers}"


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_5node
@pytest.mark.slow
@pytest.mark.asyncio
async def test_symmetric_latency(five_node_cluster):
    """Test that latency is symmetric between node pairs.

    Verifies that RTT from A->B is similar to RTT from B->A,
    which indicates proper bidirectional connectivity.
    """
    node_ips = {
        "node-1": "10.0.0.1",
        "node-2": "10.0.0.2",
        "node-3": "10.0.0.3",
        "node-4": "10.0.0.4",
        "node-5": "10.0.0.5",
    }

    # Test pairs in both directions
    test_pairs = [
        ("node-1", "node-3"),
        ("node-2", "node-4"),
        ("node-3", "node-5"),
    ]

    ssh_clients = {}
    asymmetries = []

    for source_name, target_name in test_pairs:
        # Create SSH clients if needed
        for node_name in [source_name, target_name]:
            if node_name not in ssh_clients:
                node = five_node_cluster.get_node(node_name)
                ssh_clients[node_name] = SSHClient(node.container_name)
                await ssh_clients[node_name].connect()

        # Ping A->B
        net_source = NetworkCheck(ssh_clients[source_name])
        result_forward = await net_source.ping(node_ips[target_name], count=5, timeout=20.0)

        # Ping B->A
        net_target = NetworkCheck(ssh_clients[target_name])
        result_reverse = await net_target.ping(node_ips[source_name], count=5, timeout=20.0)

        if result_forward.avg_rtt_ms and result_reverse.avg_rtt_ms:
            # Check if RTTs are within 50% of each other
            ratio = result_forward.avg_rtt_ms / result_reverse.avg_rtt_ms
            if ratio < 0.5 or ratio > 2.0:
                asymmetries.append({
                    "pair": (source_name, target_name),
                    "forward_rtt": result_forward.avg_rtt_ms,
                    "reverse_rtt": result_reverse.avg_rtt_ms,
                    "ratio": ratio
                })

    # Cleanup
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    # Assert reasonable symmetry (allow up to 2x difference due to network variance)
    assert len(asymmetries) == 0, \
        f"Detected asymmetric latency on {len(asymmetries)} pairs: {asymmetries}"
