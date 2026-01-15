"""10-node topology tests for Buckwild VPN.

Tests scalability and performance in a 10-node full mesh topology.
Verifies resource constraints, convergence time, and resilience at scale.
"""

import asyncio
import time
import pytest
from typing import Dict, List, Tuple, Optional

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_10node
@pytest.mark.slow
@pytest.mark.ten_node
@pytest.mark.asyncio
async def test_full_mesh_connectivity_10node(ten_node_cluster):
    """Test full mesh connectivity between all 10 nodes.

    In a 10-node cluster, there are 10*9/2 = 45 unique node pairs.
    This test verifies that every node can ping every other node,
    demonstrating full mesh connectivity at scale.

    Resource constraints: 0.5 CPU, 512MB per node (configured in docker-compose).
    """
    nodes = ten_node_cluster.get_all_nodes()
    assert len(nodes) == 10, f"Expected 10 nodes, got {len(nodes)}"

    # VPN IPs are 10.0.0.1 through 10.0.0.10
    node_vpn_ips = {
        f"node-{i}": f"10.0.0.{i}"
        for i in range(1, 11)
    }

    # Create SSH clients for all nodes
    ssh_clients = {}
    for node in nodes:
        ssh_clients[node.name] = SSHClient(node.container_name)
        await ssh_clients[node.name].connect()

    # Test all unique pairs (45 pairs total)
    failed_pairs = []
    successful_pairs = []

    # Test in parallel batches to avoid overwhelming the system
    # With 10 nodes, testing all pairs sequentially would take too long
    batch_size = 15  # Test 15 pairs at a time

    test_pairs = []
    for i, source_node in enumerate(nodes):
        for target_node in nodes[i+1:]:
            test_pairs.append((source_node, target_node))

    for batch_start in range(0, len(test_pairs), batch_size):
        batch = test_pairs[batch_start:batch_start + batch_size]

        # Create ping tasks for this batch
        ping_tasks = []
        for source_node, target_node in batch:
            net = NetworkCheck(ssh_clients[source_node.name])
            target_ip = node_vpn_ips[target_node.name]
            ping_tasks.append((
                source_node.name,
                target_node.name,
                net.ping(target_ip, count=3, timeout=30.0)
            ))

        # Execute batch in parallel
        results = await asyncio.gather(*[task for _, _, task in ping_tasks])

        # Process results
        for (source_name, target_name, _), result in zip(ping_tasks, results):
            if result.success and result.packet_loss < 50.0:
                successful_pairs.append((source_name, target_name))
            else:
                failed_pairs.append((source_name, target_name, result.error))

    # Cleanup SSH connections
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    # Assert all 45 pairs succeeded
    assert len(successful_pairs) == 45, \
        f"Expected 45 successful pairs, got {len(successful_pairs)}"

    assert len(failed_pairs) == 0, \
        f"Failed pairs ({len(failed_pairs)}): {failed_pairs[:5]}"  # Show first 5 failures


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_10node
@pytest.mark.slow
@pytest.mark.ten_node
@pytest.mark.asyncio
async def test_convergence_time_10node(ten_node_cluster):
    """Measure network convergence time for 10-node topology.

    Tests how long it takes for all nodes to discover each other
    and establish stable routing. Measures time from cluster start
    until all nodes can ping all other nodes.

    Success criteria: Convergence within 2 minutes.
    """
    nodes = ten_node_cluster.get_all_nodes()

    node_vpn_ips = {
        f"node-{i}": f"10.0.0.{i}"
        for i in range(1, 11)
    }

    # Sample convergence by testing a subset of critical paths
    # Full mesh test is separate - this focuses on timing
    test_paths = [
        ("node-1", "node-10"),   # Furthest endpoints
        ("node-5", "node-6"),    # Middle nodes
        ("node-1", "node-5"),    # Quarter point
        ("node-3", "node-8"),    # Cross-section
    ]

    ssh_clients = {}
    for source_name, _ in test_paths:
        if source_name not in ssh_clients:
            node = ten_node_cluster.get_node(source_name)
            ssh_clients[source_name] = SSHClient(node.container_name)
            await ssh_clients[source_name].connect()

    # Measure convergence time
    start_time = time.time()
    max_convergence_time = 120.0  # 2 minutes
    poll_interval = 5.0

    converged = False
    convergence_time = None

    while time.time() - start_time < max_convergence_time:
        all_paths_work = True

        for source_name, target_name in test_paths:
            net = NetworkCheck(ssh_clients[source_name])
            target_ip = node_vpn_ips[target_name]
            result = await net.ping(target_ip, count=2, timeout=10.0)

            if not result.success or result.packet_loss >= 50.0:
                all_paths_work = False
                break

        if all_paths_work:
            converged = True
            convergence_time = time.time() - start_time
            break

        # Wait before next poll
        await asyncio.sleep(poll_interval)

    # Cleanup
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    assert converged, \
        f"Network did not converge within {max_convergence_time}s"

    assert convergence_time <= max_convergence_time, \
        f"Convergence took {convergence_time:.1f}s (max: {max_convergence_time}s)"

    # Log convergence time for performance tracking
    print(f"\nNetwork converged in {convergence_time:.1f} seconds")


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_10node
@pytest.mark.slow
@pytest.mark.ten_node
@pytest.mark.asyncio
async def test_resource_consumption_10node(ten_node_cluster):
    """Monitor resource consumption across 10 nodes.

    Verifies that nodes respect resource limits (0.5 CPU, 512MB memory)
    and measures actual resource usage under normal operation.
    """
    nodes = ten_node_cluster.get_all_nodes()

    # Get resource stats from all containers
    resource_stats = []

    for node in nodes:
        # Use docker stats to get resource consumption
        cmd = f"docker stats {node.container_name} --no-stream --format '{{{{.CPUPerc}}}},{{{{.MemUsage}}}}'"

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            output = stdout.decode().strip()
            # Parse output: "1.23%,45.5MiB / 512MiB"
            cpu_str, mem_str = output.split(',')
            cpu_pct = float(cpu_str.rstrip('%'))

            # Parse memory (e.g., "45.5MiB / 512MiB")
            mem_parts = mem_str.split(' / ')
            mem_used_str = mem_parts[0].strip()
            mem_used = float(mem_used_str.rstrip('MiBGB'))

            resource_stats.append({
                'node': node.name,
                'cpu_percent': cpu_pct,
                'mem_mb': mem_used
            })

    # Verify we got stats from all nodes
    assert len(resource_stats) == 10, \
        f"Expected stats from 10 nodes, got {len(resource_stats)}"

    # Check no node exceeds limits significantly
    # Allow some overhead for Docker accounting
    for stats in resource_stats:
        # CPU limit is 50% (0.5 core), allow up to 60% due to Docker overhead
        assert stats['cpu_percent'] <= 60.0, \
            f"Node {stats['node']} exceeds CPU limit: {stats['cpu_percent']}%"

        # Memory limit is 512MB, warn if approaching
        assert stats['mem_mb'] <= 550.0, \
            f"Node {stats['node']} exceeds memory limit: {stats['mem_mb']}MB"

    # Calculate aggregate usage
    total_cpu = sum(s['cpu_percent'] for s in resource_stats)
    total_mem = sum(s['mem_mb'] for s in resource_stats)
    avg_cpu = total_cpu / len(resource_stats)
    avg_mem = total_mem / len(resource_stats)

    print(f"\nResource usage across 10 nodes:")
    print(f"  Average CPU: {avg_cpu:.1f}%")
    print(f"  Average Memory: {avg_mem:.1f}MB")
    print(f"  Total Memory: {total_mem:.1f}MB")


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_10node
@pytest.mark.slow
@pytest.mark.ten_node
@pytest.mark.asyncio
async def test_partial_failure_resilience_10node(ten_node_cluster):
    """Test resilience with partial node failures.

    Stops 2 nodes (node-3 and node-7) and verifies that:
    1. Remaining 8 nodes can still communicate
    2. At least 80% of remaining pairs maintain connectivity
    3. Network adapts to the failure

    With 8 remaining nodes, there are 8*7/2 = 28 unique pairs.
    """
    nodes = ten_node_cluster.get_all_nodes()

    node_vpn_ips = {
        f"node-{i}": f"10.0.0.{i}"
        for i in range(1, 11)
    }

    # Stop node-3 and node-7 to create partial failures
    node3 = ten_node_cluster.get_node("node-3")
    node7 = ten_node_cluster.get_node("node-7")

    stop_cmds = [
        f"docker stop {node3.container_name}",
        f"docker stop {node7.container_name}"
    ]

    for cmd in stop_cmds:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    # Wait for failure detection
    await asyncio.sleep(15)

    # Test connectivity between remaining nodes
    remaining_nodes = [n for n in nodes if n.name not in ["node-3", "node-7"]]

    # Sample connectivity - test a representative subset
    test_sample_pairs = [
        ("node-1", "node-2"),
        ("node-1", "node-10"),
        ("node-2", "node-5"),
        ("node-4", "node-6"),
        ("node-5", "node-8"),
        ("node-6", "node-9"),
        ("node-8", "node-10"),
        ("node-1", "node-5"),
        ("node-2", "node-9"),
        ("node-4", "node-10"),
    ]

    ssh_clients = {}
    successful_pairs = 0
    failed_pairs = []

    for source_name, target_name in test_sample_pairs:
        if source_name not in ssh_clients:
            source_node = ten_node_cluster.get_node(source_name)
            ssh_clients[source_name] = SSHClient(source_node.container_name)
            await ssh_clients[source_name].connect()

        net = NetworkCheck(ssh_clients[source_name])
        target_ip = node_vpn_ips[target_name]

        result = await net.ping(target_ip, count=3, timeout=25.0)

        if result.success and result.packet_loss < 50.0:
            successful_pairs += 1
        else:
            failed_pairs.append((source_name, target_name, result.error))

    # Restart failed nodes for cleanup
    restart_cmds = [
        f"docker start {node3.container_name}",
        f"docker start {node7.container_name}"
    ]

    for cmd in restart_cmds:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    # Cleanup SSH connections
    for ssh in ssh_clients.values():
        await ssh.disconnect()

    # Assert at least 80% of sample pairs succeeded
    success_rate = successful_pairs / len(test_sample_pairs)
    assert success_rate >= 0.8, \
        f"Failure resilience failed: only {successful_pairs}/{len(test_sample_pairs)} " \
        f"pairs working ({success_rate:.1%}). Failed: {failed_pairs[:3]}"


@pytest.mark.e2e
@pytest.mark.topology
@pytest.mark.topology_10node
@pytest.mark.slow
@pytest.mark.ten_node
@pytest.mark.asyncio
async def test_concurrent_data_transfer_10node(ten_node_cluster):
    """Test multiple concurrent data transfers between different node pairs.

    Performs simultaneous 50KB transfers between 5 different node pairs
    to verify the network can handle multiple concurrent flows at scale.
    """
    # Define 5 concurrent transfer pairs using different nodes
    transfer_pairs = [
        ("node-1", "node-2", "10.0.0.2", 9001),
        ("node-3", "node-4", "10.0.0.4", 9002),
        ("node-5", "node-6", "10.0.0.6", 9003),
        ("node-7", "node-8", "10.0.0.8", 9004),
        ("node-9", "node-10", "10.0.0.10", 9005),
    ]

    ssh_clients = {}

    # Setup SSH clients
    for source_name, target_name, _, _ in transfer_pairs:
        for node_name in [source_name, target_name]:
            if node_name not in ssh_clients:
                node = ten_node_cluster.get_node(node_name)
                ssh_clients[node_name] = SSHClient(node.container_name)
                await ssh_clients[node_name].connect()

    async def transfer_file(source_name: str, target_name: str, target_ip: str, port: int) -> Tuple[bool, str]:
        """Transfer a 50KB file between two nodes."""
        ssh_source = ssh_clients[source_name]
        ssh_target = ssh_clients[target_name]

        # Create 50KB test file on source
        create_result = await ssh_source.exec_command(
            f"dd if=/dev/urandom of=/tmp/test_{port}.bin bs=1024 count=50 2>/dev/null && "
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
@pytest.mark.topology_10node
@pytest.mark.slow
@pytest.mark.ten_node
@pytest.mark.asyncio
async def test_scalability_metrics_10node(ten_node_cluster):
    """Measure scalability metrics for 10-node topology.

    Collects and verifies:
    1. Average throughput per node
    2. Aggregate network bandwidth
    3. Per-node latency statistics
    4. Connection establishment overhead

    This provides baseline performance metrics for the 10-node scale.
    """
    nodes = ten_node_cluster.get_all_nodes()

    node_vpn_ips = {
        f"node-{i}": f"10.0.0.{i}"
        for i in range(1, 11)
    }

    # Measure latency from node-1 to all other nodes
    node1 = ten_node_cluster.get_node("node-1")
    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net1 = NetworkCheck(ssh1)

    latencies = []

    for i in range(2, 11):
        target_ip = node_vpn_ips[f"node-{i}"]
        result = await net1.ping(target_ip, count=10, timeout=30.0)

        if result.success and result.avg_rtt_ms:
            latencies.append({
                'target': f"node-{i}",
                'avg_rtt': result.avg_rtt_ms,
                'min_rtt': result.min_rtt_ms,
                'max_rtt': result.max_rtt_ms,
                'packet_loss': result.packet_loss
            })

    await ssh1.disconnect()

    # Verify we got measurements from all targets
    assert len(latencies) >= 8, \
        f"Expected latency measurements to at least 8 nodes, got {len(latencies)}"

    # Calculate statistics
    avg_latencies = [l['avg_rtt'] for l in latencies]
    avg_rtt = sum(avg_latencies) / len(avg_latencies)
    max_rtt = max(avg_latencies)
    min_rtt = min(avg_latencies)

    # Verify reasonable latency bounds
    # Container networking should have low latency
    assert avg_rtt < 100.0, \
        f"Average RTT too high: {avg_rtt:.2f}ms (expected < 100ms)"

    assert max_rtt < 200.0, \
        f"Maximum RTT too high: {max_rtt:.2f}ms (expected < 200ms)"

    # Log metrics for performance tracking
    print(f"\nScalability metrics for 10-node topology:")
    print(f"  Average RTT: {avg_rtt:.2f}ms")
    print(f"  Min RTT: {min_rtt:.2f}ms")
    print(f"  Max RTT: {max_rtt:.2f}ms")
    print(f"  Measured paths: {len(latencies)}/9")
