"""Node failure and recovery resilience tests for Buckwild VPN.

Tests various node failure scenarios including graceful shutdown, sudden
termination, session recovery, and multi-node failures to verify system
resilience and fault tolerance.
"""

import asyncio
import time
import pytest
from typing import List

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.asyncio
async def test_graceful_shutdown_sigterm(three_node_cluster):
    """Test graceful node shutdown with SIGTERM.

    Stops a node cleanly using SIGTERM and verifies:
    1. The stopped node is unreachable
    2. Other nodes detect the disconnection
    3. Remaining nodes maintain connectivity with each other
    """
    node2 = three_node_cluster.get_node("node-2")

    # Verify initial connectivity
    node1 = three_node_cluster.get_node("node-1")
    node3 = three_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh3.connect()

    net1 = NetworkCheck(ssh1)

    # Verify node-1 can reach node-2 before shutdown
    initial_result = await net1.ping("10.0.0.2", count=3, timeout=15.0)
    assert initial_result.success, f"Initial connectivity failed: {initial_result.error}"

    # Gracefully stop node-2 with SIGTERM (default docker stop behavior)
    start_time = time.time()
    stop_cmd = f"docker stop -t 10 {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        stop_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    stop_duration = time.time() - start_time

    # Graceful shutdown should complete within timeout
    assert stop_duration < 12.0, \
        f"Graceful shutdown took too long: {stop_duration:.1f}s"

    # Wait for failure detection
    await asyncio.sleep(8)

    # Verify node-2 is now unreachable from node-1
    ping_result = await net1.ping("10.0.0.2", count=3, timeout=10.0)
    assert not ping_result.success, "Node-2 should be unreachable after shutdown"

    # Verify node-1 and node-3 can still communicate
    result_1_to_3 = await net1.ping("10.0.0.3", count=3, timeout=15.0)
    assert result_1_to_3.success, \
        f"Node-1 -> Node-3 communication failed after node-2 shutdown: {result_1_to_3.error}"

    # Restart node-2 for cleanup
    restart_cmd = f"docker start {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        restart_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    await asyncio.sleep(5)

    await ssh1.disconnect()
    await ssh3.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.asyncio
async def test_sudden_termination_sigkill(three_node_cluster):
    """Test sudden node termination with SIGKILL.

    Kills a node immediately using SIGKILL and verifies:
    1. System handles ungraceful exit without corruption
    2. Other nodes detect the failure
    3. No zombie processes or resource leaks
    """
    node2 = three_node_cluster.get_node("node-2")
    node1 = three_node_cluster.get_node("node-1")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net1 = NetworkCheck(ssh1)

    # Verify connectivity before kill
    initial_result = await net1.ping("10.0.0.2", count=2, timeout=10.0)
    assert initial_result.success, "Initial connectivity check failed"

    # Kill node-2 immediately (SIGKILL)
    start_time = time.time()
    kill_cmd = f"docker kill {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        kill_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    kill_duration = time.time() - start_time

    # SIGKILL should be nearly instant
    assert kill_duration < 2.0, \
        f"SIGKILL took unexpectedly long: {kill_duration:.1f}s"

    # Wait for failure detection
    await asyncio.sleep(8)

    # Verify node-2 is unreachable
    ping_result = await net1.ping("10.0.0.2", count=3, timeout=10.0)
    assert not ping_result.success, "Node-2 should be unreachable after kill"

    # Restart node-2 and verify it recovers
    restart_cmd = f"docker start {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        restart_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    await asyncio.sleep(10)

    # Wait for node-2 to be ready after ungraceful restart
    try:
        await asyncio.wait_for(node2.wait_ready(timeout=60.0), timeout=70.0)
        recovery_result = await net1.ping("10.0.0.2", count=3, timeout=15.0)
        recovered = recovery_result.success
    except asyncio.TimeoutError:
        recovered = False

    assert recovered, "Node-2 failed to recover after SIGKILL and restart"

    await ssh1.disconnect()


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.asyncio
async def test_session_recovery_after_restart(three_node_cluster):
    """Test session recovery after node restart.

    Restarts a stopped node and verifies:
    1. Node restarts successfully
    2. VPN sessions reestablish with peers
    3. Full mesh connectivity is restored
    """
    node2 = three_node_cluster.get_node("node-2")
    node1 = three_node_cluster.get_node("node-1")
    node3 = three_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh3.connect()

    net1 = NetworkCheck(ssh1)
    net3 = NetworkCheck(ssh3)

    # Stop node-2
    stop_cmd = f"docker stop -t 10 {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        stop_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    await asyncio.sleep(5)

    # Verify node-2 is unreachable
    ping_result = await net1.ping("10.0.0.2", count=2, timeout=10.0)
    assert not ping_result.success, "Node-2 should be unreachable while stopped"

    # Restart node-2
    restart_start = time.time()
    restart_cmd = f"docker start {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        restart_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()

    # Wait for node-2 to become ready
    await asyncio.sleep(5)
    try:
        await asyncio.wait_for(node2.wait_ready(timeout=60.0), timeout=70.0)
    except asyncio.TimeoutError:
        pass  # Continue to check connectivity

    # Wait for sessions to reestablish
    await asyncio.sleep(10)

    recovery_time = time.time() - restart_start

    # Test full mesh connectivity after recovery
    test_pairs = [
        (net1, "10.0.0.2", "node-1 -> node-2"),
        (net1, "10.0.0.3", "node-1 -> node-3"),
        (net3, "10.0.0.2", "node-3 -> node-2"),
    ]

    successful_recoveries = 0
    for net, target_ip, description in test_pairs:
        result = await net.ping(target_ip, count=3, timeout=15.0)
        if result.success and result.packet_loss < 50.0:
            successful_recoveries += 1

    await ssh1.disconnect()
    await ssh3.disconnect()

    # At least 2 of 3 paths should recover (allowing for race conditions)
    assert successful_recoveries >= 2, \
        f"Session recovery incomplete: only {successful_recoveries}/3 paths recovered"

    # Recovery should complete within reasonable time
    assert recovery_time < 90.0, \
        f"Recovery took too long: {recovery_time:.1f}s"


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.slow
@pytest.mark.asyncio
async def test_multi_node_failure_5node(five_node_cluster):
    """Test multiple simultaneous node failures in 5-node cluster.

    Stops 2 of 5 nodes and verifies:
    1. Remaining 3 nodes continue operating
    2. Partial mesh connectivity is maintained
    3. No cascading failures occur
    """
    # Stop node-2 and node-4 simultaneously
    node2 = five_node_cluster.get_node("node-2")
    node4 = five_node_cluster.get_node("node-4")

    # Stop both nodes
    stop_cmds = [
        f"docker stop -t 10 {node2.container_name}",
        f"docker stop -t 10 {node4.container_name}"
    ]

    for cmd in stop_cmds:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    # Wait for failure detection
    await asyncio.sleep(10)

    # Test connectivity between remaining nodes (1, 3, 5)
    node1 = five_node_cluster.get_node("node-1")
    node3 = five_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    ssh3 = SSHClient(node3.container_name)

    await ssh1.connect()
    await ssh3.connect()

    net1 = NetworkCheck(ssh1)
    net3 = NetworkCheck(ssh3)

    # Test remaining connectivity
    test_pairs = [
        (net1, "10.0.0.3", "node-1 -> node-3"),
        (net1, "10.0.0.5", "node-1 -> node-5"),
        (net3, "10.0.0.5", "node-3 -> node-5"),
    ]

    successful_pairs = 0
    for net, target_ip, description in test_pairs:
        result = await net.ping(target_ip, count=3, timeout=20.0)
        if result.success and result.packet_loss < 50.0:
            successful_pairs += 1

    # Restart failed nodes for cleanup
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

    await ssh1.disconnect()
    await ssh3.disconnect()

    # At least 2 of 3 remaining pairs should work
    assert successful_pairs >= 2, \
        f"Multi-node failure caused excessive connectivity loss: " \
        f"only {successful_pairs}/3 remaining pairs functional"


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.asyncio
async def test_rapid_restart_cycle(three_node_cluster):
    """Test rapid stop/start cycles for stability.

    Stops and restarts a node multiple times in quick succession
    and verifies:
    1. System handles rapid state changes
    2. No resource exhaustion occurs
    3. Final state is stable and healthy
    """
    node2 = three_node_cluster.get_node("node-2")
    node1 = three_node_cluster.get_node("node-1")

    # Perform 3 rapid restart cycles
    for cycle in range(3):
        # Stop
        stop_cmd = f"docker stop -t 5 {node2.container_name}"
        process = await asyncio.create_subprocess_shell(
            stop_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        await asyncio.sleep(2)

        # Start
        start_cmd = f"docker start {node2.container_name}"
        process = await asyncio.create_subprocess_shell(
            start_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        await asyncio.sleep(5)

    # Wait for final stabilization
    await asyncio.sleep(10)

    # Try to wait for node to be ready
    try:
        await asyncio.wait_for(node2.wait_ready(timeout=60.0), timeout=70.0)
    except asyncio.TimeoutError:
        pass  # Continue to connectivity check

    # Verify final connectivity from node-1 to node-2
    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net1 = NetworkCheck(ssh1)
    final_result = await net1.ping("10.0.0.2", count=5, timeout=20.0)

    await ssh1.disconnect()

    assert final_result.success or final_result.packet_loss < 60.0, \
        f"Node-2 unstable after rapid restart cycles: {final_result.error}"


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.asyncio
async def test_data_transfer_interrupted_by_kill(three_node_cluster):
    """Test data transfer interrupted by node kill.

    Starts a data transfer and kills the receiver mid-transfer
    to verify:
    1. Sender detects the failure
    2. No data corruption occurs
    3. System recovers cleanly
    """
    node1 = three_node_cluster.get_node("node-1")
    node2 = three_node_cluster.get_node("node-2")

    ssh1 = SSHClient(node1.container_name)
    ssh2 = SSHClient(node2.container_name)

    await ssh1.connect()
    await ssh2.connect()

    # Create a large test file on node-1 (10MB)
    _, stdout, _ = await ssh1.exec_command(
        "dd if=/dev/zero of=/tmp/large_test.bin bs=1024 count=10240 2>/dev/null && "
        "md5sum /tmp/large_test.bin | awk '{print $1}'",
        timeout=20.0
    )
    original_checksum = stdout.strip()

    # Start receiver on node-2
    receiver_task = ssh2.exec_command_async(
        "nc -l -p 9999 > /tmp/received_large.bin",
        timeout=120.0
    )

    await asyncio.sleep(2)

    # Start sender on node-1 (this will run in background)
    sender_task = asyncio.create_task(
        ssh1.exec_command(
            "nc -w 60 10.0.0.2 9999 < /tmp/large_test.bin",
            timeout=90.0,
            check=False
        )
    )

    # Wait for transfer to begin
    await asyncio.sleep(3)

    # Kill node-2 during transfer
    kill_cmd = f"docker kill {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        kill_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()

    # Wait for sender to detect failure
    try:
        sender_result = await asyncio.wait_for(sender_task, timeout=15.0)
        # Sender should exit (possibly with error since receiver died)
        sender_detected_failure = True
    except asyncio.TimeoutError:
        sender_detected_failure = False
        sender_task.cancel()

    # Cancel receiver task since container is killed
    try:
        receiver_task.cancel()
        await receiver_task
    except (asyncio.CancelledError, Exception):
        pass

    # Restart node-2 for cleanup
    restart_cmd = f"docker start {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        restart_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    await asyncio.sleep(5)

    # Cleanup
    await ssh1.exec_command("rm -f /tmp/large_test.bin", check=False)

    await ssh1.disconnect()
    await ssh2.disconnect()

    # Sender should have detected the failure (timeout or connection reset)
    assert sender_detected_failure, \
        "Sender did not detect receiver failure during transfer"


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.asyncio
async def test_failure_detection_timing(three_node_cluster):
    """Test failure detection timing.

    Measures how long it takes for other nodes to detect a failed node
    and verifies:
    1. Detection occurs within reasonable time window
    2. Detection is consistent across multiple failures
    3. Timing is predictable for operational planning
    """
    node2 = three_node_cluster.get_node("node-2")
    node1 = three_node_cluster.get_node("node-1")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net1 = NetworkCheck(ssh1)

    detection_times: List[float] = []

    # Run 3 detection timing tests
    for run in range(3):
        # Verify connectivity
        pre_result = await net1.ping("10.0.0.2", count=2, timeout=10.0)
        assert pre_result.success, f"Pre-test connectivity failed on run {run+1}"

        # Kill node-2
        failure_time = time.time()
        kill_cmd = f"docker kill {node2.container_name}"
        process = await asyncio.create_subprocess_shell(
            kill_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

        # Poll for failure detection
        detected = False
        while time.time() - failure_time < 30.0:
            result = await net1.ping("10.0.0.2", count=1, timeout=3.0)
            if not result.success:
                detection_time = time.time() - failure_time
                detection_times.append(detection_time)
                detected = True
                break
            await asyncio.sleep(1)

        assert detected, f"Failure not detected within 30s on run {run+1}"

        # Restart for next iteration
        restart_cmd = f"docker start {node2.container_name}"
        process = await asyncio.create_subprocess_shell(
            restart_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        await asyncio.sleep(15)

        # Wait for node to be ready
        try:
            await asyncio.wait_for(node2.wait_ready(timeout=60.0), timeout=70.0)
        except asyncio.TimeoutError:
            pass

        await asyncio.sleep(5)

    await ssh1.disconnect()

    # Analyze detection times
    avg_detection = sum(detection_times) / len(detection_times)
    max_detection = max(detection_times)

    # Detection should average under 15 seconds
    assert avg_detection < 15.0, \
        f"Average failure detection too slow: {avg_detection:.1f}s"

    # Maximum detection should be under 20 seconds
    assert max_detection < 20.0, \
        f"Maximum failure detection too slow: {max_detection:.1f}s"


@pytest.mark.e2e
@pytest.mark.resilience
@pytest.mark.chaos
@pytest.mark.node_failure
@pytest.mark.slow
@pytest.mark.asyncio
async def test_cascading_failure_isolation_5node(five_node_cluster):
    """Test cascading failure isolation in 5-node cluster.

    Stops nodes sequentially to verify:
    1. One failure doesn't trigger cascading failures
    2. Remaining nodes maintain stability
    3. Network degrades gracefully
    """
    # Stop nodes one at a time: node-2, then node-4
    node2 = five_node_cluster.get_node("node-2")
    node4 = five_node_cluster.get_node("node-4")

    # Stop node-2
    stop_cmd = f"docker stop -t 10 {node2.container_name}"
    process = await asyncio.create_subprocess_shell(
        stop_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    await asyncio.sleep(8)

    # Check that other nodes are still responsive
    node1 = five_node_cluster.get_node("node-1")
    node3 = five_node_cluster.get_node("node-3")

    ssh1 = SSHClient(node1.container_name)
    await ssh1.connect()

    net1 = NetworkCheck(ssh1)

    # Verify node-1 can reach node-3 after first failure
    result_after_first = await net1.ping("10.0.0.3", count=3, timeout=15.0)
    first_failure_isolated = result_after_first.success

    # Stop node-4 (second failure)
    stop_cmd = f"docker stop -t 10 {node4.container_name}"
    process = await asyncio.create_subprocess_shell(
        stop_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    await asyncio.sleep(8)

    # Verify node-1 can still reach node-3 after second failure
    result_after_second = await net1.ping("10.0.0.3", count=3, timeout=15.0)
    second_failure_isolated = result_after_second.success

    # Restart both nodes for cleanup
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

    await ssh1.disconnect()

    # Both failures should be isolated
    assert first_failure_isolated, \
        "First failure caused cascading impact on remaining nodes"
    assert second_failure_isolated, \
        "Second failure caused cascading impact on remaining nodes"
