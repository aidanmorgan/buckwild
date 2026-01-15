"""Chaos testing: Network partition scenarios.

Tests the protocol's ability to detect and handle network partitions.
"""

import pytest

from framework.chaos import apply_partition, clear_all_faults
from framework.transfer_client import (
    NODES_2,
    NODES_3,
    check_node_health,
    get_tun_ip,
    trigger_upload,
)


@pytest.fixture(autouse=True)
async def cleanup_chaos():
    """Automatically clean up chaos rules after each test."""
    yield
    # Clean up all nodes after test
    for node in NODES_3:
        await clear_all_faults(node)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_single_node_isolation():
    """Test complete isolation of a single node."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Isolate source from target
    target_ip = get_tun_ip(target)
    await apply_partition(source, target_ip)

    try:
        # Transfer should fail - source cannot reach target
        result = await trigger_upload(source, target, size=10 * 1024, timeout=30)
        assert not result.success, "Transfer should fail during partition"
        assert result.error, "Expected error message for partition"

    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_partition_healing():
    """Test connectivity restoration after partition healing."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # First transfer - should succeed
    result1 = await trigger_upload(source, target, size=50 * 1024, timeout=60)
    assert result1.success, f"Initial transfer failed: {result1.error}"
    assert result1.hashes_match()

    # Partition the network
    target_ip = get_tun_ip(target)
    await apply_partition(source, target_ip)

    # Transfer should fail during partition
    result2 = await trigger_upload(source, target, size=10 * 1024, timeout=30)
    assert not result2.success, "Transfer should fail during partition"

    # Heal partition
    await clear_all_faults(source)

    # Transfer should succeed after healing
    result3 = await trigger_upload(source, target, size=50 * 1024, timeout=60)
    assert result3.success, f"Transfer failed after healing: {result3.error}"
    assert result3.hashes_match()


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_asymmetric_partition():
    """Test asymmetric partition (A can reach B, but B cannot reach A)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Block target from reaching source (asymmetric)
    source_ip = get_tun_ip(source)
    await apply_partition(target, source_ip)

    try:
        # Source can reach target, but response path is blocked
        result = await trigger_upload(source, target, size=10 * 1024, timeout=30)

        # Protocol should detect asymmetric partition
        # This may succeed or fail depending on how protocol handles asymmetry
        if not result.success:
            assert result.error, "Expected error for asymmetric partition"

    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_network_split_3node():
    """Test network split in 3-node topology (node-01 vs node-02 + node-03)."""
    node1, node2, node3 = NODES_3

    # Verify nodes are healthy before applying chaos
    for node in NODES_3:
        assert await check_node_health(node), f"{node} not healthy"

    # Isolate node1 from node2 and node3
    node2_ip = get_tun_ip(node2)
    node3_ip = get_tun_ip(node3)

    await apply_partition(node1, node2_ip)
    await apply_partition(node1, node3_ip)

    try:
        # node1 cannot reach node2
        result1 = await trigger_upload(node1, node2, size=10 * 1024, timeout=30)
        assert not result1.success, "Transfer to node2 should fail"

        # node1 cannot reach node3
        result2 = await trigger_upload(node1, node3, size=10 * 1024, timeout=30)
        assert not result2.success, "Transfer to node3 should fail"

        # node2 can still reach node3 (they are on same side of split)
        result3 = await trigger_upload(node2, node3, size=50 * 1024, timeout=60)
        assert result3.success, f"Transfer node2→node3 failed: {result3.error}"
        assert result3.hashes_match()

    finally:
        for node in NODES_3:
            await clear_all_faults(node)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_partial_connectivity_3node():
    """Test partial connectivity in 3-node topology."""
    node1, node2, node3 = NODES_3

    # Verify nodes are healthy before applying chaos
    for node in NODES_3:
        assert await check_node_health(node), f"{node} not healthy"

    # Block only node1 → node2 path
    node2_ip = get_tun_ip(node2)
    await apply_partition(node1, node2_ip)

    try:
        # node1 cannot reach node2
        result1 = await trigger_upload(node1, node2, size=10 * 1024, timeout=30)
        assert not result1.success, "Transfer node1→node2 should fail"

        # node1 can still reach node3
        result2 = await trigger_upload(node1, node3, size=50 * 1024, timeout=60)
        assert result2.success, f"Transfer node1→node3 failed: {result2.error}"
        assert result2.hashes_match()

        # node2 can reach node3
        result3 = await trigger_upload(node2, node3, size=50 * 1024, timeout=60)
        assert result3.success, f"Transfer node2→node3 failed: {result3.error}"
        assert result3.hashes_match()

    finally:
        for node in NODES_3:
            await clear_all_faults(node)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transitive_connectivity_3node():
    """Test transitive connectivity failure (A→B, B→C, but not A→C directly)."""
    node1, node2, node3 = NODES_3

    # Verify nodes are healthy before applying chaos
    for node in NODES_3:
        assert await check_node_health(node), f"{node} not healthy"

    # Block direct path node1 → node3
    node3_ip = get_tun_ip(node3)
    await apply_partition(node1, node3_ip)

    try:
        # node1 cannot reach node3 directly
        result1 = await trigger_upload(node1, node3, size=10 * 1024, timeout=30)
        assert not result1.success, "Direct transfer node1→node3 should fail"

        # node1 can reach node2
        result2 = await trigger_upload(node1, node2, size=50 * 1024, timeout=60)
        assert result2.success, f"Transfer node1→node2 failed: {result2.error}"
        assert result2.hashes_match()

        # node2 can reach node3
        result3 = await trigger_upload(node2, node3, size=50 * 1024, timeout=60)
        assert result3.success, f"Transfer node2→node3 failed: {result3.error}"
        assert result3.hashes_match()

    finally:
        for node in NODES_3:
            await clear_all_faults(node)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_bidirectional_partition():
    """Test bidirectional partition (both directions blocked)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Block both directions
    target_ip = get_tun_ip(target)
    source_ip = get_tun_ip(source)

    await apply_partition(source, target_ip)
    await apply_partition(target, source_ip)

    try:
        # source → target should fail
        result1 = await trigger_upload(source, target, size=10 * 1024, timeout=30)
        assert not result1.success, "Transfer source→target should fail"

        # target → source should also fail
        result2 = await trigger_upload(target, source, size=10 * 1024, timeout=30)
        assert not result2.success, "Transfer target→source should fail"

    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_rolling_partition_healing():
    """Test rolling partition and healing cycle."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    target_ip = get_tun_ip(target)

    # Cycle: partition → heal → partition → heal
    for cycle in range(3):
        # Apply partition
        await apply_partition(source, target_ip)

        # Verify partition active
        result_partitioned = await trigger_upload(
            source, target, size=10 * 1024, timeout=30
        )
        assert not result_partitioned.success, (
            f"Cycle {cycle}: Transfer should fail during partition"
        )

        # Heal partition
        await clear_all_faults(source)

        # Verify healing successful
        result_healed = await trigger_upload(source, target, size=50 * 1024, timeout=60)
        assert result_healed.success, (
            f"Cycle {cycle}: Transfer failed after healing: {result_healed.error}"
        )
        assert result_healed.hashes_match()

    # Final cleanup
    await clear_all_faults(source)
    await clear_all_faults(target)
