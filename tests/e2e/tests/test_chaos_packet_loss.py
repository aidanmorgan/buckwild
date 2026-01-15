"""Chaos testing: Packet loss scenarios.

Tests the protocol's ability to handle packet loss and retransmission.
"""

import os
import time

import pytest

from framework.chaos import (
    apply_packet_loss,
    apply_scenario,
    clear_all_faults,
    get_scenario,
)
from framework.transfer_client import (
    NODES_2,
    check_node_health,
    trigger_upload,
)


def get_duration() -> int:
    """Get test duration from env var, default 30 seconds."""
    return int(os.environ.get("BUCKWILD_TRANSFER_DURATION", "30"))


@pytest.fixture(autouse=True)
async def cleanup_chaos():
    """Automatically clean up chaos rules after each test."""
    yield
    # Clean up all nodes after test
    for node in NODES_2:
        await clear_all_faults(node)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_1pct_packet_loss():
    """Test data transfer with 1% random packet loss."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 1% packet loss to both nodes
    await apply_packet_loss(source, loss_pct=1.0)
    await apply_packet_loss(target, loss_pct=1.0)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=90)
        assert result.success, f"Transfer failed with 1% loss: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch with 1% loss: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_5pct_packet_loss():
    """Test data transfer with 5% random packet loss."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 5% packet loss to both nodes
    await apply_packet_loss(source, loss_pct=5.0)
    await apply_packet_loss(target, loss_pct=5.0)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=120)
        assert result.success, f"Transfer failed with 5% loss: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch with 5% loss: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_10pct_packet_loss():
    """Test data transfer with 10% random packet loss."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 10% packet loss to both nodes
    await apply_packet_loss(source, loss_pct=10.0)
    await apply_packet_loss(target, loss_pct=10.0)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=180)
        assert result.success, f"Transfer failed with 10% loss: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch with 10% loss: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_bursty_packet_loss():
    """Test data transfer with bursty packet loss (20% loss, 50% correlation)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply bursty packet loss (Gilbert-Elliott model)
    await apply_packet_loss(source, loss_pct=20.0, correlation=50)
    await apply_packet_loss(target, loss_pct=20.0, correlation=50)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=240)
        assert result.success, f"Transfer failed with bursty loss: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch with bursty loss: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_mobile_3g_scenario():
    """Test mobile 3G scenario (200ms±100ms, 2% loss, 5% reorder)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    scenario = get_scenario("mobile_3g")

    await apply_scenario(source, scenario)
    await apply_scenario(target, scenario)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=180)
        assert result.success, f"Transfer failed in 3G scenario: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch in 3G scenario: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_flaky_wifi_scenario():
    """Test flaky WiFi scenario (20ms±50ms, 5% loss, 50% correlation)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    scenario = get_scenario("flaky_wifi")

    await apply_scenario(source, scenario)
    await apply_scenario(target, scenario)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=150)
        assert result.success, f"Transfer failed in WiFi scenario: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch in WiFi scenario: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_recovery_after_packet_loss():
    """Test protocol recovery after packet loss is removed."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # First transfer with packet loss
    await apply_packet_loss(source, loss_pct=10.0)
    await apply_packet_loss(target, loss_pct=10.0)

    result1 = await trigger_upload(source, target, size=50 * 1024, timeout=180)
    assert result1.success, f"Transfer failed with loss: {result1.error}"
    assert result1.hashes_match()

    # Remove packet loss
    await clear_all_faults(source)
    await clear_all_faults(target)

    # Second transfer without loss - should be faster
    result2 = await trigger_upload(source, target, size=50 * 1024, timeout=60)
    assert result2.success, f"Transfer failed after loss removal: {result2.error}"
    assert result2.hashes_match()

    # Recovery means faster transfer
    assert result2.duration_ms < result1.duration_ms, (
        f"Expected faster transfer after loss removal: {result1.duration_ms}ms -> {result2.duration_ms}ms"
    )


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_asymmetric_packet_loss():
    """Test with asymmetric packet loss (only one direction lossy)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply packet loss only to source node (asymmetric)
    await apply_packet_loss(source, loss_pct=10.0)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=150)
        assert result.success, f"Transfer failed with asymmetric loss: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch with asymmetric loss: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_continuous_transfer_under_packet_loss():
    """Run continuous transfers under packet loss for configured duration."""
    source, target = NODES_2
    duration = get_duration()

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 5% packet loss
    await apply_packet_loss(source, loss_pct=5.0)
    await apply_packet_loss(target, loss_pct=5.0)

    try:
        start = time.monotonic()
        transfers = 0

        while time.monotonic() - start < duration:
            result = await trigger_upload(source, target, size=50 * 1024, timeout=120)
            assert result.success, f"Transfer {transfers} failed: {result.error}"
            assert result.hashes_match()
            transfers += 1

        print(f"Completed {transfers} transfers under 5% packet loss in {duration}s")
        assert transfers > 0, "No transfers completed"

    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)
