"""Chaos testing: Latency and jitter scenarios.

Tests the protocol's ability to handle high-latency and variable-latency connections.
"""

import os
import time

import pytest

from framework.chaos import (
    apply_latency,
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
async def test_transfer_with_50ms_latency():
    """Test data transfer with 50ms fixed latency (typical WAN)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 50ms latency to both nodes
    await apply_latency(source, delay_ms=50)
    await apply_latency(target, delay_ms=50)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=60)
        assert result.success, f"Transfer failed with 50ms latency: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_100ms_latency():
    """Test data transfer with 100ms fixed latency."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 100ms latency to both nodes
    await apply_latency(source, delay_ms=100)
    await apply_latency(target, delay_ms=100)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=90)
        assert result.success, f"Transfer failed with 100ms latency: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_500ms_latency():
    """Test data transfer with 500ms high latency (satellite-like)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 500ms latency to both nodes
    await apply_latency(source, delay_ms=500)
    await apply_latency(target, delay_ms=500)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=120)
        assert result.success, f"Transfer failed with 500ms latency: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_transfer_with_latency_and_jitter():
    """Test data transfer with latency and jitter (100ms ± 50ms)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 100ms latency with 50ms jitter to both nodes
    await apply_latency(source, delay_ms=100, jitter_ms=50)
    await apply_latency(target, delay_ms=100, jitter_ms=50)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=120)
        assert result.success, f"Transfer failed with jitter: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_wan_link_scenario():
    """Test WAN link scenario (50ms latency, 10ms jitter, 0.1% loss)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    scenario = get_scenario("wan_link")

    await apply_scenario(source, scenario)
    await apply_scenario(target, scenario)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=90)
        assert result.success, f"Transfer failed in WAN scenario: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_satellite_link_scenario():
    """Test satellite link scenario (600ms latency, 20ms jitter, 1% loss)."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    scenario = get_scenario("satellite_link")

    await apply_scenario(source, scenario)
    await apply_scenario(target, scenario)

    try:
        result = await trigger_upload(source, target, size=100 * 1024, timeout=180)
        assert result.success, f"Transfer failed in satellite scenario: {result.error}"
        assert result.hashes_match(), (
            f"SHA256 mismatch: "
            f"source={result.source_sha256[:16]}... "
            f"target={result.target_sha256[:16]}..."
        )
    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_recovery_after_latency_spike():
    """Test protocol recovery after latency spike is removed."""
    source, target = NODES_2

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # First transfer with high latency
    await apply_latency(source, delay_ms=500)
    await apply_latency(target, delay_ms=500)

    result1 = await trigger_upload(source, target, size=50 * 1024, timeout=120)
    assert result1.success, f"Transfer failed with latency: {result1.error}"
    assert result1.hashes_match()

    # Remove latency
    await clear_all_faults(source)
    await clear_all_faults(target)

    # Second transfer without latency - should be faster
    result2 = await trigger_upload(source, target, size=50 * 1024, timeout=60)
    assert result2.success, f"Transfer failed after latency removal: {result2.error}"
    assert result2.hashes_match()

    # Recovery means faster transfer
    assert result2.duration_ms < result1.duration_ms, (
        f"Expected faster transfer after latency removal: {result1.duration_ms}ms -> {result2.duration_ms}ms"
    )


@pytest.mark.e2e
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_continuous_transfer_under_latency():
    """Run continuous transfers under latency for configured duration."""
    source, target = NODES_2
    duration = get_duration()

    # Verify nodes are healthy before applying chaos
    for node in [source, target]:
        assert await check_node_health(node), f"{node} not healthy"

    # Apply 100ms latency
    await apply_latency(source, delay_ms=100)
    await apply_latency(target, delay_ms=100)

    try:
        start = time.monotonic()
        transfers = 0

        while time.monotonic() - start < duration:
            result = await trigger_upload(source, target, size=50 * 1024, timeout=90)
            assert result.success, f"Transfer {transfers} failed: {result.error}"
            assert result.hashes_match()
            transfers += 1

        print(f"Completed {transfers} transfers under 100ms latency in {duration}s")
        assert transfers > 0, "No transfers completed"

    finally:
        await clear_all_faults(source)
        await clear_all_faults(target)
