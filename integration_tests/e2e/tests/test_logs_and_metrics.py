"""Example tests demonstrating log and metrics collection utilities.

These tests show how to use the LogCollector and MetricsCollector
for debugging and monitoring during E2E tests.
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from pathlib import Path

from framework import (
    LogCollector,
    MultiContainerLogCollector,
    LogLevel,
    MetricsCollector,
    NodeMetricsCollector,
)


@pytest.mark.asyncio
async def test_log_collector_basic():
    """Test basic log collection from a container."""
    collector = LogCollector("buckwild-node-1")

    # Get recent logs
    logs = await collector.get_logs(tail=100)
    assert isinstance(logs, str)


@pytest.mark.asyncio
async def test_log_collector_with_time_range():
    """Test log collection with time-based filtering."""
    collector = LogCollector("buckwild-node-1")

    # Get logs from the last 5 minutes
    five_minutes_ago = datetime.now() - timedelta(minutes=5)
    logs = await collector.get_logs_since(five_minutes_ago)

    assert isinstance(logs, str)


@pytest.mark.asyncio
async def test_log_search():
    """Test searching logs for patterns."""
    collector = LogCollector("buckwild-node-1")

    # Search for error-related logs
    error_entries = await collector.search_logs(
        pattern="error|fail|panic",
        level=LogLevel.ERROR,
        case_sensitive=False
    )

    assert isinstance(error_entries, list)


@pytest.mark.asyncio
async def test_log_level_filtering():
    """Test filtering logs by level."""
    collector = LogCollector("buckwild-node-1")

    # Get only ERROR level logs
    error_logs = await collector.filter_by_level(LogLevel.ERROR)

    assert isinstance(error_logs, list)
    for entry in error_logs:
        assert entry.level == LogLevel.ERROR


@pytest.mark.asyncio
async def test_multi_container_logs():
    """Test collecting logs from multiple containers."""
    collector = MultiContainerLogCollector([
        "buckwild-node-1",
        "buckwild-node-2",
    ])

    # Get logs from all containers
    all_logs = await collector.get_all_logs(tail=50)

    assert isinstance(all_logs, dict)
    assert "buckwild-node-1" in all_logs
    assert "buckwild-node-2" in all_logs


@pytest.mark.asyncio
async def test_log_export(tmp_path):
    """Test exporting logs to a file."""
    collector = LogCollector("buckwild-node-1")

    output_file = tmp_path / "test_logs.txt"

    await collector.export_logs(
        output_path=output_file,
        tail=100,
        level=LogLevel.ERROR
    )

    assert output_file.exists()
    content = output_file.read_text()
    assert isinstance(content, str)


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,  # Skip by default unless Prometheus is running
    reason="Requires Prometheus to be running"
)
async def test_metrics_collector_query():
    """Test querying metrics from Prometheus."""
    collector = MetricsCollector("http://localhost:9090")

    # Check if Prometheus is reachable
    is_healthy = await collector.health_check()
    if not is_healthy:
        pytest.skip("Prometheus not available")

    # Query an instant metric
    results = await collector.query("up")
    assert isinstance(results, list)


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,
    reason="Requires Prometheus to be running"
)
async def test_metrics_range_query():
    """Test querying metrics over a time range."""
    collector = MetricsCollector("http://localhost:9090")

    if not await collector.health_check():
        pytest.skip("Prometheus not available")

    # Query metric over the last 5 minutes
    end = datetime.now()
    start = end - timedelta(minutes=5)

    ranges = await collector.query_range(
        query="up",
        start=start,
        end=end,
        step="15s"
    )

    assert isinstance(ranges, list)


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,
    reason="Requires Prometheus to be running"
)
async def test_node_metrics_collector():
    """Test collecting metrics for a specific node."""
    collector = NodeMetricsCollector(
        node_id="node-1",
        prometheus_url="http://localhost:9090"
    )

    if not await collector.collector.health_check():
        pytest.skip("Prometheus not available")

    # Get a node-specific metric
    value = await collector.get_node_metric("up")
    assert value is None or isinstance(value, float)


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,
    reason="Requires Prometheus to be running"
)
async def test_wait_for_metric():
    """Test waiting for a metric to meet a condition."""
    collector = MetricsCollector("http://localhost:9090")

    if not await collector.health_check():
        pytest.skip("Prometheus not available")

    # Wait for 'up' metric to be 1 (indicating service is up)
    value = await collector.wait_for_metric(
        metric_name="up",
        condition=lambda v: v == 1.0,
        timeout=10.0,
        poll_interval=1.0
    )

    assert value is None or value == 1.0


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,
    reason="Requires Prometheus to be running"
)
async def test_metrics_export(tmp_path):
    """Test exporting metrics to a file."""
    collector = MetricsCollector("http://localhost:9090")

    if not await collector.health_check():
        pytest.skip("Prometheus not available")

    output_file = tmp_path / "metrics.json"

    end = datetime.now()
    start = end - timedelta(minutes=5)

    await collector.export_metrics(
        output_path=output_file,
        query="up",
        start=start,
        end=end,
        step="15s",
        format="json"
    )

    assert output_file.exists()


@pytest.mark.asyncio
async def test_get_error_logs():
    """Test getting error-level logs."""
    collector = LogCollector("buckwild-node-1")

    # Get all error logs from the last 10 minutes
    error_logs = await collector.get_error_logs(since="10m")

    assert isinstance(error_logs, list)
