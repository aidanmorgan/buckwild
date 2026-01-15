"""Metrics collection utilities for E2E testing.

This module provides utilities for querying Prometheus metrics from test clusters,
supporting time-based queries and metric export.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from urllib.parse import urlencode


logger = logging.getLogger(__name__)


@dataclass
class MetricValue:
    """Represents a single metric value at a point in time."""

    timestamp: datetime
    value: float
    labels: Dict[str, str]


@dataclass
class MetricRange:
    """Represents a metric's values over a time range."""

    metric_name: str
    labels: Dict[str, str]
    values: List[MetricValue]


class MetricsCollector:
    """Collects metrics from Prometheus.

    Provides methods to query instant values, time ranges, and export metrics
    to files for analysis.
    """

    def __init__(
        self,
        prometheus_url: str = "http://localhost:9090",
        timeout: float = 30.0
    ):
        """Initialize a MetricsCollector.

        Args:
            prometheus_url: Base URL of Prometheus server
            timeout: Default timeout for queries in seconds
        """
        self.prometheus_url = prometheus_url.rstrip('/')
        self.timeout = timeout
        self._check_dependencies()

    def _check_dependencies(self) -> None:
        """Check if required dependencies are available.

        Raises:
            ImportError: If required packages are missing
        """
        try:
            import aiohttp
        except ImportError:
            raise ImportError(
                "aiohttp is required for metrics collection. "
                "Install with: pip install aiohttp"
            )

    async def _query_api(
        self,
        endpoint: str,
        params: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """Execute a query against the Prometheus API.

        Args:
            endpoint: API endpoint (e.g., "query", "query_range")
            params: Query parameters
            timeout: Query timeout in seconds

        Returns:
            Parsed JSON response

        Raises:
            RuntimeError: If query fails
            ConnectionError: If Prometheus is unreachable
        """
        import aiohttp

        url = f"{self.prometheus_url}/api/v1/{endpoint}"
        query_timeout = timeout if timeout is not None else self.timeout

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=query_timeout)
                ) as response:
                    if response.status != 200:
                        text = await response.text()
                        raise RuntimeError(
                            f"Prometheus query failed with status {response.status}: {text}"
                        )

                    data = await response.json()

                    if data.get("status") != "success":
                        error = data.get("error", "Unknown error")
                        raise RuntimeError(f"Prometheus query error: {error}")

                    return data

        except aiohttp.ClientError as e:
            logger.error(f"Failed to connect to Prometheus at {url}: {e}")
            raise ConnectionError(f"Failed to connect to Prometheus: {e}")
        except asyncio.TimeoutError:
            logger.error(f"Prometheus query timed out after {query_timeout}s")
            raise RuntimeError(f"Query timed out after {query_timeout}s")

    async def query(
        self,
        query: str,
        time: Optional[datetime] = None,
        timeout: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Execute an instant query against Prometheus.

        Args:
            query: PromQL query string
            time: Evaluation timestamp (defaults to now)
            timeout: Query timeout in seconds

        Returns:
            List of metric results

        Raises:
            RuntimeError: If query fails
            ConnectionError: If Prometheus is unreachable
        """
        params = {"query": query}

        if time is not None:
            # Convert to Unix timestamp
            params["time"] = time.timestamp()

        try:
            data = await self._query_api("query", params, timeout)
            return data.get("data", {}).get("result", [])

        except Exception as e:
            logger.error(f"Query failed: {query}: {e}")
            raise

    async def query_range(
        self,
        query: str,
        start: datetime,
        end: datetime,
        step: str = "15s",
        timeout: Optional[float] = None
    ) -> List[MetricRange]:
        """Execute a range query against Prometheus.

        Args:
            query: PromQL query string
            start: Start time for the range
            end: End time for the range
            step: Query resolution step width (e.g., "15s", "1m", "1h")
            timeout: Query timeout in seconds

        Returns:
            List of MetricRange objects

        Raises:
            RuntimeError: If query fails
            ConnectionError: If Prometheus is unreachable
        """
        params = {
            "query": query,
            "start": start.timestamp(),
            "end": end.timestamp(),
            "step": step
        }

        try:
            data = await self._query_api("query_range", params, timeout)
            results = data.get("data", {}).get("result", [])

            metric_ranges = []

            for result in results:
                metric_name = result.get("metric", {}).get("__name__", "unknown")
                labels = {
                    k: v for k, v in result.get("metric", {}).items()
                    if k != "__name__"
                }

                values = []
                for timestamp, value in result.get("values", []):
                    values.append(
                        MetricValue(
                            timestamp=datetime.fromtimestamp(timestamp),
                            value=float(value),
                            labels=labels
                        )
                    )

                metric_ranges.append(
                    MetricRange(
                        metric_name=metric_name,
                        labels=labels,
                        values=values
                    )
                )

            return metric_ranges

        except Exception as e:
            logger.error(f"Range query failed: {query}: {e}")
            raise

    async def get_metric(
        self,
        metric_name: str,
        labels: Optional[Dict[str, str]] = None,
        time: Optional[datetime] = None
    ) -> Optional[float]:
        """Get the current value of a specific metric.

        Args:
            metric_name: Name of the metric
            labels: Optional label filters
            time: Evaluation timestamp (defaults to now)

        Returns:
            Metric value, or None if metric not found
        """
        # Build PromQL query
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            query = f'{metric_name}{{{label_str}}}'
        else:
            query = metric_name

        try:
            results = await self.query(query, time)

            if not results:
                return None

            # Return the first result's value
            value = results[0].get("value", [None, None])[1]
            return float(value) if value is not None else None

        except Exception as e:
            logger.error(f"Failed to get metric {metric_name}: {e}")
            return None

    async def wait_for_metric(
        self,
        metric_name: str,
        condition: callable,
        labels: Optional[Dict[str, str]] = None,
        timeout: float = 60.0,
        poll_interval: float = 2.0
    ) -> Optional[float]:
        """Wait for a metric to meet a condition.

        Args:
            metric_name: Name of the metric
            condition: Callable that takes metric value and returns bool
            labels: Optional label filters
            timeout: Maximum time to wait in seconds
            poll_interval: Time between polls in seconds

        Returns:
            Final metric value when condition is met, or None on timeout

        Raises:
            RuntimeError: If metric query fails
        """
        start_time = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                value = await self.get_metric(metric_name, labels)

                if value is not None and condition(value):
                    logger.info(
                        f"Metric {metric_name} met condition: {value}"
                    )
                    return value

                await asyncio.sleep(poll_interval)

            except Exception as e:
                logger.warning(
                    f"Error checking metric {metric_name}: {e}, retrying..."
                )
                await asyncio.sleep(poll_interval)

        logger.warning(
            f"Metric {metric_name} did not meet condition within {timeout}s"
        )
        return None

    async def get_all_metrics(self) -> List[str]:
        """Get list of all available metric names.

        Returns:
            List of metric names

        Raises:
            RuntimeError: If query fails
        """
        try:
            # Query for all metric names using label_names
            data = await self._query_api("label/__name__/values", {})
            return data.get("data", [])

        except Exception as e:
            logger.error(f"Failed to get metric names: {e}")
            raise

    async def export_metrics(
        self,
        output_path: Path,
        query: str,
        start: datetime,
        end: datetime,
        step: str = "15s",
        format: str = "json"
    ) -> None:
        """Export metric data to a file.

        Args:
            output_path: Path to write metrics to
            query: PromQL query string
            start: Start time for the range
            end: End time for the range
            step: Query resolution step width
            format: Output format ("json" or "csv")

        Raises:
            ValueError: If format is not supported
            IOError: If file cannot be written
        """
        if format not in ("json", "csv"):
            raise ValueError(f"Unsupported format: {format}")

        try:
            metric_ranges = await self.query_range(query, start, end, step)

            output_path.parent.mkdir(parents=True, exist_ok=True)

            if format == "json":
                self._export_json(output_path, metric_ranges)
            elif format == "csv":
                self._export_csv(output_path, metric_ranges)

            logger.info(f"Exported metrics to {output_path}")

        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")
            raise IOError(f"Failed to export metrics: {e}")

    def _export_json(
        self,
        output_path: Path,
        metric_ranges: List[MetricRange]
    ) -> None:
        """Export metrics to JSON format.

        Args:
            output_path: Path to write JSON to
            metric_ranges: List of MetricRange objects
        """
        data = []

        for metric_range in metric_ranges:
            metric_data = {
                "metric": metric_range.metric_name,
                "labels": metric_range.labels,
                "values": [
                    {
                        "timestamp": v.timestamp.isoformat(),
                        "value": v.value
                    }
                    for v in metric_range.values
                ]
            }
            data.append(metric_data)

        output_path.write_text(json.dumps(data, indent=2))

    def _export_csv(
        self,
        output_path: Path,
        metric_ranges: List[MetricRange]
    ) -> None:
        """Export metrics to CSV format.

        Args:
            output_path: Path to write CSV to
            metric_ranges: List of MetricRange objects
        """
        import csv

        with output_path.open('w', newline='') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow(['metric', 'labels', 'timestamp', 'value'])

            # Write data
            for metric_range in metric_ranges:
                labels_str = json.dumps(metric_range.labels)
                for value in metric_range.values:
                    writer.writerow([
                        metric_range.metric_name,
                        labels_str,
                        value.timestamp.isoformat(),
                        value.value
                    ])

    async def health_check(self) -> bool:
        """Check if Prometheus is reachable and healthy.

        Returns:
            True if Prometheus is healthy, False otherwise
        """
        try:
            # Use a simple query to check connectivity
            await self.query("up", timeout=5.0)
            return True
        except Exception as e:
            logger.warning(f"Prometheus health check failed: {e}")
            return False

    def __repr__(self) -> str:
        """String representation."""
        return f"MetricsCollector(url={self.prometheus_url})"


class NodeMetricsCollector:
    """Collects metrics for a specific node.

    Provides convenient access to node-specific metrics with automatic
    label filtering by node ID.
    """

    def __init__(
        self,
        node_id: str,
        prometheus_url: str = "http://localhost:9090"
    ):
        """Initialize a NodeMetricsCollector.

        Args:
            node_id: ID of the node to collect metrics for
            prometheus_url: Base URL of Prometheus server
        """
        self.node_id = node_id
        self.collector = MetricsCollector(prometheus_url)

    async def get_node_metric(
        self,
        metric_name: str,
        additional_labels: Optional[Dict[str, str]] = None
    ) -> Optional[float]:
        """Get a metric value for this node.

        Args:
            metric_name: Name of the metric
            additional_labels: Additional label filters beyond node_id

        Returns:
            Metric value, or None if not found
        """
        labels = {"node": self.node_id}
        if additional_labels:
            labels.update(additional_labels)

        return await self.collector.get_metric(metric_name, labels)

    async def get_node_metrics_range(
        self,
        metric_name: str,
        start: datetime,
        end: datetime,
        step: str = "15s",
        additional_labels: Optional[Dict[str, str]] = None
    ) -> List[MetricRange]:
        """Get metric values over a time range for this node.

        Args:
            metric_name: Name of the metric
            start: Start time
            end: End time
            step: Query resolution step width
            additional_labels: Additional label filters beyond node_id

        Returns:
            List of MetricRange objects
        """
        # Build query with node filter
        if additional_labels:
            labels = {"node": self.node_id, **additional_labels}
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            query = f'{metric_name}{{{label_str}}}'
        else:
            query = f'{metric_name}{{node="{self.node_id}"}}'

        return await self.collector.query_range(query, start, end, step)

    def __repr__(self) -> str:
        """String representation."""
        return f"NodeMetricsCollector(node={self.node_id})"
