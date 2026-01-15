"""Pytest configuration for E2E tests.

Provides fixtures for cluster management, node access, and test configuration.
"""

import os
import asyncio
import logging
import pytest
from pathlib import Path
from typing import Optional

from .framework.cluster import Cluster


logger = logging.getLogger(__name__)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests.

    This fixture ensures a single event loop is used for the entire test session.
    """
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def docker_dir() -> Path:
    """Get the path to the docker directory.

    Returns:
        Path to docker directory containing compose files

    Can be overridden via BUCKWILD_DOCKER_DIR environment variable.
    """
    env_dir = os.getenv("BUCKWILD_DOCKER_DIR")
    if env_dir:
        return Path(env_dir)

    # Default: project_root/docker
    return Path(__file__).parent.parent.parent / "docker"


@pytest.fixture(scope="session")
def test_config() -> dict:
    """Provide test configuration.

    Returns:
        Dictionary of test configuration values

    Configuration can be overridden via environment variables:
    - BUCKWILD_TEST_TIMEOUT: Test timeout in seconds (default: 300)
    - BUCKWILD_NODE_TIMEOUT: Node ready timeout in seconds (default: 60)
    - BUCKWILD_WITH_OBSERVABILITY: Enable observability stack (default: false)
    """
    return {
        "test_timeout": int(os.getenv("BUCKWILD_TEST_TIMEOUT", "300")),
        "node_timeout": int(os.getenv("BUCKWILD_NODE_TIMEOUT", "60")),
        "with_observability": os.getenv("BUCKWILD_WITH_OBSERVABILITY", "false").lower() == "true",
    }


@pytest.fixture(scope="function")
async def two_node_cluster(docker_dir: Path, test_config: dict):
    """Provide a 2-node cluster for testing.

    Yields:
        Cluster instance with 2 nodes

    This is a function-scoped fixture that starts and stops a cluster
    for each test that uses it.
    """
    cluster = Cluster.from_topology(
        "2-node",
        docker_dir=docker_dir,
        with_observability=test_config["with_observability"]
    )

    try:
        cluster.start()
        await cluster.wait_ready(timeout=test_config["node_timeout"])
        yield cluster
    finally:
        cluster.stop()


@pytest.fixture(scope="function")
async def three_node_cluster(docker_dir: Path, test_config: dict):
    """Provide a 3-node cluster for testing.

    Yields:
        Cluster instance with 3 nodes
    """
    cluster = Cluster.from_topology(
        "3-node",
        docker_dir=docker_dir,
        with_observability=test_config["with_observability"]
    )

    try:
        cluster.start()
        await cluster.wait_ready(timeout=test_config["node_timeout"])
        yield cluster
    finally:
        cluster.stop()


@pytest.fixture(scope="function")
async def five_node_cluster(docker_dir: Path, test_config: dict):
    """Provide a 5-node cluster for testing.

    Yields:
        Cluster instance with 5 nodes
    """
    cluster = Cluster.from_topology(
        "5-node",
        docker_dir=docker_dir,
        with_observability=test_config["with_observability"]
    )

    try:
        cluster.start()
        await cluster.wait_ready(timeout=test_config["node_timeout"])
        yield cluster
    finally:
        cluster.stop()


@pytest.fixture(scope="function")
async def ten_node_cluster(docker_dir: Path, test_config: dict):
    """Provide a 10-node cluster for testing.

    Yields:
        Cluster instance with 10 nodes
    """
    cluster = Cluster.from_topology(
        "10-node",
        docker_dir=docker_dir,
        with_observability=test_config["with_observability"]
    )

    try:
        cluster.start()
        await cluster.wait_ready(timeout=test_config["node_timeout"])
        yield cluster
    finally:
        cluster.stop()


@pytest.fixture(scope="session")
async def session_two_node_cluster(docker_dir: Path, test_config: dict):
    """Provide a session-scoped 2-node cluster.

    This fixture is more efficient for tests that don't modify cluster state,
    as the cluster is only started once per session.

    Yields:
        Cluster instance with 2 nodes
    """
    cluster = Cluster.from_topology(
        "2-node",
        docker_dir=docker_dir,
        with_observability=test_config["with_observability"]
    )

    try:
        cluster.start()
        await cluster.wait_ready(timeout=test_config["node_timeout"])
        yield cluster
    finally:
        cluster.stop()


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "topology: mark test as topology verification test"
    )
    config.addinivalue_line(
        "markers",
        "topology_2node: mark test as requiring a 2-node topology"
    )
    config.addinivalue_line(
        "markers",
        "topology_3node: mark test as requiring a 3-node topology"
    )
    config.addinivalue_line(
        "markers",
        "topology_5node: mark test as requiring a 5-node topology"
    )
    config.addinivalue_line(
        "markers",
        "topology_10node: mark test as requiring a 10-node topology"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers",
        "requires_observability: mark test as requiring observability stack"
    )
    config.addinivalue_line(
        "markers",
        "smoke: mark test as smoke test (fast, < 5 minutes total)"
    )
    config.addinivalue_line(
        "markers",
        "nightly: mark test as nightly test (long-running, may take hours)"
    )
    config.addinivalue_line(
        "markers",
        "grpc: mark test as gRPC protocol test"
    )
    config.addinivalue_line(
        "markers",
        "e2e: mark test as end-to-end integration test"
    )
    config.addinivalue_line(
        "markers",
        "websocket: mark test as WebSocket protocol test"
    )
    config.addinivalue_line(
        "markers",
        "http: mark test as HTTP/HTTPS protocol test"
    )
    config.addinivalue_line(
        "markers",
        "isolation: mark test as network isolation verification test"
    )
    config.addinivalue_line(
        "markers",
        "sse: mark test as SSE (Server-Sent Events) protocol test"
    )
    config.addinivalue_line(
        "markers",
        "ftp: mark test as FTP protocol test"
    )
    config.addinivalue_line(
        "markers",
        "ten_node: mark test as 10-node topology test"
    )
    config.addinivalue_line(
        "markers",
        "resilience: mark test as resilience/fault-tolerance test"
    )
    config.addinivalue_line(
        "markers",
        "chaos: mark test as chaos engineering test"
    )
    config.addinivalue_line(
        "markers",
        "packet_loss: mark test as packet loss resilience test"
    )
    config.addinivalue_line(
        "markers",
        "latency: mark test as latency resilience test"
    )
    config.addinivalue_line(
        "markers",
        "node_failure: mark test as node failure resilience test"
    )
