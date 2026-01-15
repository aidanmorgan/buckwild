"""Pytest configuration and fixtures for e2e tests."""

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# Add parent directory to path for imports
import sys

sys.path.insert(0, str(Path(__file__).parent))

from framework.transfer_client import NODE_PORTS, check_node_health


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "protocol: Protocol-specific tests")
    config.addinivalue_line("markers", "slow: Long-running tests")


def get_test_duration() -> int:
    """Get test duration from environment variable."""
    return int(os.environ.get("BUCKWILD_TRANSFER_DURATION", "30"))


def get_h2_streams() -> int:
    """Get HTTP/2 stream count from environment variable."""
    return int(os.environ.get("BUCKWILD_H2_STREAMS", "10"))


@dataclass
class TransferStats:
    """Statistics tracker for transfer tests."""

    uploads: int = 0
    downloads: int = 0
    total_bytes: int = 0
    total_duration_ms: int = 0
    failures: int = 0

    def record_upload(self, size_bytes: int, duration_ms: int, success: bool):
        """Record an upload result."""
        if success:
            self.uploads += 1
            self.total_bytes += size_bytes
            self.total_duration_ms += duration_ms
        else:
            self.failures += 1

    def record_download(self, size_bytes: int, duration_ms: int, success: bool):
        """Record a download result."""
        if success:
            self.downloads += 1
            self.total_bytes += size_bytes
            self.total_duration_ms += duration_ms
        else:
            self.failures += 1

    def print_summary(self):
        """Print test summary."""
        total = self.uploads + self.downloads
        if self.total_duration_ms > 0:
            throughput = self.total_bytes / (self.total_duration_ms / 1000)
        else:
            throughput = 0

        print(f"\n{'=' * 60}")
        print("Transfer Test Summary")
        print(f"{'=' * 60}")
        print(f"Total transfers: {total} ({self.uploads} uploads, {self.downloads} downloads)")
        print(f"Failures: {self.failures}")
        print(f"Total data: {self.total_bytes / 1024 / 1024:.2f} MB")
        print(f"Avg throughput: {throughput / 1024 / 1024:.2f} MB/s")
        print(f"{'=' * 60}\n")


@dataclass
class ClusterConfig:
    """Configuration for a test cluster."""

    nodes: list[str]
    compose_file: str
    docker_dir: Path


@dataclass
class Cluster:
    """Manages a Docker Compose cluster for testing."""

    config: ClusterConfig
    _started: bool = field(default=False, init=False)

    @classmethod
    def from_topology(cls, topology: str) -> "Cluster":
        """Create cluster from topology name."""
        docker_dir = Path(__file__).parent / "docker"

        topologies = {
            "2-node": ClusterConfig(
                nodes=["node-a", "node-b"],
                compose_file="docker-compose.2-node.yml",
                docker_dir=docker_dir,
            ),
            "3-node": ClusterConfig(
                nodes=["node-a", "node-b", "node-c"],
                compose_file="docker-compose.3-node.yml",
                docker_dir=docker_dir,
            ),
            "5-node": ClusterConfig(
                nodes=["node-a", "node-b", "node-c", "node-d", "node-e"],
                compose_file="docker-compose.5-node.yml",
                docker_dir=docker_dir,
            ),
        }

        if topology not in topologies:
            raise ValueError(f"Unknown topology: {topology}. Valid: {list(topologies.keys())}")

        return cls(config=topologies[topology])

    def start(self, timeout: float = 120.0):
        """Start the cluster."""
        compose_path = self.config.docker_dir / self.config.compose_file

        if not compose_path.exists():
            raise FileNotFoundError(f"Compose file not found: {compose_path}")

        subprocess.run(
            ["docker", "compose", "-f", str(compose_path), "up", "-d"],
            check=True,
            cwd=self.config.docker_dir,
        )
        self._started = True

        # Wait for nodes to be healthy
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            all_healthy = True
            for node in self.config.nodes:
                import asyncio

                if not asyncio.get_event_loop().run_until_complete(check_node_health(node)):
                    all_healthy = False
                    break

            if all_healthy:
                return

            time.sleep(1)

        raise TimeoutError(f"Cluster did not become healthy within {timeout}s")

    def stop(self):
        """Stop the cluster."""
        if not self._started:
            return

        compose_path = self.config.docker_dir / self.config.compose_file

        subprocess.run(
            ["docker", "compose", "-f", str(compose_path), "down", "-v"],
            check=False,
            cwd=self.config.docker_dir,
        )
        self._started = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


@pytest.fixture
def stats():
    """Provide a fresh TransferStats instance."""
    return TransferStats()


@pytest.fixture
def test_duration():
    """Get configured test duration."""
    return get_test_duration()


@pytest.fixture
def h2_streams():
    """Get configured HTTP/2 stream count."""
    return get_h2_streams()


@pytest.fixture(scope="session")
def docker_dir():
    """Path to docker directory."""
    return Path(__file__).parent / "docker"


# Note: Cluster fixtures should only be used when Docker infrastructure is in place
# For now, tests can use check_node_health() to verify nodes are available
