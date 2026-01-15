"""Cluster management for E2E testing.

This module provides Docker Compose lifecycle management for test clusters,
supporting various topologies (2-node, 3-node, 5-node, 10-node).
"""

import asyncio
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

from .node import Node, NodeConfig


logger = logging.getLogger(__name__)


@dataclass
class ClusterConfig:
    """Configuration for a test cluster."""

    topology: str  # "2-node", "3-node", "5-node", "10-node"
    compose_file: Path
    project_name: Optional[str] = None
    with_observability: bool = False


class Cluster:
    """Manages Docker Compose lifecycle for a test cluster.

    Handles starting/stopping clusters, managing node lifecycle,
    and providing access to individual nodes.
    """

    # Topology definitions with node configurations
    TOPOLOGIES = {
        "2-node": {
            "compose_file": "docker-compose.2-node.yml",
            "nodes": [
                {"name": "node-1", "container": "buckwild-node-1", "ip": "172.30.0.10", "id": "node-1"},
                {"name": "node-2", "container": "buckwild-node-2", "ip": "172.30.0.11", "id": "node-2"},
            ]
        },
        "3-node": {
            "compose_file": "docker-compose.3-node.yml",
            "nodes": [
                {"name": "node-1", "container": "buckwild-node-1", "ip": "172.30.0.10", "id": "node-1"},
                {"name": "node-2", "container": "buckwild-node-2", "ip": "172.30.0.11", "id": "node-2"},
                {"name": "node-3", "container": "buckwild-node-3", "ip": "172.30.0.12", "id": "node-3"},
            ]
        },
        "5-node": {
            "compose_file": "docker-compose.5-node.yml",
            "nodes": [
                {"name": "node-1", "container": "buckwild-node-1", "ip": "172.30.0.10", "id": "node-1"},
                {"name": "node-2", "container": "buckwild-node-2", "ip": "172.30.0.11", "id": "node-2"},
                {"name": "node-3", "container": "buckwild-node-3", "ip": "172.30.0.12", "id": "node-3"},
                {"name": "node-4", "container": "buckwild-node-4", "ip": "172.30.0.13", "id": "node-4"},
                {"name": "node-5", "container": "buckwild-node-5", "ip": "172.30.0.14", "id": "node-5"},
            ]
        },
        "10-node": {
            "compose_file": "docker-compose.10-node.yml",
            "nodes": [
                {"name": f"node-{i}", "container": f"buckwild-node-{i}", "ip": f"172.30.0.{10+i-1}", "id": f"node-{i}"}
                for i in range(1, 11)
            ]
        }
    }

    def __init__(self, config: ClusterConfig):
        """Initialize a Cluster instance.

        Args:
            config: Cluster configuration
        """
        self.config = config
        self.topology = config.topology
        self.compose_file = config.compose_file
        self.project_name = config.project_name or f"buckwild-test-{self.topology}"
        self.nodes: Dict[str, Node] = {}
        self._started = False

        if self.topology not in self.TOPOLOGIES:
            raise ValueError(f"Unknown topology: {self.topology}")

        # Initialize node objects
        topology_config = self.TOPOLOGIES[self.topology]
        for node_def in topology_config["nodes"]:
            node_config = NodeConfig(
                name=node_def["name"],
                container_name=node_def["container"],
                ip_address=node_def["ip"],
                node_id=node_def["id"]
            )
            self.nodes[node_def["name"]] = Node(node_config)

    @classmethod
    def from_topology(
        cls,
        topology: str,
        docker_dir: Optional[Path] = None,
        with_observability: bool = False
    ) -> "Cluster":
        """Create a cluster from a topology name.

        Args:
            topology: Topology name ("2-node", "3-node", etc.)
            docker_dir: Path to docker directory (defaults to project docker dir)
            with_observability: Whether to include observability stack

        Returns:
            Cluster instance
        """
        if docker_dir is None:
            # Default to project docker directory
            docker_dir = Path(__file__).parent.parent.parent.parent / "docker"

        if topology not in cls.TOPOLOGIES:
            raise ValueError(f"Unknown topology: {topology}")

        compose_filename = cls.TOPOLOGIES[topology]["compose_file"]
        compose_file = docker_dir / "topologies" / compose_filename

        if not compose_file.exists():
            raise FileNotFoundError(f"Compose file not found: {compose_file}")

        config = ClusterConfig(
            topology=topology,
            compose_file=compose_file,
            with_observability=with_observability
        )

        return cls(config)

    def start(self, timeout: float = 120.0) -> None:
        """Start the cluster using Docker Compose.

        Args:
            timeout: Maximum time to wait for cluster to start

        Raises:
            RuntimeError: If cluster fails to start
        """
        if self._started:
            logger.warning("Cluster already started")
            return

        logger.info(f"Starting {self.topology} cluster from {self.compose_file}")

        cmd = [
            "docker", "compose",
            "-f", str(self.compose_file),
            "-p", self.project_name,
            "up", "-d"
        ]

        if self.config.with_observability:
            # Add observability compose file
            observability_file = self.compose_file.parent.parent / "docker-compose.observability.yml"
            if observability_file.exists():
                cmd.extend(["-f", str(observability_file)])

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            logger.debug(f"Docker compose up output: {result.stdout}")
            self._started = True
            logger.info(f"Cluster {self.project_name} started successfully")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start cluster: {e.stderr}")
            raise RuntimeError(f"Failed to start cluster: {e.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"Cluster start timed out after {timeout}s")
            raise RuntimeError(f"Cluster start timed out after {timeout}s")

    def stop(self, remove_volumes: bool = True, timeout: float = 60.0) -> None:
        """Stop the cluster using Docker Compose.

        Args:
            remove_volumes: Whether to remove volumes
            timeout: Maximum time to wait for cluster to stop
        """
        if not self._started:
            logger.warning("Cluster not started")
            return

        logger.info(f"Stopping cluster {self.project_name}")

        cmd = [
            "docker", "compose",
            "-f", str(self.compose_file),
            "-p", self.project_name,
            "down"
        ]

        if remove_volumes:
            cmd.append("-v")

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            logger.debug(f"Docker compose down output: {result.stdout}")
            self._started = False
            logger.info(f"Cluster {self.project_name} stopped successfully")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop cluster: {e.stderr}")
            raise RuntimeError(f"Failed to stop cluster: {e.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"Cluster stop timed out after {timeout}s")
            raise RuntimeError(f"Cluster stop timed out after {timeout}s")

    def get_node(self, name: str) -> Node:
        """Get a node by name.

        Args:
            name: Node name (e.g., "node-1")

        Returns:
            Node instance

        Raises:
            KeyError: If node not found
        """
        if name not in self.nodes:
            raise KeyError(f"Node {name} not found in cluster")
        return self.nodes[name]

    def get_all_nodes(self) -> List[Node]:
        """Get all nodes in the cluster.

        Returns:
            List of all Node instances
        """
        return list(self.nodes.values())

    async def wait_ready(self, timeout: float = 120.0) -> None:
        """Wait for all nodes in the cluster to be ready.

        Args:
            timeout: Maximum time to wait for all nodes

        Raises:
            TimeoutError: If nodes don't become ready within timeout
        """
        logger.info(f"Waiting for {len(self.nodes)} nodes to be ready")

        # Wait for all nodes in parallel
        tasks = [node.wait_ready(timeout) for node in self.nodes.values()]

        try:
            await asyncio.gather(*tasks)
            logger.info("All nodes ready")
        except TimeoutError as e:
            logger.error(f"Not all nodes became ready: {e}")
            raise

    async def restart_node(self, name: str, timeout: float = 60.0) -> None:
        """Restart a specific node.

        Args:
            name: Node name
            timeout: Maximum time to wait for restart
        """
        node = self.get_node(name)
        logger.info(f"Restarting node {name}")

        cmd = [
            "docker", "compose",
            "-f", str(self.compose_file),
            "-p", self.project_name,
            "restart", node.container_name
        ]

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            logger.debug(f"Restart output: {result.stdout}")

            # Reset ready flag and wait for node to be ready again
            node._ready = False
            await node.wait_ready(timeout)

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restart node {name}: {e.stderr}")
            raise RuntimeError(f"Failed to restart node {name}: {e.stderr}")

    def get_logs_all(self) -> str:
        """Get logs from all services in the cluster.

        Returns:
            Combined logs from all services
        """
        cmd = [
            "docker", "compose",
            "-f", str(self.compose_file),
            "-p", self.project_name,
            "logs", "--no-color"
        ]

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30.0
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get logs: {e.stderr}")
            return f"Error getting logs: {e.stderr}"

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()

    def __repr__(self) -> str:
        """String representation."""
        return f"Cluster(topology={self.topology}, nodes={len(self.nodes)}, started={self._started})"
