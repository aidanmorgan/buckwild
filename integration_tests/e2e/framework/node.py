"""Node abstraction for E2E testing.

This module provides an abstraction over individual Docker containers
running Buckwild nodes, allowing tests to interact with nodes via
async operations.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class NodeConfig:
    """Configuration for a Buckwild node."""

    name: str
    container_name: str
    ip_address: str
    node_id: str
    ssh_port: Optional[int] = None


class Node:
    """Represents a single Buckwild node in a Docker container.

    Provides methods to interact with the node via Docker exec commands,
    retrieve logs, check health status, and perform async operations.
    """

    def __init__(self, config: NodeConfig):
        """Initialize a Node instance.

        Args:
            config: Node configuration including name, container name, IP, etc.
        """
        self.config = config
        self.name = config.name
        self.container_name = config.container_name
        self.ip_address = config.ip_address
        self.node_id = config.node_id
        self._ready = False

    async def exec_command(
        self,
        command: str | List[str],
        timeout: float = 30.0,
        check: bool = True
    ) -> tuple[int, str, str]:
        """Execute a command inside the node container.

        Args:
            command: Command to execute (string or list of args)
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero return code

        Returns:
            Tuple of (return_code, stdout, stderr)

        Raises:
            asyncio.TimeoutError: If command times out
            RuntimeError: If command fails and check=True
        """
        if isinstance(command, str):
            cmd = ["docker", "exec", self.container_name, "sh", "-c", command]
        else:
            cmd = ["docker", "exec", self.container_name] + command

        logger.debug(f"Executing command on {self.name}: {cmd}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            stdout = stdout_bytes.decode('utf-8') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8') if stderr_bytes else ""
            returncode = process.returncode or 0

            if check and returncode != 0:
                raise RuntimeError(
                    f"Command failed on {self.name} with code {returncode}: {stderr}"
                )

            return returncode, stdout, stderr

        except asyncio.TimeoutError:
            logger.error(f"Command timed out on {self.name}: {command}")
            raise
        except Exception as e:
            logger.error(f"Error executing command on {self.name}: {e}")
            raise

    async def get_logs(
        self,
        tail: Optional[int] = None,
        since: Optional[str] = None
    ) -> str:
        """Retrieve container logs.

        Args:
            tail: Number of lines from end of logs to retrieve
            since: Only return logs since this time (e.g., "10m", "1h")

        Returns:
            Container logs as string
        """
        cmd = ["docker", "logs", self.container_name]

        if tail is not None:
            cmd.extend(["--tail", str(tail)])
        if since is not None:
            cmd.extend(["--since", since])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_bytes, _ = await process.communicate()
        return stdout_bytes.decode('utf-8') if stdout_bytes else ""

    def get_ip(self) -> str:
        """Get the node's IP address.

        Returns:
            IP address string
        """
        return self.ip_address

    async def is_ready(self, timeout: float = 60.0) -> bool:
        """Check if the node is ready to accept connections.

        Checks the health endpoint and verifies the daemon is running.

        Args:
            timeout: Maximum time to wait for node to be ready

        Returns:
            True if node is ready, False otherwise
        """
        if self._ready:
            return True

        start_time = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                # Check if container is running
                returncode, stdout, _ = await self.exec_command(
                    "curl -f http://localhost:8080/health || echo 'not ready'",
                    timeout=5.0,
                    check=False
                )

                if returncode == 0 and "not ready" not in stdout:
                    logger.info(f"Node {self.name} is ready")
                    self._ready = True
                    return True

            except Exception as e:
                logger.debug(f"Health check failed for {self.name}: {e}")

            await asyncio.sleep(2)

        logger.warning(f"Node {self.name} did not become ready within {timeout}s")
        return False

    async def wait_ready(self, timeout: float = 60.0) -> None:
        """Wait for the node to be ready.

        Args:
            timeout: Maximum time to wait

        Raises:
            TimeoutError: If node doesn't become ready within timeout
        """
        if not await self.is_ready(timeout):
            raise TimeoutError(f"Node {self.name} not ready within {timeout}s")

    async def get_metrics(self) -> Dict[str, Any]:
        """Retrieve node metrics from the metrics endpoint.

        Returns:
            Dictionary of metrics
        """
        try:
            _, stdout, _ = await self.exec_command(
                "curl -s http://localhost:8080/metrics",
                timeout=10.0
            )
            # Parse Prometheus metrics format
            # For now, return raw output
            return {"raw": stdout}
        except Exception as e:
            logger.error(f"Failed to get metrics from {self.name}: {e}")
            return {}

    async def get_vpn_status(self) -> Dict[str, Any]:
        """Get VPN status information.

        Returns:
            Dictionary containing VPN status information
        """
        try:
            _, stdout, _ = await self.exec_command(
                "curl -s http://localhost:8080/status",
                timeout=10.0
            )
            # Parse JSON response if available
            import json
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {"raw": stdout}
        except Exception as e:
            logger.error(f"Failed to get VPN status from {self.name}: {e}")
            return {}

    def __repr__(self) -> str:
        """String representation of the node."""
        return f"Node(name={self.name}, ip={self.ip_address}, ready={self._ready})"
