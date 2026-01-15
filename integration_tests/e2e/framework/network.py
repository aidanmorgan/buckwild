"""Network connectivity utilities for E2E testing.

This module provides network checking capabilities for testing
connectivity between nodes in a cluster.
"""

import asyncio
import logging
import time
from typing import Optional
from dataclasses import dataclass

from .ssh import SSHClient


logger = logging.getLogger(__name__)


@dataclass
class PingResult:
    """Result of a ping operation."""

    success: bool
    packet_loss: float
    avg_rtt_ms: Optional[float] = None
    error: Optional[str] = None

    def __repr__(self) -> str:
        """String representation."""
        if self.success:
            return f"PingResult(success=True, loss={self.packet_loss}%, rtt={self.avg_rtt_ms}ms)"
        return f"PingResult(success=False, error={self.error})"


@dataclass
class PortCheckResult:
    """Result of a port connectivity check."""

    open: bool
    host: str
    port: int
    error: Optional[str] = None

    def __repr__(self) -> str:
        """String representation."""
        status = "open" if self.open else "closed"
        return f"PortCheckResult(host={self.host}, port={self.port}, status={status})"


class NetworkCheck:
    """Network connectivity checking for container environments.

    Provides methods to verify network connectivity between nodes,
    check port availability, and wait for services to become ready.
    """

    def __init__(self, ssh_client: SSHClient):
        """Initialize NetworkCheck.

        Args:
            ssh_client: SSH client for executing network commands
        """
        self.ssh = ssh_client

    async def ping(
        self,
        target: str,
        count: int = 4,
        timeout: float = 10.0
    ) -> PingResult:
        """Ping a target host.

        Args:
            target: Target IP or hostname
            count: Number of ping packets to send
            timeout: Overall timeout for ping operation

        Returns:
            PingResult with success status and statistics
        """
        logger.debug(f"Pinging {target} from {self.ssh.container_name}")

        cmd = f"ping -c {count} -W 1 {target}"

        try:
            result = await self.ssh.exec_command(cmd, timeout=timeout, check=False)

            if result.returncode != 0:
                return PingResult(
                    success=False,
                    packet_loss=100.0,
                    error=result.stderr or "Ping failed"
                )

            # Parse ping output for statistics
            # Example: "4 packets transmitted, 4 received, 0% packet loss"
            packet_loss = 100.0
            avg_rtt = None

            for line in result.stdout.splitlines():
                if "packet loss" in line:
                    parts = line.split(",")
                    for part in parts:
                        if "% packet loss" in part:
                            loss_str = part.strip().split("%")[0].split()[-1]
                            packet_loss = float(loss_str)

                # Parse RTT: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.100 ms"
                if "rtt min/avg/max" in line:
                    parts = line.split("=")
                    if len(parts) > 1:
                        stats = parts[1].strip().split()[0]
                        avg_rtt = float(stats.split("/")[1])

            success = packet_loss < 100.0

            return PingResult(
                success=success,
                packet_loss=packet_loss,
                avg_rtt_ms=avg_rtt
            )

        except asyncio.TimeoutError:
            return PingResult(
                success=False,
                packet_loss=100.0,
                error=f"Ping timed out after {timeout}s"
            )
        except Exception as e:
            logger.error(f"Ping failed: {e}")
            return PingResult(
                success=False,
                packet_loss=100.0,
                error=str(e)
            )

    async def check_port(
        self,
        host: str,
        port: int,
        timeout: float = 5.0
    ) -> PortCheckResult:
        """Check if a TCP port is open.

        Args:
            host: Target hostname or IP
            port: Target port number
            timeout: Connection timeout in seconds

        Returns:
            PortCheckResult indicating if port is open
        """
        logger.debug(f"Checking {host}:{port} from {self.ssh.container_name}")

        # Use nc (netcat) for port checking
        cmd = f"nc -z -w {int(timeout)} {host} {port}"

        try:
            result = await self.ssh.exec_command(cmd, timeout=timeout + 1.0, check=False)

            return PortCheckResult(
                open=result.returncode == 0,
                host=host,
                port=port,
                error=result.stderr if result.returncode != 0 else None
            )

        except asyncio.TimeoutError:
            return PortCheckResult(
                open=False,
                host=host,
                port=port,
                error=f"Connection timed out after {timeout}s"
            )
        except Exception as e:
            logger.error(f"Port check failed: {e}")
            return PortCheckResult(
                open=False,
                host=host,
                port=port,
                error=str(e)
            )

    async def wait_for_port(
        self,
        host: str,
        port: int,
        timeout: float = 60.0,
        interval: float = 1.0
    ) -> bool:
        """Wait for a port to become available.

        Polls the port at regular intervals until it opens or timeout.

        Args:
            host: Target hostname or IP
            port: Target port number
            timeout: Maximum time to wait in seconds
            interval: Polling interval in seconds

        Returns:
            True if port became available, False if timeout
        """
        logger.info(f"Waiting for {host}:{port} to become available")

        start_time = time.time()
        attempts = 0

        while time.time() - start_time < timeout:
            attempts += 1
            result = await self.check_port(host, port, timeout=min(5.0, timeout))

            if result.open:
                elapsed = time.time() - start_time
                logger.info(f"Port {host}:{port} available after {elapsed:.1f}s ({attempts} attempts)")
                return True

            logger.debug(f"Port {host}:{port} not ready (attempt {attempts})")
            await asyncio.sleep(interval)

        logger.warning(f"Port {host}:{port} not available after {timeout}s")
        return False

    async def check_dns(
        self,
        hostname: str,
        timeout: float = 5.0
    ) -> bool:
        """Check if DNS resolution works for a hostname.

        Args:
            hostname: Hostname to resolve
            timeout: DNS lookup timeout in seconds

        Returns:
            True if hostname resolves, False otherwise
        """
        logger.debug(f"Resolving {hostname} from {self.ssh.container_name}")

        cmd = f"getent hosts {hostname}"

        try:
            result = await self.ssh.exec_command(cmd, timeout=timeout, check=False)
            return result.returncode == 0

        except asyncio.TimeoutError:
            logger.warning(f"DNS lookup timed out for {hostname}")
            return False
        except Exception as e:
            logger.error(f"DNS check failed: {e}")
            return False

    async def check_connectivity(
        self,
        target_ip: str,
        target_port: Optional[int] = None,
        ping_count: int = 3
    ) -> dict:
        """Comprehensive connectivity check.

        Performs both ping and port checks if port is specified.

        Args:
            target_ip: Target IP address
            target_port: Optional port to check
            ping_count: Number of ping packets

        Returns:
            Dictionary with connectivity test results
        """
        logger.info(f"Checking connectivity to {target_ip} from {self.ssh.container_name}")

        results = {}

        # Ping check
        ping_result = await self.ping(target_ip, count=ping_count)
        results["ping"] = {
            "success": ping_result.success,
            "packet_loss": ping_result.packet_loss,
            "avg_rtt_ms": ping_result.avg_rtt_ms,
            "error": ping_result.error
        }

        # Port check if specified
        if target_port is not None:
            port_result = await self.check_port(target_ip, target_port)
            results["port"] = {
                "open": port_result.open,
                "port": target_port,
                "error": port_result.error
            }

        results["overall_success"] = (
            ping_result.success and
            (target_port is None or results["port"]["open"])
        )

        return results

    def __repr__(self) -> str:
        """String representation."""
        return f"NetworkCheck(container={self.ssh.container_name})"
