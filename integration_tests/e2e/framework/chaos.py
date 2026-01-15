"""Network chaos engineering utilities for E2E testing.

This module provides tc-based network impairment capabilities for testing
resilience under adverse network conditions.
"""

import asyncio
import logging
from typing import Optional
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class ChaosConfig:
    """Network chaos configuration."""

    loss_percent: float = 0.0
    delay_ms: int = 0
    jitter_ms: int = 0
    rate_kbps: int = 0

    def has_any(self) -> bool:
        """Check if any chaos is configured."""
        return (
            self.loss_percent > 0
            or self.delay_ms > 0
            or self.jitter_ms > 0
            or self.rate_kbps > 0
        )


class NetworkChaos:
    """Network chaos injection using Linux tc (traffic control).

    Provides methods to inject packet loss, latency, jitter, and bandwidth
    limitations into Docker containers for resilience testing.

    This class executes tc commands inside containers via docker exec,
    supporting both individual impairments and combined conditions.
    """

    def __init__(
        self,
        container: str,
        interface: str = "eth0",
        auto_cleanup: bool = True
    ):
        """Initialize NetworkChaos.

        Args:
            container: Container name or ID
            interface: Network interface to apply chaos to
            auto_cleanup: Whether to automatically cleanup on context exit
        """
        self.container = container
        self.interface = interface
        self.auto_cleanup = auto_cleanup
        self._applied = False
        self._config = ChaosConfig()

    async def _exec_tc(self, command: str) -> tuple[int, str, str]:
        """Execute tc command in container.

        Args:
            command: tc command to execute (without 'tc' prefix)

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        full_cmd = f"tc {command}"
        logger.debug(f"Executing tc on {self.container}: {full_cmd}")

        cmd = ["docker", "exec", self.container, "sh", "-c", full_cmd]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout_bytes, stderr_bytes = await process.communicate()
            stdout = stdout_bytes.decode('utf-8') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8') if stderr_bytes else ""
            returncode = process.returncode or 0

            if returncode != 0:
                logger.warning(
                    f"tc command failed on {self.container}: {stderr}"
                )

            return returncode, stdout, stderr

        except Exception as e:
            logger.error(f"Failed to execute tc on {self.container}: {e}")
            raise

    async def add_loss(self, percent: float) -> None:
        """Add packet loss.

        Args:
            percent: Packet loss percentage (0-100)

        Raises:
            ValueError: If percent is out of range
            RuntimeError: If tc command fails
        """
        if not 0 <= percent <= 100:
            raise ValueError(f"Loss percent must be 0-100, got {percent}")

        logger.info(f"Adding {percent}% packet loss to {self.container}")

        await self.clear()

        cmd = f"qdisc add dev {self.interface} root netem loss {percent}%"
        returncode, _, stderr = await self._exec_tc(cmd)

        if returncode != 0:
            raise RuntimeError(
                f"Failed to add packet loss: {stderr}"
            )

        self._applied = True
        self._config.loss_percent = percent

    async def add_latency(self, delay_ms: int, jitter_ms: int = 0) -> None:
        """Add network latency with optional jitter.

        Args:
            delay_ms: Base delay in milliseconds
            jitter_ms: Jitter (variation) in milliseconds

        Raises:
            ValueError: If delay or jitter is negative
            RuntimeError: If tc command fails
        """
        if delay_ms < 0:
            raise ValueError(f"Delay must be non-negative, got {delay_ms}")
        if jitter_ms < 0:
            raise ValueError(f"Jitter must be non-negative, got {jitter_ms}")

        logger.info(
            f"Adding {delay_ms}ms latency (jitter: {jitter_ms}ms) to {self.container}"
        )

        await self.clear()

        if jitter_ms > 0:
            cmd = f"qdisc add dev {self.interface} root netem delay {delay_ms}ms {jitter_ms}ms"
        else:
            cmd = f"qdisc add dev {self.interface} root netem delay {delay_ms}ms"

        returncode, _, stderr = await self._exec_tc(cmd)

        if returncode != 0:
            raise RuntimeError(
                f"Failed to add latency: {stderr}"
            )

        self._applied = True
        self._config.delay_ms = delay_ms
        self._config.jitter_ms = jitter_ms

    async def limit_bandwidth(self, rate_kbps: int) -> None:
        """Limit bandwidth to specified rate.

        Args:
            rate_kbps: Bandwidth limit in kilobits per second

        Raises:
            ValueError: If rate is not positive
            RuntimeError: If tc command fails
        """
        if rate_kbps <= 0:
            raise ValueError(f"Rate must be positive, got {rate_kbps}")

        logger.info(f"Limiting bandwidth to {rate_kbps}kbps on {self.container}")

        await self.clear()

        # Calculate burst size (10% of rate, min 32kbit)
        burst_kb = max(32, rate_kbps // 10)

        # Use tbf (token bucket filter) for rate limiting
        cmd = (
            f"qdisc add dev {self.interface} root tbf "
            f"rate {rate_kbps}kbit burst {burst_kb}kbit latency 400ms"
        )

        returncode, _, stderr = await self._exec_tc(cmd)

        if returncode != 0:
            raise RuntimeError(
                f"Failed to limit bandwidth: {stderr}"
            )

        self._applied = True
        self._config.rate_kbps = rate_kbps

    async def add_combined(
        self,
        loss_percent: float = 0,
        delay_ms: int = 0,
        jitter_ms: int = 0,
        rate_kbps: int = 0
    ) -> None:
        """Apply combined network conditions.

        Combines netem (loss/latency) with tbf (bandwidth limiting).
        Uses tc qdisc hierarchy: root netem -> child tbf.

        Args:
            loss_percent: Packet loss percentage (0-100)
            delay_ms: Base delay in milliseconds
            jitter_ms: Jitter in milliseconds
            rate_kbps: Bandwidth limit in kilobits per second

        Raises:
            ValueError: If any parameter is out of range
            RuntimeError: If tc command fails
        """
        if not 0 <= loss_percent <= 100:
            raise ValueError(f"Loss percent must be 0-100, got {loss_percent}")
        if delay_ms < 0:
            raise ValueError(f"Delay must be non-negative, got {delay_ms}")
        if jitter_ms < 0:
            raise ValueError(f"Jitter must be non-negative, got {jitter_ms}")
        if rate_kbps < 0:
            raise ValueError(f"Rate must be non-negative, got {rate_kbps}")

        logger.info(
            f"Adding combined chaos to {self.container}: "
            f"loss={loss_percent}%, delay={delay_ms}ms, "
            f"jitter={jitter_ms}ms, rate={rate_kbps}kbps"
        )

        await self.clear()

        has_netem = loss_percent > 0 or delay_ms > 0
        has_tbf = rate_kbps > 0

        if not has_netem and not has_tbf:
            logger.warning("No chaos conditions specified")
            return

        if has_netem and has_tbf:
            # Hierarchical: netem as root, tbf as child
            netem_parts = []
            if delay_ms > 0:
                if jitter_ms > 0:
                    netem_parts.append(f"delay {delay_ms}ms {jitter_ms}ms")
                else:
                    netem_parts.append(f"delay {delay_ms}ms")
            if loss_percent > 0:
                netem_parts.append(f"loss {loss_percent}%")

            netem_cmd = (
                f"qdisc add dev {self.interface} root handle 1: "
                f"netem {' '.join(netem_parts)}"
            )

            returncode, _, stderr = await self._exec_tc(netem_cmd)
            if returncode != 0:
                raise RuntimeError(f"Failed to add netem: {stderr}")

            # Add tbf as child
            burst_kb = max(32, rate_kbps // 10)
            tbf_cmd = (
                f"qdisc add dev {self.interface} parent 1: handle 2: "
                f"tbf rate {rate_kbps}kbit burst {burst_kb}kbit latency 400ms"
            )

            returncode, _, stderr = await self._exec_tc(tbf_cmd)
            if returncode != 0:
                # Cleanup netem on failure
                await self.clear()
                raise RuntimeError(f"Failed to add tbf: {stderr}")

        elif has_netem:
            # Only netem
            netem_parts = []
            if delay_ms > 0:
                if jitter_ms > 0:
                    netem_parts.append(f"delay {delay_ms}ms {jitter_ms}ms")
                else:
                    netem_parts.append(f"delay {delay_ms}ms")
            if loss_percent > 0:
                netem_parts.append(f"loss {loss_percent}%")

            cmd = f"qdisc add dev {self.interface} root netem {' '.join(netem_parts)}"
            returncode, _, stderr = await self._exec_tc(cmd)
            if returncode != 0:
                raise RuntimeError(f"Failed to add netem: {stderr}")

        else:
            # Only tbf
            burst_kb = max(32, rate_kbps // 10)
            cmd = (
                f"qdisc add dev {self.interface} root tbf "
                f"rate {rate_kbps}kbit burst {burst_kb}kbit latency 400ms"
            )
            returncode, _, stderr = await self._exec_tc(cmd)
            if returncode != 0:
                raise RuntimeError(f"Failed to add tbf: {stderr}")

        self._applied = True
        self._config.loss_percent = loss_percent
        self._config.delay_ms = delay_ms
        self._config.jitter_ms = jitter_ms
        self._config.rate_kbps = rate_kbps

    async def clear(self) -> None:
        """Remove all tc rules from the interface.

        This clears any existing qdisc rules on the interface,
        restoring normal network behavior.
        """
        if not self._applied:
            logger.debug(f"No chaos applied to {self.container}, skipping clear")
            return

        logger.info(f"Clearing network chaos from {self.container}")

        cmd = f"qdisc del dev {self.interface} root"
        returncode, _, stderr = await self._exec_tc(cmd)

        # Ignore "No such file or directory" - means already cleared
        if returncode != 0 and "No such file or directory" not in stderr:
            logger.warning(
                f"Failed to clear tc rules from {self.container}: {stderr}"
            )

        self._applied = False
        self._config = ChaosConfig()

    def get_config(self) -> ChaosConfig:
        """Get current chaos configuration.

        Returns:
            ChaosConfig with current settings
        """
        return self._config

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with automatic cleanup."""
        if self.auto_cleanup:
            await self.clear()
        return False

    def __repr__(self) -> str:
        """String representation."""
        status = "active" if self._applied else "inactive"
        return f"NetworkChaos(container={self.container}, interface={self.interface}, status={status})"
