"""Network chaos injection framework using OS-level tools.

This module provides utilities for fault injection testing using tc netem, iptables,
and libfaketime. All tools execute inside Docker containers with NET_ADMIN and SYS_TIME
capabilities.

Design:
- tc netem: Latency, jitter, packet loss, reorder, corruption
- iptables: Network partitions (DROP rules)
- libfaketime: Clock skew simulation (via LD_PRELOAD)
- Async API: All operations use asyncio.subprocess
- Auto-cleanup: Pytest fixtures ensure cleanup on test completion
"""

import asyncio
from dataclasses import dataclass
from enum import Enum


class FaultType(Enum):
    """Types of network faults that can be injected."""

    LATENCY = "latency"
    JITTER = "jitter"
    PACKET_LOSS = "packet_loss"
    REORDER = "reorder"
    DUPLICATE = "duplicate"
    CORRUPT = "corrupt"
    PARTITION = "partition"
    CLOCK_SKEW = "clock_skew"


@dataclass
class ChaosScenario:
    """Predefined chaos scenario configuration."""

    name: str
    description: str
    delay_ms: int = 0
    jitter_ms: int = 0
    loss_percent: float = 0.0
    loss_correlation: int = 0
    reorder_percent: float = 0.0
    reorder_correlation: int = 0
    clock_offset_seconds: int = 0


# Predefined scenarios matching common network conditions
SCENARIOS = {
    "wan_link": ChaosScenario(
        name="wan_link",
        description="Typical WAN connection (50ms latency, 0.1% loss)",
        delay_ms=50,
        jitter_ms=10,
        loss_percent=0.1,
    ),
    "satellite_link": ChaosScenario(
        name="satellite_link",
        description="Satellite connection (600ms latency, 1% loss)",
        delay_ms=600,
        jitter_ms=20,
        loss_percent=1.0,
    ),
    "mobile_3g": ChaosScenario(
        name="mobile_3g",
        description="Mobile 3G (200ms±100ms, 2% loss, 5% reorder)",
        delay_ms=200,
        jitter_ms=100,
        loss_percent=2.0,
        reorder_percent=5.0,
        reorder_correlation=25,
    ),
    "flaky_wifi": ChaosScenario(
        name="flaky_wifi",
        description="Flaky WiFi (20ms±50ms, 5% loss, 50% correlation)",
        delay_ms=20,
        jitter_ms=50,
        loss_percent=5.0,
        loss_correlation=50,
    ),
}


async def _exec_in_container(node: str, cmd: str) -> tuple[int, str, str]:
    """Execute command in a Docker container.

    Args:
        node: Node name (e.g., "node-01")
        cmd: Shell command to execute

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    container_name = f"buckwild-e2e-{node}-1"

    proc = await asyncio.create_subprocess_exec(
        "docker",
        "exec",
        container_name,
        "sh",
        "-c",
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    returncode = proc.returncode if proc.returncode is not None else -1

    return (
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


async def apply_latency(
    node: str, delay_ms: int, jitter_ms: int = 0, correlation: int = 0
) -> None:
    """Apply latency to a node's outbound traffic via tc netem.

    Args:
        node: Node name (e.g., "node-01")
        delay_ms: Fixed delay in milliseconds
        jitter_ms: Jitter (standard deviation) in milliseconds
        correlation: Jitter correlation percentage (0-100)

    Raises:
        RuntimeError: If tc command fails
    """
    cmd = f"tc qdisc add dev eth0 root netem delay {delay_ms}ms"

    if jitter_ms > 0:
        cmd += f" {jitter_ms}ms"
        if correlation > 0:
            cmd += f" {correlation}%"

    returncode, stdout, stderr = await _exec_in_container(node, cmd)

    if returncode != 0:
        raise RuntimeError(f"Failed to apply latency on {node}: {stderr or stdout}")


async def apply_packet_loss(node: str, loss_pct: float, correlation: int = 0) -> None:
    """Apply packet loss via tc netem.

    Args:
        node: Node name (e.g., "node-01")
        loss_pct: Packet loss percentage (0.0-100.0)
        correlation: Loss correlation percentage for bursty loss (0-100)

    Raises:
        RuntimeError: If tc command fails
    """
    cmd = f"tc qdisc add dev eth0 root netem loss {loss_pct}%"

    if correlation > 0:
        cmd += f" {correlation}%"

    returncode, stdout, stderr = await _exec_in_container(node, cmd)

    if returncode != 0:
        raise RuntimeError(f"Failed to apply packet loss on {node}: {stderr or stdout}")


async def apply_reorder(
    node: str, reorder_pct: float, correlation: int = 25, gap: int = 5
) -> None:
    """Apply packet reordering via tc netem.

    Args:
        node: Node name (e.g., "node-01")
        reorder_pct: Reorder probability percentage (0.0-100.0)
        correlation: Reorder correlation percentage (0-100)
        gap: Number of packets to delay (default 5)

    Raises:
        RuntimeError: If tc command fails
    """
    cmd = f"tc qdisc add dev eth0 root netem reorder {reorder_pct}% {correlation}% gap {gap}"

    returncode, stdout, stderr = await _exec_in_container(node, cmd)

    if returncode != 0:
        raise RuntimeError(f"Failed to apply reordering on {node}: {stderr or stdout}")


async def apply_corruption(node: str, corrupt_pct: float) -> None:
    """Apply packet corruption via tc netem.

    Args:
        node: Node name (e.g., "node-01")
        corrupt_pct: Corruption probability percentage (0.0-100.0)

    Raises:
        RuntimeError: If tc command fails
    """
    cmd = f"tc qdisc add dev eth0 root netem corrupt {corrupt_pct}%"

    returncode, stdout, stderr = await _exec_in_container(node, cmd)

    if returncode != 0:
        raise RuntimeError(f"Failed to apply corruption on {node}: {stderr or stdout}")


async def apply_partition(source_node: str, target_ip: str) -> None:
    """Create network partition - source cannot reach target via iptables.

    Args:
        source_node: Node that will have packets dropped (e.g., "node-01")
        target_ip: Target IP address to block (e.g., "10.0.0.2")

    Raises:
        RuntimeError: If iptables command fails
    """
    cmd = f"iptables -A OUTPUT -d {target_ip} -j DROP"

    returncode, stdout, stderr = await _exec_in_container(source_node, cmd)

    if returncode != 0:
        raise RuntimeError(
            f"Failed to apply partition on {source_node}: {stderr or stdout}"
        )


async def apply_scenario(node: str, scenario: ChaosScenario) -> None:
    """Apply a complete chaos scenario to a node.

    Args:
        node: Node name (e.g., "node-01")
        scenario: Predefined chaos scenario configuration

    Raises:
        RuntimeError: If any command fails
    """
    # Clear existing rules first
    await clear_all_faults(node)

    # Build tc netem command with all parameters
    if (
        scenario.delay_ms > 0
        or scenario.loss_percent > 0
        or scenario.reorder_percent > 0
    ):
        cmd_parts = ["tc qdisc add dev eth0 root netem"]

        if scenario.delay_ms > 0:
            cmd_parts.append(f"delay {scenario.delay_ms}ms")
            if scenario.jitter_ms > 0:
                cmd_parts.append(f"{scenario.jitter_ms}ms")

        if scenario.loss_percent > 0:
            cmd_parts.append(f"loss {scenario.loss_percent}%")
            if scenario.loss_correlation > 0:
                cmd_parts.append(f"{scenario.loss_correlation}%")

        if scenario.reorder_percent > 0:
            cmd_parts.append(f"reorder {scenario.reorder_percent}%")
            if scenario.reorder_correlation > 0:
                cmd_parts.append(f"{scenario.reorder_correlation}%")

        cmd = " ".join(cmd_parts)
        returncode, stdout, stderr = await _exec_in_container(node, cmd)

        if returncode != 0:
            raise RuntimeError(
                f"Failed to apply scenario {scenario.name} on {node}: {stderr or stdout}"
            )


async def clear_all_faults(node: str) -> None:
    """Remove all network faults from a node.

    Args:
        node: Node name (e.g., "node-01")

    Note:
        This function does not raise errors if cleanup fails (best-effort cleanup).
    """
    # Remove tc qdisc rules (ignore errors)
    await _exec_in_container(node, "tc qdisc del dev eth0 root 2>/dev/null || true")

    # Remove iptables OUTPUT rules (ignore errors)
    await _exec_in_container(node, "iptables -F OUTPUT 2>/dev/null || true")


async def get_chaos_status(node: str) -> dict[str, str]:
    """Get current chaos configuration for a node.

    Args:
        node: Node name (e.g., "node-01")

    Returns:
        Dictionary with tc and iptables status
    """
    tc_returncode, tc_stdout, _ = await _exec_in_container(
        node, "tc qdisc show dev eth0"
    )
    iptables_returncode, iptables_stdout, _ = await _exec_in_container(
        node, "iptables -L OUTPUT -n"
    )

    return {
        "node": node,
        "tc_status": tc_stdout if tc_returncode == 0 else "error",
        "iptables_status": (iptables_stdout if iptables_returncode == 0 else "error"),
    }


def get_scenario(name: str) -> ChaosScenario:
    """Get a predefined chaos scenario by name.

    Args:
        name: Scenario name (e.g., "wan_link", "satellite_link")

    Returns:
        ChaosScenario configuration

    Raises:
        KeyError: If scenario name is not found
    """
    if name not in SCENARIOS:
        raise KeyError(
            f"Unknown scenario: {name}. Available: {', '.join(SCENARIOS.keys())}"
        )
    return SCENARIOS[name]
