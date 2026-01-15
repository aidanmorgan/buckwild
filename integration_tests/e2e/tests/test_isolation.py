"""Isolation verification tests for E2E framework.

Tests verify that the network isolation policy is correctly enforced:
1. SSH access is allowed (management channel)
2. Buckwild tunnel traffic is allowed (our protocol)
3. Direct HTTP is blocked (isolation enforced)
4. DNS resolution is blocked (isolation enforced)
"""

import pytest
import asyncio

from ..framework.ssh import SSHClient
from ..framework.network import NetworkCheck


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_ssh_access_allowed(two_node_cluster):
    """Verify SSH access works between nodes.

    SSH is our management channel and must be allowed through the firewall.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()

    result = await ssh_client.exec_command(
        f"nc -z -w 3 {node2.get_ip()} 22",
        timeout=10.0,
        check=False
    )

    assert result.returncode == 0, f"SSH port should be accessible, stderr: {result.stderr}"
    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_buckwild_tunnel_works(two_node_cluster):
    """Verify Buckwild tunnel traffic is allowed.

    Our protocol uses UDP port 51820 and must be allowed through the firewall.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()

    result = await ssh_client.exec_command(
        f"nc -zu -w 3 {node2.get_ip()} 51820",
        timeout=10.0,
        check=False
    )

    assert result.returncode == 0, f"Buckwild port should be accessible, stderr: {result.stderr}"
    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_direct_http_blocked(two_node_cluster):
    """Verify direct HTTP access is blocked by firewall.

    Direct HTTP should be blocked - only Buckwild tunnel traffic allowed.
    Port 80 should be inaccessible.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()

    result = await ssh_client.exec_command(
        f"timeout 5 curl -f --max-time 3 http://{node2.get_ip()}:80 2>&1",
        timeout=10.0,
        check=False
    )

    assert result.returncode != 0, "HTTP should be blocked by firewall"
    assert "timed out" in result.stdout or "Connection refused" in result.stdout or "No route to host" in result.stderr, \
        f"Expected connection failure, got stdout: {result.stdout}, stderr: {result.stderr}"

    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_dns_resolution_blocked(two_node_cluster):
    """Verify DNS resolution is blocked.

    External DNS should be blocked to prevent data leakage.
    Only local resolution should work.
    """
    node1 = two_node_cluster.get_node("node-1")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()
    network_check = NetworkCheck(ssh_client)

    result = await network_check.check_dns("google.com")

    assert not result, "External DNS resolution should be blocked"

    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_https_blocked(two_node_cluster):
    """Verify HTTPS is blocked.

    HTTPS should be blocked - only Buckwild tunnel traffic allowed.
    Port 443 should be inaccessible.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()

    result = await ssh_client.exec_command(
        f"timeout 5 curl -f --max-time 3 https://{node2.get_ip()}:443 2>&1",
        timeout=10.0,
        check=False
    )

    assert result.returncode != 0, "HTTPS should be blocked by firewall"
    assert "timed out" in result.stdout or "Connection refused" in result.stdout or "No route to host" in result.stderr, \
        f"Expected connection failure, got stdout: {result.stdout}, stderr: {result.stderr}"

    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_icmp_ping_allowed(two_node_cluster):
    """Verify ICMP ping is allowed.

    ICMP should be allowed for connectivity verification.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()
    network_check = NetworkCheck(ssh_client)

    ping_result = await network_check.ping(node2.get_ip(), count=3, timeout=10.0)

    assert ping_result.success, f"Ping should succeed, packet_loss: {ping_result.packet_loss}%, error: {ping_result.error}"
    assert ping_result.packet_loss < 100.0, "Should have some successful pings"

    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_arbitrary_port_blocked(two_node_cluster):
    """Verify arbitrary ports are blocked by default.

    Only whitelisted ports (SSH, Buckwild) should be accessible.
    Random ports should be blocked.
    """
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()
    network_check = NetworkCheck(ssh_client)

    port_result = await network_check.check_port(node2.get_ip(), 9999, timeout=5.0)

    assert not port_result.open, "Arbitrary ports should be blocked"

    await ssh_client.disconnect()


@pytest.mark.e2e
@pytest.mark.isolation
@pytest.mark.asyncio
async def test_local_loopback_accessible(two_node_cluster):
    """Verify local loopback interface is accessible.

    Nodes should be able to access their own services on localhost.
    """
    node1 = two_node_cluster.get_node("node-1")

    ssh_client = SSHClient(node1.container_name)
    await ssh_client.connect()

    result = await ssh_client.exec_command(
        "curl -f --max-time 3 http://localhost:8080/health",
        timeout=10.0,
        check=False
    )

    assert result.returncode == 0, f"Localhost health check should work, stderr: {result.stderr}"

    await ssh_client.disconnect()
