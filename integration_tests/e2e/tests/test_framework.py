"""Basic framework functionality tests."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_cluster_from_topology(docker_dir):
    """Test that clusters can be created from topology names."""
    from ..framework.cluster import Cluster

    cluster = Cluster.from_topology("2-node", docker_dir=docker_dir)
    assert cluster is not None
    assert cluster.topology == "2-node"
    assert len(cluster.nodes) == 2
    assert "node-1" in cluster.nodes
    assert "node-2" in cluster.nodes


def test_node_config():
    """Test node configuration."""
    from ..framework.node import NodeConfig, Node

    config = NodeConfig(
        name="test-node",
        container_name="test-container",
        ip_address="172.30.0.10",
        node_id="node-1"
    )

    node = Node(config)
    assert node.name == "test-node"
    assert node.container_name == "test-container"
    assert node.get_ip() == "172.30.0.10"
    assert node.node_id == "node-1"


def test_cluster_topologies():
    """Test that all topologies are defined."""
    from ..framework.cluster import Cluster

    assert "2-node" in Cluster.TOPOLOGIES
    assert "3-node" in Cluster.TOPOLOGIES
    assert "5-node" in Cluster.TOPOLOGIES
    assert "10-node" in Cluster.TOPOLOGIES


# SSH Client Tests


@pytest.mark.asyncio
async def test_ssh_client_init():
    """Test SSHClient initialization."""
    from ..framework.ssh import SSHClient

    client = SSHClient("test-container", default_timeout=10.0)
    assert client.container_name == "test-container"
    assert client.default_timeout == 10.0
    assert not client._connected


@pytest.mark.asyncio
async def test_ssh_client_connect_success():
    """Test successful connection to container."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"true\n", b""))
        mock_subprocess.return_value = mock_process

        client = SSHClient("test-container")
        await client.connect()

        assert client._connected
        mock_subprocess.assert_called_once()


@pytest.mark.asyncio
async def test_ssh_client_connect_not_running():
    """Test connection to stopped container fails."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"false\n", b""))
        mock_subprocess.return_value = mock_process

        client = SSHClient("test-container")

        with pytest.raises(RuntimeError, match="is not running"):
            await client.connect()


@pytest.mark.asyncio
async def test_ssh_client_exec_command_success():
    """Test successful command execution."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"hello\n", b""))
        mock_subprocess.return_value = mock_process

        client = SSHClient("test-container")
        client._connected = True

        result = await client.exec_command("echo hello")

        assert result.success
        assert result.returncode == 0
        assert result.stdout == "hello\n"
        assert result.stderr == ""
        assert not result.timed_out


@pytest.mark.asyncio
async def test_ssh_client_exec_command_failure():
    """Test command execution failure."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error\n"))
        mock_subprocess.return_value = mock_process

        client = SSHClient("test-container")
        client._connected = True

        result = await client.exec_command("false", check=False)

        assert not result.success
        assert result.returncode == 1
        assert result.stderr == "error\n"


@pytest.mark.asyncio
async def test_ssh_client_exec_command_check_raises():
    """Test command failure raises exception when check=True."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error\n"))
        mock_subprocess.return_value = mock_process

        client = SSHClient("test-container")
        client._connected = True

        with pytest.raises(RuntimeError, match="Command failed"):
            await client.exec_command("false", check=True)


@pytest.mark.asyncio
async def test_ssh_client_exec_command_timeout():
    """Test command timeout handling."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_subprocess.return_value = mock_process

        client = SSHClient("test-container", default_timeout=1.0)
        client._connected = True

        result = await client.exec_command("sleep 10", check=False)

        assert not result.success
        assert result.timed_out
        assert "timed out" in result.stderr


@pytest.mark.asyncio
async def test_ssh_client_context_manager():
    """Test SSHClient as async context manager."""
    from ..framework.ssh import SSHClient

    with patch("asyncio.create_subprocess_exec") as mock_subprocess:
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"true\n", b""))
        mock_subprocess.return_value = mock_process

        async with SSHClient("test-container") as client:
            assert client._connected

        assert not client._connected


# NetworkCheck Tests


@pytest.mark.asyncio
async def test_network_check_init():
    """Test NetworkCheck initialization."""
    from ..framework.ssh import SSHClient
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    net = NetworkCheck(client)

    assert net.ssh is client


@pytest.mark.asyncio
async def test_network_check_ping_success():
    """Test successful ping operation."""
    from ..framework.ssh import SSHClient, CommandResult
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    ping_output = """PING 172.30.0.11 (172.30.0.11) 56(84) bytes of data.
64 bytes from 172.30.0.11: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from 172.30.0.11: icmp_seq=2 ttl=64 time=0.234 ms

--- 172.30.0.11 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.123/0.178/0.234/0.055 ms
"""

    with patch.object(client, "exec_command", return_value=CommandResult(
        returncode=0,
        stdout=ping_output,
        stderr=""
    )):
        result = await net.ping("172.30.0.11", count=2)

        assert result.success
        assert result.packet_loss == 0.0
        assert result.avg_rtt_ms == 0.178


@pytest.mark.asyncio
async def test_network_check_ping_failure():
    """Test ping failure."""
    from ..framework.ssh import SSHClient, CommandResult
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    with patch.object(client, "exec_command", return_value=CommandResult(
        returncode=1,
        stdout="",
        stderr="ping: unknown host"
    )):
        result = await net.ping("invalid-host")

        assert not result.success
        assert result.packet_loss == 100.0
        assert result.error is not None


@pytest.mark.asyncio
async def test_network_check_port_open():
    """Test port check for open port."""
    from ..framework.ssh import SSHClient, CommandResult
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    with patch.object(client, "exec_command", return_value=CommandResult(
        returncode=0,
        stdout="",
        stderr=""
    )):
        result = await net.check_port("172.30.0.11", 8080)

        assert result.open
        assert result.host == "172.30.0.11"
        assert result.port == 8080


@pytest.mark.asyncio
async def test_network_check_port_closed():
    """Test port check for closed port."""
    from ..framework.ssh import SSHClient, CommandResult
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    with patch.object(client, "exec_command", return_value=CommandResult(
        returncode=1,
        stdout="",
        stderr="Connection refused"
    )):
        result = await net.check_port("172.30.0.11", 9999)

        assert not result.open
        assert result.error == "Connection refused"


@pytest.mark.asyncio
async def test_network_check_wait_for_port_success():
    """Test waiting for port to become available."""
    from ..framework.ssh import SSHClient
    from ..framework.network import NetworkCheck, PortCheckResult

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    call_count = 0

    async def mock_check_port(host, port, timeout):
        nonlocal call_count
        call_count += 1
        if call_count >= 3:
            return PortCheckResult(open=True, host=host, port=port)
        return PortCheckResult(open=False, host=host, port=port)

    with patch.object(net, "check_port", side_effect=mock_check_port):
        result = await net.wait_for_port("172.30.0.11", 8080, timeout=10.0, interval=0.1)

        assert result is True
        assert call_count >= 3


@pytest.mark.asyncio
async def test_network_check_wait_for_port_timeout():
    """Test wait for port times out."""
    from ..framework.ssh import SSHClient
    from ..framework.network import NetworkCheck, PortCheckResult

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    async def mock_check_port(host, port, timeout):
        return PortCheckResult(open=False, host=host, port=port)

    with patch.object(net, "check_port", side_effect=mock_check_port):
        result = await net.wait_for_port("172.30.0.11", 8080, timeout=0.5, interval=0.1)

        assert result is False


@pytest.mark.asyncio
async def test_network_check_dns_success():
    """Test successful DNS resolution."""
    from ..framework.ssh import SSHClient, CommandResult
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    with patch.object(client, "exec_command", return_value=CommandResult(
        returncode=0,
        stdout="172.30.0.11 node-2\n",
        stderr=""
    )):
        result = await net.check_dns("node-2")

        assert result is True


@pytest.mark.asyncio
async def test_network_check_dns_failure():
    """Test DNS resolution failure."""
    from ..framework.ssh import SSHClient, CommandResult
    from ..framework.network import NetworkCheck

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    with patch.object(client, "exec_command", return_value=CommandResult(
        returncode=2,
        stdout="",
        stderr=""
    )):
        result = await net.check_dns("invalid-host")

        assert result is False


@pytest.mark.asyncio
async def test_network_check_connectivity_full():
    """Test comprehensive connectivity check."""
    from ..framework.ssh import SSHClient
    from ..framework.network import NetworkCheck, PingResult, PortCheckResult

    client = SSHClient("test-container")
    client._connected = True
    net = NetworkCheck(client)

    async def mock_ping(target, count):
        return PingResult(success=True, packet_loss=0.0, avg_rtt_ms=0.5)

    async def mock_check_port(host, port, timeout=5.0):
        return PortCheckResult(open=True, host=host, port=port)

    with patch.object(net, "ping", side_effect=mock_ping), \
         patch.object(net, "check_port", side_effect=mock_check_port):

        results = await net.check_connectivity("172.30.0.11", target_port=8080)

        assert results["overall_success"] is True
        assert results["ping"]["success"] is True
        assert results["port"]["open"] is True
