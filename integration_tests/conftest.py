"""
Pytest configuration for top-level integration tests.
"""

import pytest
import asyncio
import subprocess
import time
import os
import signal
from pathlib import Path

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def buckwild_daemon():
    """Start and stop the Buckwild daemon for testing."""
    # Build the daemon first
    build_result = subprocess.run(
        ["cargo", "build", "--bin", "buckwild-daemon"],
        cwd="../",
        capture_output=True,
        text=True
    )
    
    if build_result.returncode != 0:
        pytest.fail(f"Failed to build daemon: {build_result.stderr}")
    
    # Start the daemon
    daemon_process = subprocess.Popen(
        ["../target/debug/buckwild-daemon", "--config", "test_config.toml"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for daemon to start
    time.sleep(2)
    
    # Check if daemon is running
    if daemon_process.poll() is not None:
        stdout, stderr = daemon_process.communicate()
        pytest.fail(f"Daemon failed to start: {stderr}")
    
    yield daemon_process
    
    # Clean shutdown
    daemon_process.send_signal(signal.SIGTERM)
    try:
        daemon_process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        daemon_process.kill()
        daemon_process.wait()

@pytest.fixture
def test_config():
    """Provide test configuration."""
    return {
        "daemon_host": "127.0.0.1",
        "daemon_port": 8080,
        "test_timeout": 30,
        "network_interface": "lo",
    }

@pytest.fixture
async def network_namespace():
    """Create isolated network namespace for testing."""
    # This would require root privileges
    # For now, return a placeholder
    yield "test_namespace"

@pytest.fixture
def docker_compose():
    """Manage Docker Compose for integration tests."""
    compose_file = Path(__file__).parent / "docker-compose.test.yml"
    
    # Start services
    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "up", "-d"],
        check=True
    )
    
    # Wait for services to be ready
    time.sleep(5)
    
    yield
    
    # Clean up
    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "down", "-v"],
        check=True
    )