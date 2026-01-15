"""SSH and command execution utilities for E2E testing.

This module provides an SSH-like client abstraction over Docker exec,
supporting async command execution with timeout and output capture.
"""

import asyncio
import logging
from typing import Optional
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of a command execution."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.returncode == 0 and not self.timed_out

    def __repr__(self) -> str:
        """String representation."""
        status = "success" if self.success else "failed"
        return f"CommandResult(status={status}, returncode={self.returncode})"


class SSHClient:
    """SSH-like client for Docker container command execution.

    Uses docker exec as transport instead of actual SSH, providing
    the same interface for async command execution with timeout.
    """

    def __init__(
        self,
        container_name: str,
        default_timeout: float = 30.0
    ):
        """Initialize SSHClient.

        Args:
            container_name: Target Docker container name
            default_timeout: Default command timeout in seconds
        """
        self.container_name = container_name
        self.default_timeout = default_timeout
        self._connected = False

    async def connect(self) -> None:
        """Establish connection to container.

        Verifies container exists and is running.

        Raises:
            RuntimeError: If container is not running
        """
        logger.debug(f"Connecting to container {self.container_name}")

        cmd = ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_bytes, stderr_bytes = await process.communicate()

            if process.returncode != 0:
                stderr = stderr_bytes.decode('utf-8') if stderr_bytes else ""
                raise RuntimeError(f"Container {self.container_name} not found: {stderr}")

            running = stdout_bytes.decode('utf-8').strip()
            if running != "true":
                raise RuntimeError(f"Container {self.container_name} is not running")

            self._connected = True
            logger.info(f"Connected to container {self.container_name}")

        except Exception as e:
            logger.error(f"Failed to connect to {self.container_name}: {e}")
            raise

    async def disconnect(self) -> None:
        """Disconnect from container.

        This is a no-op for Docker exec transport but matches SSH interface.
        """
        logger.debug(f"Disconnecting from {self.container_name}")
        self._connected = False

    async def exec_command(
        self,
        command: str,
        timeout: Optional[float] = None,
        check: bool = False
    ) -> CommandResult:
        """Execute a command in the container.

        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds (uses default if not specified)
            check: Whether to raise exception on non-zero return code

        Returns:
            CommandResult with returncode, stdout, stderr

        Raises:
            RuntimeError: If check=True and command fails
            asyncio.TimeoutError: If command exceeds timeout
        """
        if not self._connected:
            await self.connect()

        timeout = timeout if timeout is not None else self.default_timeout

        cmd = ["docker", "exec", self.container_name, "sh", "-c", command]
        logger.debug(f"Executing on {self.container_name}: {command}")

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

            result = CommandResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False
            )

            if check and returncode != 0:
                raise RuntimeError(
                    f"Command failed on {self.container_name} with code {returncode}: {stderr}"
                )

            return result

        except asyncio.TimeoutError:
            logger.error(f"Command timed out on {self.container_name} after {timeout}s: {command}")
            result = CommandResult(
                returncode=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                timed_out=True
            )
            if check:
                raise
            return result

        except Exception as e:
            logger.error(f"Error executing command on {self.container_name}: {e}")
            raise

    async def exec_command_async(
        self,
        command: str,
        timeout: Optional[float] = None
    ) -> asyncio.Task:
        """Execute a command asynchronously without waiting.

        Returns a Task that can be awaited later or cancelled.

        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds

        Returns:
            asyncio.Task that resolves to CommandResult
        """
        if not self._connected:
            await self.connect()

        async def _run():
            return await self.exec_command(command, timeout=timeout, check=False)

        task = asyncio.create_task(_run())
        logger.debug(f"Started async command on {self.container_name}: {command}")
        return task

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()

    def __repr__(self) -> str:
        """String representation."""
        status = "connected" if self._connected else "disconnected"
        return f"SSHClient(container={self.container_name}, status={status})"
