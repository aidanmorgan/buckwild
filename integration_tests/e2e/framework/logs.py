"""Log collection utilities for E2E testing.

This module provides utilities for collecting, filtering, and exporting logs
from Docker containers running Buckwild nodes.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """Log level filtering options."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    """Represents a single log entry."""

    timestamp: Optional[datetime]
    level: Optional[LogLevel]
    container: str
    message: str
    raw: str


class LogCollector:
    """Collects and filters logs from Docker containers.

    Provides methods to retrieve logs from containers, filter by time range
    and log level, search for patterns, and export to files.
    """

    def __init__(self, container_name: str):
        """Initialize a LogCollector for a specific container.

        Args:
            container_name: Name of the Docker container
        """
        self.container_name = container_name
        self._log_level_pattern = re.compile(
            r'\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]',
            re.IGNORECASE
        )

    async def get_logs(
        self,
        tail: Optional[int] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        timestamps: bool = True
    ) -> str:
        """Retrieve logs from the container.

        Args:
            tail: Number of lines from end of logs to retrieve
            since: Only return logs since this time (e.g., "10m", "1h", RFC3339 timestamp)
            until: Only return logs before this time (e.g., "10m", "1h", RFC3339 timestamp)
            timestamps: Include timestamps in output

        Returns:
            Container logs as string

        Raises:
            RuntimeError: If docker logs command fails
        """
        cmd = ["docker", "logs", self.container_name]

        if timestamps:
            cmd.append("--timestamps")

        if tail is not None:
            cmd.extend(["--tail", str(tail)])

        if since is not None:
            cmd.extend(["--since", since])

        if until is not None:
            cmd.extend(["--until", until])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout_bytes, stderr_bytes = await process.communicate()

            if process.returncode != 0:
                stderr = stderr_bytes.decode('utf-8') if stderr_bytes else ""
                raise RuntimeError(
                    f"Failed to get logs from {self.container_name}: {stderr}"
                )

            return stdout_bytes.decode('utf-8') if stdout_bytes else ""

        except Exception as e:
            logger.error(f"Error getting logs from {self.container_name}: {e}")
            raise

    async def get_logs_since(
        self,
        since: datetime,
        tail: Optional[int] = None
    ) -> str:
        """Retrieve logs since a specific datetime.

        Args:
            since: Return logs after this datetime
            tail: Maximum number of lines to retrieve

        Returns:
            Container logs as string
        """
        # Convert datetime to RFC3339 format for Docker
        since_str = since.isoformat() + "Z" if since.tzinfo is None else since.isoformat()
        return await self.get_logs(tail=tail, since=since_str)

    async def get_logs_range(
        self,
        since: datetime,
        until: datetime,
        tail: Optional[int] = None
    ) -> str:
        """Retrieve logs within a time range.

        Args:
            since: Return logs after this datetime
            until: Return logs before this datetime
            tail: Maximum number of lines to retrieve

        Returns:
            Container logs as string
        """
        since_str = since.isoformat() + "Z" if since.tzinfo is None else since.isoformat()
        until_str = until.isoformat() + "Z" if until.tzinfo is None else until.isoformat()
        return await self.get_logs(tail=tail, since=since_str, until=until_str)

    def _parse_log_entry(self, line: str) -> LogEntry:
        """Parse a single log line into a LogEntry.

        Args:
            line: Raw log line

        Returns:
            Parsed LogEntry
        """
        timestamp = None
        level = None
        message = line

        # Try to parse timestamp (RFC3339 format from Docker)
        # Example: 2025-01-11T04:12:34.123456789Z message
        timestamp_match = re.match(
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(.+)$',
            line
        )
        if timestamp_match:
            try:
                timestamp = datetime.fromisoformat(
                    timestamp_match.group(1).replace('Z', '+00:00')
                )
                message = timestamp_match.group(2)
            except ValueError:
                pass

        # Try to extract log level
        level_match = self._log_level_pattern.search(message)
        if level_match:
            try:
                level = LogLevel(level_match.group(1).upper())
            except ValueError:
                pass

        return LogEntry(
            timestamp=timestamp,
            level=level,
            container=self.container_name,
            message=message,
            raw=line
        )

    async def search_logs(
        self,
        pattern: str,
        level: Optional[LogLevel] = None,
        since: Optional[str] = None,
        case_sensitive: bool = False
    ) -> List[LogEntry]:
        """Search logs for a pattern with optional filtering.

        Args:
            pattern: Regex pattern to search for
            level: Filter by log level
            since: Only search logs since this time
            case_sensitive: Whether pattern matching is case-sensitive

        Returns:
            List of matching LogEntry objects
        """
        logs = await self.get_logs(since=since, timestamps=True)

        # Compile search pattern
        flags = 0 if case_sensitive else re.IGNORECASE
        search_re = re.compile(pattern, flags)

        matching_entries = []

        for line in logs.splitlines():
            if not line.strip():
                continue

            entry = self._parse_log_entry(line)

            # Apply level filter
            if level is not None and entry.level != level:
                continue

            # Apply pattern search
            if search_re.search(entry.message):
                matching_entries.append(entry)

        return matching_entries

    async def filter_by_level(
        self,
        level: LogLevel,
        since: Optional[str] = None,
        tail: Optional[int] = None
    ) -> List[LogEntry]:
        """Filter logs by log level.

        Args:
            level: Log level to filter by
            since: Only include logs since this time
            tail: Maximum number of lines to retrieve

        Returns:
            List of LogEntry objects matching the level
        """
        logs = await self.get_logs(since=since, tail=tail, timestamps=True)

        filtered_entries = []

        for line in logs.splitlines():
            if not line.strip():
                continue

            entry = self._parse_log_entry(line)

            if entry.level == level:
                filtered_entries.append(entry)

        return filtered_entries

    async def export_logs(
        self,
        output_path: Path,
        since: Optional[str] = None,
        until: Optional[str] = None,
        level: Optional[LogLevel] = None,
        tail: Optional[int] = None
    ) -> None:
        """Export logs to a file with optional filtering.

        Args:
            output_path: Path to write logs to
            since: Only export logs since this time
            until: Only export logs before this time
            level: Filter by log level
            tail: Maximum number of lines to export

        Raises:
            IOError: If file cannot be written
        """
        logs = await self.get_logs(
            since=since,
            until=until,
            tail=tail,
            timestamps=True
        )

        # If level filtering is requested, parse and filter
        if level is not None:
            entries = [
                self._parse_log_entry(line)
                for line in logs.splitlines()
                if line.strip()
            ]
            filtered_entries = [e for e in entries if e.level == level]
            content = "\n".join(e.raw for e in filtered_entries)
        else:
            content = logs

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content)
            logger.info(f"Exported logs to {output_path}")
        except Exception as e:
            logger.error(f"Failed to export logs to {output_path}: {e}")
            raise IOError(f"Failed to export logs: {e}")

    async def get_error_logs(
        self,
        since: Optional[str] = None,
        tail: Optional[int] = None
    ) -> List[LogEntry]:
        """Convenience method to get ERROR and CRITICAL level logs.

        Args:
            since: Only include logs since this time
            tail: Maximum number of lines to retrieve

        Returns:
            List of error-level LogEntry objects
        """
        logs = await self.get_logs(since=since, tail=tail, timestamps=True)

        error_entries = []

        for line in logs.splitlines():
            if not line.strip():
                continue

            entry = self._parse_log_entry(line)

            if entry.level in (LogLevel.ERROR, LogLevel.CRITICAL):
                error_entries.append(entry)

        return error_entries

    def __repr__(self) -> str:
        """String representation."""
        return f"LogCollector(container={self.container_name})"


class MultiContainerLogCollector:
    """Collects logs from multiple containers simultaneously.

    Useful for collecting logs from all nodes in a cluster.
    """

    def __init__(self, container_names: List[str]):
        """Initialize a MultiContainerLogCollector.

        Args:
            container_names: List of container names to collect logs from
        """
        self.collectors = {
            name: LogCollector(name)
            for name in container_names
        }

    async def get_all_logs(
        self,
        since: Optional[str] = None,
        tail: Optional[int] = None
    ) -> Dict[str, str]:
        """Get logs from all containers.

        Args:
            since: Only return logs since this time
            tail: Maximum number of lines per container

        Returns:
            Dictionary mapping container name to logs
        """
        tasks = {
            name: collector.get_logs(since=since, tail=tail)
            for name, collector in self.collectors.items()
        }

        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await task
            except Exception as e:
                logger.error(f"Failed to get logs from {name}: {e}")
                results[name] = f"Error: {e}"

        return results

    async def search_all(
        self,
        pattern: str,
        level: Optional[LogLevel] = None,
        since: Optional[str] = None
    ) -> Dict[str, List[LogEntry]]:
        """Search logs across all containers.

        Args:
            pattern: Regex pattern to search for
            level: Filter by log level
            since: Only search logs since this time

        Returns:
            Dictionary mapping container name to matching LogEntry objects
        """
        tasks = {
            name: collector.search_logs(pattern, level, since)
            for name, collector in self.collectors.items()
        }

        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await task
            except Exception as e:
                logger.error(f"Failed to search logs from {name}: {e}")
                results[name] = []

        return results

    async def export_all_logs(
        self,
        output_dir: Path,
        since: Optional[str] = None,
        until: Optional[str] = None,
        level: Optional[LogLevel] = None
    ) -> None:
        """Export logs from all containers to separate files.

        Args:
            output_dir: Directory to write log files to
            since: Only export logs since this time
            until: Only export logs before this time
            level: Filter by log level

        Raises:
            IOError: If files cannot be written
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        tasks = []
        for name, collector in self.collectors.items():
            output_path = output_dir / f"{name}.log"
            tasks.append(
                collector.export_logs(output_path, since, until, level)
            )

        await asyncio.gather(*tasks)
        logger.info(f"Exported all logs to {output_dir}")
