"""CLI adapter for local tool execution."""

import os
import shutil
import subprocess
import time
from typing import Dict, Generator, List, Optional

from erebos.executors.base import ToolResult, Transport


class CLIAdapter(Transport):
    """CLI transport for local subprocess execution."""

    def __init__(self, extra_path: Optional[List[str]] = None):
        """Initialize CLI adapter with optional extra PATH directories."""
        self._extra_path = extra_path or []

    def _resolve_tool(self, tool: str) -> Optional[str]:
        """Resolve tool path, checking extra_path directories first."""
        # Check extra paths first (prefer Go/homebrew binaries over pip ones)
        for directory in self._extra_path:
            expanded = os.path.expandvars(os.path.expanduser(directory))
            candidate = os.path.join(expanded, tool)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        # Fallback to system PATH
        return shutil.which(tool)

    def execute(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        """Execute a tool via subprocess."""
        # Check if tool is available
        tool_path = self._resolve_tool(tool)
        if not tool_path:
            return ToolResult(
                tool=tool,
                exit_code=127,
                stdout="",
                stderr=f"Tool '{tool}' not found in PATH",
                duration_seconds=0.0,
                command_string=f"{tool} {' '.join(args)}",
            )

        # Build command
        cmd = [tool_path] + args
        command_string = f"{tool_path} {' '.join(args)}"

        # Merge environment
        exec_env = None
        if env:
            exec_env = {**os.environ.copy(), **env}

        # Execute
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=exec_env,
            )
            duration = time.time() - start_time
            return ToolResult(
                tool=tool,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=duration,
                command_string=command_string,
            )
        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time
            stdout_str = e.stdout.decode() if e.stdout else ""
            return ToolResult(
                tool=tool,
                exit_code=124,  # timeout exit code
                stdout=stdout_str,
                stderr=f"Command timed out after {timeout} seconds",
                duration_seconds=duration,
                command_string=command_string,
            )
        except Exception as e:
            duration = time.time() - start_time
            return ToolResult(
                tool=tool,
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=duration,
                command_string=command_string,
            )

    def stream(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
    ) -> Generator[str, None, None]:
        """Stream output in real-time."""
        # Check if tool is available
        tool_path = shutil.which(tool)
        if not tool_path:
            yield f"ERROR: Tool '{tool}' not found in PATH\n"
            return

        # Build command
        cmd = [tool] + args

        # Merge environment
        exec_env = None
        if env:
            exec_env = {**os.environ.copy(), **env}

        # Execute with streaming
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=exec_env,
            )

            # Stream stdout
            if process.stdout:
                for line in process.stdout:
                    yield line

            # Wait for completion
            process.wait()

            # Stream stderr if any
            if process.stderr:
                for line in process.stderr:
                    yield line

        except Exception as e:
            yield f"ERROR: {str(e)}\n"

    def available(self) -> bool:
        """Check if CLI transport is available."""
        # CLI is always available if we can run subprocess
        return True
