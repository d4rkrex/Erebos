"""Secure tool executor — subprocess wrapper with safety controls.

VT-Spec T-01: No shell=True, argument validation, sanitized input.
VT-Spec D-01: 10MB stdout cap, timeout, concurrent subprocess limit.
VT-Spec E-01: Tool path validation against expected directories.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# VT-Spec D-01: Resource limits
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10MB
MAX_TOOL_TIMEOUT = 600  # 10 minutes absolute max
DEFAULT_TOOL_TIMEOUT = 300  # 5 minutes default
MAX_CONCURRENT_TOOLS = 4  # VT-Spec D-01: concurrent subprocess limit

# VT-Spec T-01: Argument validation patterns
SAFE_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")
SAFE_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
SAFE_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
SAFE_PATH_RE = re.compile(r"^[a-zA-Z0-9_\-\./]+$")

# VT-Spec E-01: Allowed directories for tool binaries
ALLOWED_TOOL_DIRS = [
    "/usr/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/snap/bin",
    "/opt/",
    "/opt/homebrew/bin",
]

# Global semaphore for concurrent tool limit
_tool_semaphore: Optional[asyncio.Semaphore] = None


def _get_tool_semaphore() -> asyncio.Semaphore:
    """Get or create the global tool execution semaphore."""
    global _tool_semaphore
    if _tool_semaphore is None:
        _tool_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TOOLS)
    return _tool_semaphore


class ToolResult(BaseModel):
    """Result of a tool execution."""

    tool: str
    command: List[str]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    truncated: bool = False


class ToolConfig(BaseModel):
    """Configuration for a specific tool."""

    name: str
    path: str
    default_args: List[str] = Field(default_factory=list)
    timeout: int = DEFAULT_TOOL_TIMEOUT
    allowed_arg_patterns: List[str] = Field(default_factory=list)


class ToolExecutor:
    """Execute security tools as subprocesses with safety controls.

    VT-Spec T-01: Never uses shell=True. Validates all arguments.
    VT-Spec D-01: Caps output, enforces timeout, limits concurrency.
    VT-Spec E-01: Validates tool binary paths.
    """

    def __init__(
        self,
        tools: Optional[Dict[str, ToolConfig]] = None,
        allowlist: Optional[List[str]] = None,
        env_passthrough: Optional[List[str]] = None,
    ):
        self._tools = tools or {}
        # VT-Spec T-01: Scope allowlist for target validation
        self._allowlist = [h.lower().strip() for h in (allowlist or [])]
        # VT-Spec I-01: Only pass specific env vars to subprocesses
        self._env_passthrough = env_passthrough or ["PATH", "HOME", "USER", "LANG"]

    def register_tool(self, config: ToolConfig) -> None:
        """Register a tool configuration after validating path."""
        # VT-Spec E-01: Validate tool path
        self._validate_tool_path(config.path)
        self._tools[config.name] = config

    async def run(
        self,
        tool_name: str,
        args: Optional[List[str]] = None,
        target: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        """Execute a registered tool with validated arguments.

        VT-Spec T-01: Arguments validated before execution.
        VT-Spec D-01: Output capped, timeout enforced, semaphore acquired.
        """
        if tool_name not in self._tools:
            return ToolResult(
                tool=tool_name,
                command=[tool_name],
                exit_code=-1,
                stderr=f"Tool '{tool_name}' not registered",
            )

        config = self._tools[tool_name]
        effective_timeout = min(timeout or config.timeout, MAX_TOOL_TIMEOUT)

        # VT-Spec T-01: Validate target against allowlist
        if target:
            self._validate_target(target)

        # VT-Spec T-01: Build and validate command
        cmd = self._build_command(config, args, target)

        # VT-Spec E-01: Re-validate path at execution time (could have changed)
        self._validate_tool_path(config.path)

        # VT-Spec I-01: Sanitized environment (no secrets)
        safe_env = self._build_safe_env()

        # VT-Spec D-01: Acquire concurrency semaphore
        semaphore = _get_tool_semaphore()
        async with semaphore:
            return await self._execute(cmd, safe_env, effective_timeout, tool_name)

    def run_sync(
        self,
        tool_name: str,
        args: Optional[List[str]] = None,
        target: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        """Synchronous wrapper for run()."""
        return asyncio.run(self.run(tool_name, args, target, timeout))

    async def _execute(
        self,
        cmd: List[str],
        env: Dict[str, str],
        timeout: int,
        tool_name: str,
    ) -> ToolResult:
        """Execute subprocess with output capping and timeout."""
        import time

        start = time.time()
        timed_out = False
        truncated = False

        try:
            # VT-Spec T-01: NEVER shell=True — use list args
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,  # process group for clean kill
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    self._read_with_limit(proc),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                timed_out = True
                # VT-Spec D-01: Kill process group on timeout
                try:
                    os.killpg(os.getpgid(proc.pid), 9)
                except (OSError, ProcessLookupError):
                    proc.kill()
                stdout_bytes = b""
                stderr_bytes = b"Process killed: timeout exceeded"
                await proc.wait()

            # VT-Spec D-01: Truncate if over limit
            if len(stdout_bytes) >= MAX_OUTPUT_BYTES:
                truncated = True
                stdout_bytes = stdout_bytes[:MAX_OUTPUT_BYTES]

            duration_ms = (time.time() - start) * 1000
            return ToolResult(
                tool=tool_name,
                command=cmd,
                exit_code=proc.returncode if proc.returncode is not None else -1,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace")[:50000],
                duration_ms=duration_ms,
                timed_out=timed_out,
                truncated=truncated,
            )

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error(f"Tool execution error ({tool_name}): {e}")
            return ToolResult(
                tool=tool_name,
                command=cmd,
                exit_code=-1,
                stderr=str(e),
                duration_ms=duration_ms,
            )

    async def _read_with_limit(self, proc: Any) -> tuple:
        """Read stdout/stderr with size limit (D-01)."""
        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        total_stdout = 0

        async def read_stdout():
            nonlocal total_stdout
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                total_stdout += len(chunk)
                if total_stdout <= MAX_OUTPUT_BYTES:
                    stdout_chunks.append(chunk)
                else:
                    # VT-Spec D-01: Kill on excessive output
                    logger.warning(f"Tool output exceeds {MAX_OUTPUT_BYTES} bytes — killing")
                    try:
                        os.killpg(os.getpgid(proc.pid), 9)
                    except (OSError, ProcessLookupError):
                        proc.kill()
                    break

        async def read_stderr():
            while True:
                chunk = await proc.stderr.read(65536)
                if not chunk:
                    break
                if sum(len(c) for c in stderr_chunks) < 50000:
                    stderr_chunks.append(chunk)

        await asyncio.gather(read_stdout(), read_stderr())
        await proc.wait()

        return b"".join(stdout_chunks), b"".join(stderr_chunks)

    def _build_command(
        self, config: ToolConfig, args: Optional[List[str]], target: Optional[str]
    ) -> List[str]:
        """Build command list with validated arguments.

        VT-Spec T-01: Every argument is validated against patterns.
        Strips URL scheme from target — CLI tools expect bare hostnames.
        """
        cmd = [config.path] + config.default_args

        if args:
            for arg in args:
                self._validate_argument(arg, config.name)
                cmd.append(arg)

        if target:
            # Strip scheme — nmap/subfinder/httpx expect bare hostnames
            from urllib.parse import urlparse

            clean_target = target.strip()
            if "://" in clean_target:
                parsed = urlparse(clean_target)
                clean_target = parsed.hostname or clean_target
            cmd.append(clean_target)

        return cmd

    def _validate_target(self, target: str) -> None:
        """VT-Spec T-01: Validate target is in allowlist and safe."""
        from urllib.parse import urlparse

        # Strip URL scheme if present — tools expect bare hostnames
        clean = target.strip().lower()
        if "://" in clean:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean

        if not (SAFE_HOSTNAME_RE.match(clean) or SAFE_IP_RE.match(clean)):
            raise ValueError(
                f"T-01: Invalid target format: '{target}'. "
                "Must be hostname or IP address."
            )

        # Check allowlist
        if self._allowlist:
            if not any(
                clean == allowed or clean.endswith(f".{allowed}")
                for allowed in self._allowlist
            ):
                raise ValueError(
                    f"T-01: Target '{target}' not in allowlist: {self._allowlist}"
                )

    def _validate_argument(self, arg: str, tool_name: str) -> None:
        """VT-Spec T-01: Validate argument contains no shell metacharacters."""
        # Block shell metacharacters
        dangerous_chars = set(";|&$`(){}[]!#~<>\\'\"\n\r\t")
        if any(c in arg for c in dangerous_chars):
            raise ValueError(
                f"T-01: Dangerous characters in argument for {tool_name}: '{arg}'"
            )

        # Block command substitution patterns
        if "$(" in arg or "${" in arg or "`" in arg:
            raise ValueError(
                f"T-01: Command substitution attempt in argument for {tool_name}: '{arg}'"
            )

    def _validate_tool_path(self, path: str) -> None:
        """VT-Spec E-01: Validate tool binary is in expected location."""
        resolved = Path(path).resolve()

        # Check exists
        if not resolved.exists():
            raise FileNotFoundError(f"E-01: Tool not found: {path}")

        # Check is not a symlink to unexpected location
        if resolved.is_symlink():
            link_target = resolved.resolve()
            if not any(str(link_target).startswith(d) for d in ALLOWED_TOOL_DIRS):
                raise ValueError(
                    f"E-01: Tool symlink points outside allowed dirs: "
                    f"{path} → {link_target}"
                )

        # Check in allowed directory
        in_path = any(str(resolved).startswith(d) for d in ALLOWED_TOOL_DIRS)
        in_user_path = str(resolved).startswith(str(Path.home()))
        if not (in_path or in_user_path):
            raise ValueError(
                f"E-01: Tool '{path}' not in allowed directories: {ALLOWED_TOOL_DIRS}"
            )

        # Check not world-writable
        try:
            file_stat = os.stat(resolved)
            if file_stat.st_mode & stat.S_IWOTH:
                logger.warning(f"E-01 SECURITY: Tool {path} is world-writable!")
        except OSError:
            pass

    def _build_safe_env(self) -> Dict[str, str]:
        """VT-Spec I-01: Build sanitized environment for subprocess.

        Never passes secrets or HMAC keys to child processes.
        """
        safe_env: Dict[str, str] = {}
        for key in self._env_passthrough:
            val = os.environ.get(key)
            if val:
                safe_env[key] = val
        return safe_env
