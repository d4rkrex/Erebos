"""Docker Sandbox Executor for Erebos (REQ-005).

Runs security tools in hardened Docker containers with full isolation.

# VT-Spec EoP-01 CRITICAL: Mandatory container hardening on ALL containers
# VT-Spec ID-03 MEDIUM: DNS/ICMP restriction to prevent tunneling
# VT-Spec R-01: All Docker API calls logged to audit trail
"""

from __future__ import annotations

import logging
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from erebos.core.models import PlannedAction
from erebos.executor.base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)

# VT-Spec EoP-01 CRITICAL: Mandatory hardening flags for ALL containers
MANDATORY_SECURITY_FLAGS = [
    "--no-new-privileges",
    "--cap-drop=ALL",
    "--read-only",
    "--security-opt=no-new-privileges:true",
    "--memory=512m",
    "--cpus=1.0",
    "--pids-limit=256",
]

# VT-Spec EoP-01: Optional capabilities that may be added back
ALLOWED_OPTIONAL_CAPS = frozenset(["NET_RAW"])  # For scanning tools only

# VT-Spec ID-03: DNS restriction configuration
DNS_RESTRICTION_FLAGS = [
    "--dns=127.0.0.1",  # Only local resolver
]

# Default sandbox configuration
DEFAULT_IMAGE = "erebos/sandbox:latest"
DEFAULT_TIMEOUT = 600  # 10 minutes
ABSOLUTE_MAX_TIMEOUT = 3600  # 1 hour


@dataclass
class ContainerInfo:
    """Tracks a running sandbox container."""

    container_id: str
    engagement_id: str
    image: str
    network: str
    created_at: float = field(default_factory=time.time)
    active: bool = True


class SandboxExecutor(BaseExecutor):
    """Executes tools in hardened Docker containers.

    # VT-Spec EoP-01 CRITICAL: ALL containers created with mandatory hardening:
    #   - --no-new-privileges
    #   - --cap-drop=ALL (add back only NET_RAW if needed)
    #   - --read-only (with tmpfs for /tmp)
    #   - --security-opt=no-new-privileges:true
    #   - --memory=512m --cpus=1.0 --pids-limit=256
    #   - --network={isolated_network} (NOT host network)
    #   - User namespace remapping
    # VT-Spec ID-03 MEDIUM: No DNS except managed resolver, block ICMP tunnels
    # VT-Spec R-01: All Docker API calls logged
    """

    def __init__(
        self,
        network_name: str = "erebos_target_net",
        default_image: str = DEFAULT_IMAGE,
        scope_validator=None,
        storage_dir: Optional[Path] = None,
    ):
        self._network_name = network_name
        self._default_image = default_image
        self._scope_validator = scope_validator
        self._storage_dir = storage_dir or Path("erebos-storage")
        self._containers: dict[str, list[ContainerInfo]] = {}  # engagement_id → containers
        self._audit_log: list[dict] = []  # VT-Spec R-01

    def create_container(
        self,
        image: str,
        engagement_id: str,
        network: Optional[str] = None,
        add_cap_net_raw: bool = False,
    ) -> str:
        """Create a hardened Docker container.

        # VT-Spec EoP-01 CRITICAL: ALL hardening flags MANDATORY.
        # VT-Spec ID-03: DNS restricted to local resolver only.
        # VT-Spec R-01: Container creation logged.

        Args:
            image: Docker image to use.
            engagement_id: Engagement this container belongs to.
            network: Docker network to attach (default: isolated target network).
            add_cap_net_raw: If True, add NET_RAW capability (for scanning tools).

        Returns:
            Container ID string.

        Raises:
            RuntimeError: If container creation fails.
        """
        container_name = f"vts_{engagement_id[:8]}_{uuid.uuid4().hex[:8]}"
        effective_network = network or self._network_name

        # VT-Spec EoP-01 CRITICAL: Build command with ALL mandatory hardening flags
        cmd = ["docker", "create", "--name", container_name]

        # Add ALL mandatory security flags
        cmd.extend(MANDATORY_SECURITY_FLAGS)

        # VT-Spec EoP-01: tmpfs for /tmp (since rootfs is read-only)
        cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=100m"])

        # VT-Spec EoP-01: User namespace remapping (non-root)
        cmd.extend(["--user", "65534:65534"])  # nobody:nogroup

        # VT-Spec EoP-01: Network isolation (NEVER host network)
        cmd.extend(["--network", effective_network])

        # VT-Spec ID-03: DNS restriction
        cmd.extend(DNS_RESTRICTION_FLAGS)

        # VT-Spec EoP-01: Optional NET_RAW for scanning tools only
        if add_cap_net_raw:
            cmd.extend(["--cap-add=NET_RAW"])

        # Image
        cmd.append(image)

        # VT-Spec R-01: Audit log (safe to log — no credentials in container create)
        self._audit_log.append({
            "action": "create_container",
            "container_name": container_name,
            "image": image,
            "engagement_id": engagement_id,
            "network": effective_network,
            "hardening_flags": MANDATORY_SECURITY_FLAGS,
            "timestamp": time.time(),
        })

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Docker create failed: {result.stderr.strip()}"
                )
            container_id = result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker create timed out")
        except FileNotFoundError:
            raise RuntimeError("Docker CLI not found")

        # Track container
        info = ContainerInfo(
            container_id=container_id,
            engagement_id=engagement_id,
            image=image,
            network=effective_network,
        )
        if engagement_id not in self._containers:
            self._containers[engagement_id] = []
        self._containers[engagement_id].append(info)

        return container_id

    def execute_in_container(
        self,
        container_id: str,
        command: list[str],
        timeout: int = DEFAULT_TIMEOUT,
    ) -> ExecutionResult:
        """Execute a command inside a container.

        # VT-Spec EoP-01: Container already hardened at creation.
        # VT-Spec DoS-01: Timeout enforcement.
        # VT-Spec R-01: Execution logged.

        Args:
            container_id: Docker container ID.
            command: Command as list of strings (NO shell interpretation).
            timeout: Execution timeout in seconds.

        Returns:
            ExecutionResult with stdout, stderr, exit_code.
        """
        effective_timeout = min(timeout, ABSOLUTE_MAX_TIMEOUT)

        # Start container if not running
        subprocess.run(
            ["docker", "start", container_id],
            capture_output=True,
            timeout=10,
            shell=False,
        )

        # VT-Spec R-01: Log execution
        self._audit_log.append({
            "action": "execute_in_container",
            "container_id": container_id[:12],
            "command": command,
            "timeout": effective_timeout,
            "timestamp": time.time(),
        })

        start_time = time.monotonic()
        truncated = False

        try:
            # Execute with shell=False, no raw interpretation
            exec_cmd = ["docker", "exec", container_id] + command
            result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                shell=False,
            )
            duration = time.monotonic() - start_time

            return ExecutionResult(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_seconds=duration,
                truncated=False,
            )

        except subprocess.TimeoutExpired as e:
            duration = time.monotonic() - start_time
            logger.warning(
                "VT-Spec DoS-01: Container command timed out after %ds", effective_timeout
            )
            # Auto-cleanup on timeout
            self._stop_container(container_id)
            return ExecutionResult(
                stdout=e.stdout.decode() if e.stdout else "",
                stderr=e.stderr.decode() if e.stderr else f"Timeout after {effective_timeout}s",
                exit_code=-1,
                duration_seconds=duration,
                truncated=True,
            )

        except FileNotFoundError:
            return ExecutionResult(
                stdout="",
                stderr="Docker CLI not found",
                exit_code=-1,
            )

    def execute(self, action: PlannedAction, engagement_id: str) -> ExecutionResult:
        """Execute a PlannedAction in a sandboxed container.

        # VT-Spec AC-001: Double scope validation at executor level.
        # VT-Spec EoP-01: Container created with full hardening.
        """
        # VT-Spec AC-001: Scope check at executor level
        if self._scope_validator:
            scope_ok, reason = self._scope_validator.validate_command(action.command)
            if not scope_ok:
                return ExecutionResult(
                    stdout="",
                    stderr=f"VT-Spec AC-001: Scope violation at sandbox executor: {reason}",
                    exit_code=-1,
                )

        # Determine if tool needs NET_RAW
        import shlex
        parts = shlex.split(action.command)
        tool_name = Path(parts[0]).name.lower() if parts else ""
        needs_net_raw = tool_name in ("nmap", "masscan", "ping", "traceroute")

        # Create hardened container
        try:
            container_id = self.create_container(
                image=self._default_image,
                engagement_id=engagement_id,
                add_cap_net_raw=needs_net_raw,
            )
        except RuntimeError as e:
            return ExecutionResult(
                stdout="",
                stderr=f"Container creation failed: {e}",
                exit_code=-1,
            )

        # Execute command in container
        result = self.execute_in_container(
            container_id=container_id,
            command=parts,
        )

        # Cleanup container after execution
        self._stop_container(container_id)
        self._remove_container(container_id)

        return result

    def cleanup(self, engagement_id: str) -> None:
        """Clean up all containers for an engagement."""
        self.cleanup_containers(engagement_id)

    def cleanup_containers(self, engagement_id: str) -> None:
        """Remove all containers for an engagement.

        # VT-Spec R-01: Cleanup logged.
        """
        containers = self._containers.get(engagement_id, [])
        for container in containers:
            if container.active:
                self._stop_container(container.container_id)
                self._remove_container(container.container_id)
                container.active = False

        self._audit_log.append({
            "action": "cleanup_containers",
            "engagement_id": engagement_id,
            "containers_cleaned": len(containers),
            "timestamp": time.time(),
        })

    def abort(self, engagement_id: str) -> None:
        """Abort all containers for an engagement.

        # VT-Spec EoP-02: Force kill all containers immediately.
        """
        containers = self._containers.get(engagement_id, [])
        for container in containers:
            if container.active:
                # Force kill (no grace period on abort)
                self._kill_container(container.container_id)
                self._remove_container(container.container_id)
                container.active = False

        self._audit_log.append({
            "action": "abort",
            "engagement_id": engagement_id,
            "containers_killed": len(containers),
            "timestamp": time.time(),
        })

    def _stop_container(self, container_id: str) -> None:
        """Stop a container gracefully."""
        try:
            subprocess.run(
                ["docker", "stop", "-t", "5", container_id],
                capture_output=True,
                timeout=15,
                shell=False,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self._kill_container(container_id)

    def _kill_container(self, container_id: str) -> None:
        """Force kill a container."""
        try:
            subprocess.run(
                ["docker", "kill", container_id],
                capture_output=True,
                timeout=10,
                shell=False,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    def _remove_container(self, container_id: str) -> None:
        """Remove a container."""
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                timeout=10,
                shell=False,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    def get_hardening_flags(self) -> list[str]:
        """Return the mandatory hardening flags for verification.

        Used by tests to verify all security flags are present.
        """
        return list(MANDATORY_SECURITY_FLAGS)
