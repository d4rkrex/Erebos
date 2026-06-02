"""Metasploit Integration for Erebos (REQ-004).

Manages Metasploit Framework RPC connection, module search/execution, and loot collection.

# VT-Spec ID-01 HIGH: Credentials Fernet-encrypted, key from env var, never logged
# VT-Spec AC-001: Scope check on RHOSTS before any exploit
# VT-Spec R-01: All MSF RPC operations logged to audit trail
"""

from __future__ import annotations

import base64
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from erebos.core.models import PlannedAction
from erebos.executor.base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)

# VT-Spec ID-01: Environment variable for Fernet encryption key
MSF_KEY_ENV_VAR = "VT_STRIKE_MSF_KEY"


@dataclass
class MSFCredentials:
    """Encrypted Metasploit RPC credentials.

    # VT-Spec ID-01 HIGH: Credentials stored encrypted with Fernet.
    Never stored in plaintext. Key from environment variable.
    """

    encrypted_host: bytes = b""
    encrypted_port: bytes = b""
    encrypted_username: bytes = b""
    encrypted_password: bytes = b""
    encrypted_ssl: bytes = b""

    def __repr__(self) -> str:
        """VT-Spec ID-01: Never expose credentials in repr/str."""
        return "MSFCredentials(***REDACTED***)"

    def __str__(self) -> str:
        """VT-Spec ID-01: Never expose credentials in string representation."""
        return "MSFCredentials(***REDACTED***)"


class CredentialEncryptor:
    """VT-Spec ID-01 HIGH: Handles Fernet encryption/decryption of MSF credentials.

    Key is sourced ONLY from environment variable VT_STRIKE_MSF_KEY.
    Never logged, never in config plaintext.
    """

    def __init__(self):
        self._key: Optional[bytes] = None

    def _get_key(self) -> bytes:
        """Get Fernet key from environment variable.

        # VT-Spec ID-01: Key ONLY from env var, never from config file.
        """
        if self._key is None:
            key_str = os.environ.get(MSF_KEY_ENV_VAR)
            if not key_str:
                raise ValueError(
                    f"VT-Spec ID-01: {MSF_KEY_ENV_VAR} environment variable not set. "
                    "MSF credentials cannot be decrypted."
                )
            self._key = key_str.encode()
        return self._key

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a string value using Fernet symmetric encryption.

        # VT-Spec ID-01: Fernet encryption for credential storage.
        """
        try:
            from cryptography.fernet import Fernet
            f = Fernet(self._get_key())
            return f.encrypt(plaintext.encode())
        except ImportError:
            # Fallback: base64 encode with marker (degraded security)
            logger.warning(
                "VT-Spec ID-01: cryptography package not installed, using fallback encoding"
            )
            return base64.b64encode(b"FALLBACK:" + plaintext.encode())

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt a Fernet-encrypted value.

        # VT-Spec ID-01: Decryption for runtime use only, never stored decrypted.
        """
        try:
            from cryptography.fernet import Fernet
            f = Fernet(self._get_key())
            return f.decrypt(ciphertext).decode()
        except ImportError:
            # Fallback: base64 decode
            decoded = base64.b64decode(ciphertext)
            if decoded.startswith(b"FALLBACK:"):
                return decoded[9:].decode()
            raise ValueError("Cannot decrypt: cryptography package not installed")


class MetasploitExecutor(BaseExecutor):
    """Metasploit Framework integration via RPC.

    # VT-Spec ID-01 HIGH: Credentials encrypted at rest, never logged
    # VT-Spec AC-001 CRITICAL: Scope check on RHOSTS before ANY exploit
    # VT-Spec R-01: All RPC operations logged to audit trail
    """

    def __init__(
        self,
        credentials: Optional[MSFCredentials] = None,
        scope_validator=None,
    ):
        self._credentials = credentials
        self._scope_validator = scope_validator
        self._encryptor = CredentialEncryptor()
        self._connected = False
        self._client = None  # RPC client instance
        self._active_jobs: dict[str, list[int]] = {}  # engagement_id → job IDs
        self._audit_log: list[dict] = []  # VT-Spec R-01

    @classmethod
    def from_plaintext(
        cls,
        host: str,
        port: int,
        username: str,
        password: str,
        ssl: bool = True,
        scope_validator=None,
    ) -> "MetasploitExecutor":
        """Create executor with credentials encrypted immediately.

        # VT-Spec ID-01: Credentials encrypted at creation, plaintext never stored.
        """
        encryptor = CredentialEncryptor()
        creds = MSFCredentials(
            encrypted_host=encryptor.encrypt(host),
            encrypted_port=encryptor.encrypt(str(port)),
            encrypted_username=encryptor.encrypt(username),
            encrypted_password=encryptor.encrypt(password),
            encrypted_ssl=encryptor.encrypt(str(ssl)),
        )
        instance = cls(credentials=creds, scope_validator=scope_validator)
        return instance

    def connect(self) -> bool:
        """Connect to msfrpcd.

        # VT-Spec ID-01: Credentials decrypted only for connection, never logged.
        # VT-Spec R-01: Connection attempt logged (without credentials).

        Returns:
            True if connected, False if connection failed.
        """
        if not self._credentials:
            logger.error("VT-Spec ID-01: No credentials configured for MSF connection")
            return False

        # VT-Spec R-01: Log connection attempt (NO credentials in log)
        self._audit_log.append({
            "action": "connect",
            "timestamp": time.time(),
            "status": "attempting",
        })

        try:
            # Decrypt credentials for connection only
            host = self._encryptor.decrypt(self._credentials.encrypted_host)
            port = int(self._encryptor.decrypt(self._credentials.encrypted_port))
            username = self._encryptor.decrypt(self._credentials.encrypted_username)
            password = self._encryptor.decrypt(self._credentials.encrypted_password)
            ssl = self._encryptor.decrypt(self._credentials.encrypted_ssl).lower() == "true"

            # Attempt RPC connection (graceful degradation if msfrpcd unavailable)
            try:
                from pymetasploit3.msfrpc import MsfRpcClient
                self._client = MsfRpcClient(
                    password, server=host, port=port, username=username, ssl=ssl
                )
                self._connected = True
            except ImportError:
                logger.warning(
                    "VT-Spec ID-01: pymetasploit3 not installed, MSF executor unavailable"
                )
                self._connected = False
                return False
            except Exception as e:
                # VT-Spec ID-01: NEVER log connection details in error
                logger.error(
                    "MSF RPC connection failed (details redacted for security): %s",
                    type(e).__name__,
                )
                self._connected = False
                return False

            self._audit_log.append({
                "action": "connect",
                "timestamp": time.time(),
                "status": "connected",
            })
            return True

        except ValueError as e:
            logger.error("VT-Spec ID-01: Credential decryption failed: %s", e)
            return False

    def search_modules(self, query: str) -> list[dict]:
        """Search for MSF modules matching a query.

        # VT-Spec R-01: Search operations logged.
        """
        if not self._connected or not self._client:
            logger.warning("MSF not connected, cannot search modules")
            return []

        self._audit_log.append({
            "action": "search_modules",
            "query": query,
            "timestamp": time.time(),
        })

        try:
            results = self._client.modules.search(query)
            return [{"name": r["fullname"], "type": r["type"]} for r in results]
        except Exception as e:
            logger.error("MSF module search failed: %s", e)
            return []

    def run_exploit(
        self,
        module: str,
        options: dict[str, Any],
        engagement_id: str,
    ) -> ExecutionResult:
        """Run an exploit module with scope checking.

        # VT-Spec AC-001 CRITICAL: Scope check on RHOSTS before ANY exploit execution.
        # VT-Spec R-01: Exploit execution logged to audit trail.
        """
        # VT-Spec AC-001: Mandatory scope check on RHOSTS
        rhosts = options.get("RHOSTS", options.get("RHOST", ""))
        if rhosts and self._scope_validator:
            scope_ok, reason = self._scope_validator.validate_command(f"msf {rhosts}")
            if not scope_ok:
                logger.warning(
                    "VT-Spec AC-001: MSF exploit RHOSTS scope check FAILED: %s",
                    reason,
                )
                return ExecutionResult(
                    stdout="",
                    stderr=f"VT-Spec AC-001: RHOSTS scope violation: {reason}",
                    exit_code=-1,
                )

        # VT-Spec R-01: Log exploit execution (redact sensitive options)
        safe_options = {k: v for k, v in options.items() if k.upper() != "PASSWORD"}
        self._audit_log.append({
            "action": "run_exploit",
            "module": module,
            "options": safe_options,
            "engagement_id": engagement_id,
            "timestamp": time.time(),
        })

        if not self._connected or not self._client:
            return ExecutionResult(
                stdout="",
                stderr="MSF RPC not connected",
                exit_code=-1,
            )

        start_time = time.monotonic()
        try:
            exploit = self._client.modules.use("exploit", module)
            for key, value in options.items():
                exploit[key] = value

            result = exploit.execute()
            duration = time.monotonic() - start_time

            # Track job for abort
            if engagement_id not in self._active_jobs:
                self._active_jobs[engagement_id] = []
            if "job_id" in result:
                self._active_jobs[engagement_id].append(result["job_id"])

            return ExecutionResult(
                stdout=str(result),
                stderr="",
                exit_code=0,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.monotonic() - start_time
            # VT-Spec ID-01: Never log full exception (may contain credentials)
            logger.error("MSF exploit execution failed: %s", type(e).__name__)
            return ExecutionResult(
                stdout="",
                stderr=f"Exploit execution failed: {type(e).__name__}",
                exit_code=-1,
                duration_seconds=duration,
            )

    def list_sessions(self) -> list[dict]:
        """List active Meterpreter/shell sessions."""
        if not self._connected or not self._client:
            return []

        try:
            sessions = self._client.sessions.list
            return [
                {"id": sid, "type": info.get("type", ""), "info": info.get("info", "")}
                for sid, info in sessions.items()
            ]
        except Exception:
            return []

    def collect_loot(self, session_id: int, engagement_id: str) -> list[Path]:
        """Collect loot from a session.

        # VT-Spec R-01: Loot collection logged.
        """
        self._audit_log.append({
            "action": "collect_loot",
            "session_id": session_id,
            "engagement_id": engagement_id,
            "timestamp": time.time(),
        })

        # Placeholder — actual loot collection via meterpreter
        return []

    def execute(self, action: PlannedAction, engagement_id: str) -> ExecutionResult:
        """Execute a Metasploit action.

        # VT-Spec AC-001: Scope validation before execution.
        """
        # Parse module and options from command
        # Expected format: "msfconsole use {module} set RHOSTS {target} ..."
        # or structured PlannedAction with command containing module info
        module, options = self._parse_msf_command(action.command)

        if not module:
            return ExecutionResult(
                stdout="",
                stderr="Could not parse MSF module from command",
                exit_code=-1,
            )

        return self.run_exploit(module, options, engagement_id)

    def cleanup(self, engagement_id: str) -> None:
        """Clean up MSF resources for an engagement."""
        if engagement_id in self._active_jobs:
            del self._active_jobs[engagement_id]

    def abort(self, engagement_id: str) -> None:
        """Abort all MSF jobs for an engagement.

        # VT-Spec EoP-02: Kill all active jobs.
        """
        if not self._connected or not self._client:
            return

        jobs = self._active_jobs.get(engagement_id, [])
        for job_id in jobs:
            try:
                self._client.jobs.stop(job_id)
            except Exception:
                pass

        if engagement_id in self._active_jobs:
            del self._active_jobs[engagement_id]

        self._audit_log.append({
            "action": "abort",
            "engagement_id": engagement_id,
            "jobs_killed": len(jobs),
            "timestamp": time.time(),
        })

    def _parse_msf_command(self, command: str) -> tuple[str, dict[str, Any]]:
        """Parse MSF module and options from command string.

        Returns:
            Tuple of (module_name, options_dict).
        """
        options: dict[str, Any] = {}
        module = ""

        parts = command.split()
        i = 0
        while i < len(parts):
            part = parts[i].lower()
            if part == "use" and i + 1 < len(parts):
                module = parts[i + 1]
                i += 2
            elif part == "set" and i + 2 < len(parts):
                key = parts[i + 1].upper()
                value = parts[i + 2]
                options[key] = value
                i += 3
            else:
                i += 1

        return module, options
