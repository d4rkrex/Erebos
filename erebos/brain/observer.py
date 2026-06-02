"""Observer module for Erebos decision loop (REQ-001).

Parses raw tool output into typed Observation instances.

# VT-Spec T-01: Input sanitization before ANY processing
# VT-Spec R-01: All observations logged via EventLog
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional

from erebos.core.events import EventLog, EventType, Event
from erebos.core.models import (
    EngagementPhase,
    Observation,
    ObservationType,
)

logger = logging.getLogger(__name__)

# VT-Spec T-01: Maximum field length for observation data values
MAX_FIELD_LENGTH = 1024
# VT-Spec T-01: Maximum raw output size before truncation
MAX_RAW_OUTPUT_SIZE = 10240  # 10KB

# VT-Spec T-01: Control character stripping pattern (keep \n and \t)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# VT-Spec T-01: Injection pattern detection
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+previous\s+instructions?", re.IGNORECASE),
    re.compile(r"ignore\s+all\s+previous", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"```\s*system\s*```", re.IGNORECASE),
    re.compile(r"<\|?system\|?>", re.IGNORECASE),
    re.compile(r"IGNORE\s+PREVIOUS", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"override\s+instructions?", re.IGNORECASE),
]

# Nmap parsing patterns
NMAP_PORT_PATTERN = re.compile(
    r"^(\d+)/(\w+)\s+(open|filtered)\s+(\S+)(?:[^\S\n]+(.+))?$", re.MULTILINE
)
NMAP_SERVICE_PATTERN = re.compile(
    r"^(\d+)/(\w+)\s+open\s+(\S+)[^\S\n]+(.+)$", re.MULTILINE
)

# Nikto CVE pattern
NIKTO_CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
NIKTO_FINDING_PATTERN = re.compile(r"\+\s+(.+)")

# Credential detection patterns
CREDENTIAL_PATTERNS = [
    re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"passwd\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"token\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"secret\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
    re.compile(r"Authorization:\s*Bearer\s+\S+", re.IGNORECASE),
]

# Gobuster pattern
GOBUSTER_PATTERN = re.compile(r"/(\S+)\s+\(Status:\s*(\d+)\)")


def compute_observation_content_hash(obs_type: str, data: Dict[str, Any]) -> str:
    """Compute content hash for deduplication, ignoring volatile fields.

    # VT-Spec D-01: Content-hash deduplication ignoring volatile fields
    """
    # Exclude volatile fields like timestamps, session IDs
    stable_data = {
        k: v for k, v in sorted(data.items())
        if k not in ("timestamp", "session_id", "nonce", "request_id")
    }
    content = f"{obs_type}|{stable_data}"
    return hashlib.sha256(content.encode()).hexdigest()


class Observer:
    """Parses raw tool output into typed Observation instances.

    # VT-Spec T-01: Input sanitization before ANY processing
    # VT-Spec R-01: Events emitted for every observation
    """

    def __init__(self, event_log: Optional[EventLog] = None):
        self._event_log = event_log
        self._seen_hashes: set[str] = set()

    def sanitize_input(self, raw: str) -> str:
        """Sanitize raw input before processing.

        # VT-Spec T-01 CRITICAL: Strip control chars, limit size, detect injection
        """
        # VT-Spec T-01: Truncate to max size
        if len(raw) > MAX_RAW_OUTPUT_SIZE:
            raw = raw[:MAX_RAW_OUTPUT_SIZE]
            logger.warning(
                "VT-Spec T-01: Raw output truncated to %d bytes", MAX_RAW_OUTPUT_SIZE
            )

        # VT-Spec T-01: Strip control characters (keep \n \t)
        raw = CONTROL_CHAR_PATTERN.sub("", raw)

        return raw

    def detect_injection(self, text: str) -> bool:
        """Detect potential prompt injection patterns in tool output.

        # VT-Spec T-01: Canary detection for injection patterns
        """
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                logger.warning(
                    "VT-Spec T-01: Injection pattern detected in tool output"
                )
                return True
        return False

    def _truncate_field(self, value: str) -> str:
        """Truncate a field value to max length.

        # VT-Spec T-01: Limit field length to MAX_FIELD_LENGTH chars
        """
        if len(value) > MAX_FIELD_LENGTH:
            return value[:MAX_FIELD_LENGTH]
        return value

    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize all string values in observation data.

        # VT-Spec T-01: Limit field lengths
        """
        sanitized = {}
        for k, v in data.items():
            if isinstance(v, str):
                v = CONTROL_CHAR_PATTERN.sub("", v)
                v = self._truncate_field(v)
            sanitized[k] = v
        return sanitized

    def _is_duplicate(self, obs_type: str, data: Dict[str, Any]) -> bool:
        """Check if observation is a duplicate via content hash.

        # VT-Spec D-01: Content-hash deduplication ignoring volatile fields
        """
        content_hash = compute_observation_content_hash(obs_type, data)
        if content_hash in self._seen_hashes:
            return True
        self._seen_hashes.add(content_hash)
        return False

    def _emit_event(self, engagement_id: str, observation: Observation) -> None:
        """Emit observation event to EventLog.

        # VT-Spec R-01: Every observation logged
        """
        if self._event_log:
            event = Event(
                engagement_id=engagement_id,
                event_type=EventType.OBSERVATION_ADDED,
                data={
                    "observation_id": observation.id,
                    "observation_type": observation.observation_type.value,
                    "target_id": observation.target_id or "",
                },
                actor="brain.observer",
            )
            self._event_log.append(event)

    def process_output(
        self,
        raw: str,
        tool: str,
        context: Dict[str, Any],
    ) -> List[Observation]:
        """Parse raw tool output into Observations.

        # VT-Spec T-01: Sanitize before processing
        # VT-Spec R-01: Emit events for observations
        """
        engagement_id = context.get("engagement_id", "")
        target_id = context.get("target_id")
        phase = context.get("phase", EngagementPhase.RECON)
        if isinstance(phase, str):
            phase = EngagementPhase(phase)

        # VT-Spec T-01 CRITICAL: Sanitize input first
        sanitized = self.sanitize_input(raw)

        # VT-Spec T-01: Detect injection patterns
        injection_detected = self.detect_injection(sanitized)
        if injection_detected:
            obs = Observation(
                engagement_id=engagement_id,
                target_id=target_id,
                observation_type=ObservationType.ERROR,
                data=self._sanitize_data({
                    "warning": "Potential injection pattern detected in tool output",
                    "tool": tool,
                    "injection_detected": True,
                }),
                phase=phase,
            )
            self._emit_event(engagement_id, obs)
            return [obs]

        # Handle empty/malformed output
        if not sanitized or not sanitized.strip():
            obs = Observation(
                engagement_id=engagement_id,
                target_id=target_id,
                observation_type=ObservationType.ERROR,
                data=self._sanitize_data({"error": "Empty tool output", "tool": tool}),
                phase=phase,
            )
            self._emit_event(engagement_id, obs)
            return [obs]

        # Route to tool-specific parser
        tool_lower = tool.lower()
        if tool_lower == "nmap":
            observations = self._parse_nmap(sanitized, engagement_id, target_id, phase)
        elif tool_lower == "nikto":
            observations = self._parse_nikto(sanitized, engagement_id, target_id, phase)
        elif tool_lower == "gobuster":
            observations = self._parse_gobuster(sanitized, engagement_id, target_id, phase)
        else:
            observations = self._parse_generic(sanitized, tool, engagement_id, target_id, phase)

        # Check for credentials in output
        cred_observations = self._detect_credentials(
            sanitized, engagement_id, target_id, phase
        )
        observations.extend(cred_observations)

        # If no observations parsed, emit error observation
        if not observations:
            obs = Observation(
                engagement_id=engagement_id,
                target_id=target_id,
                observation_type=ObservationType.ERROR,
                data=self._sanitize_data({
                    "error": "No parseable data in output",
                    "tool": tool,
                    "raw_snippet": sanitized[:200],
                }),
                phase=phase,
            )
            self._emit_event(engagement_id, obs)
            return [obs]

        # Emit events for all observations
        for obs in observations:
            self._emit_event(engagement_id, obs)

        return observations

    def _parse_nmap(
        self,
        output: str,
        engagement_id: str,
        target_id: Optional[str],
        phase: EngagementPhase,
    ) -> List[Observation]:
        """Parse nmap output into Observations."""
        observations: List[Observation] = []

        for match in NMAP_PORT_PATTERN.finditer(output):
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4) or ""
            version_info = match.group(5) or ""

            if state == "open":
                data: Dict[str, Any] = self._sanitize_data({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                })

                # Deduplication check
                if self._is_duplicate(ObservationType.PORT_OPEN.value, data):
                    continue

                observations.append(
                    Observation(
                        engagement_id=engagement_id,
                        target_id=target_id,
                        observation_type=ObservationType.PORT_OPEN,
                        data=data,
                        phase=phase,
                    )
                )

                # If version info present, also emit SERVICE_DETECTED
                if version_info.strip():
                    svc_data = self._sanitize_data({
                        "port": port,
                        "service": service,
                        "version": version_info.strip(),
                        "product": version_info.split()[0] if version_info.strip() else "",
                    })

                    if not self._is_duplicate(ObservationType.SERVICE_DETECTED.value, svc_data):
                        observations.append(
                            Observation(
                                engagement_id=engagement_id,
                                target_id=target_id,
                                observation_type=ObservationType.SERVICE_DETECTED,
                                data=svc_data,
                                phase=phase,
                            )
                        )

        return observations

    def _parse_nikto(
        self,
        output: str,
        engagement_id: str,
        target_id: Optional[str],
        phase: EngagementPhase,
    ) -> List[Observation]:
        """Parse nikto output into Observations."""
        observations: List[Observation] = []

        for line in output.splitlines():
            # Check for CVEs
            cve_matches = NIKTO_CVE_PATTERN.findall(line)
            if cve_matches:
                for cve in cve_matches:
                    data = self._sanitize_data({
                        "cve_id": cve,
                        "description": line.strip(),
                        "tool": "nikto",
                    })
                    if not self._is_duplicate(
                        ObservationType.VULNERABILITY_FOUND.value, data
                    ):
                        observations.append(
                            Observation(
                                engagement_id=engagement_id,
                                target_id=target_id,
                                observation_type=ObservationType.VULNERABILITY_FOUND,
                                data=data,
                                phase=phase,
                            )
                        )
            elif NIKTO_FINDING_PATTERN.match(line):
                finding = NIKTO_FINDING_PATTERN.match(line)
                if finding:
                    finding_text = finding.group(1).strip()
                    if finding_text and not finding_text.startswith("Target"):
                        data = self._sanitize_data({
                            "finding": finding_text,
                            "tool": "nikto",
                        })
                        if not self._is_duplicate(
                            ObservationType.VULNERABILITY_FOUND.value, data
                        ):
                            observations.append(
                                Observation(
                                    engagement_id=engagement_id,
                                    target_id=target_id,
                                    observation_type=ObservationType.VULNERABILITY_FOUND,
                                    data=data,
                                    phase=phase,
                                )
                            )

        return observations

    def _parse_gobuster(
        self,
        output: str,
        engagement_id: str,
        target_id: Optional[str],
        phase: EngagementPhase,
    ) -> List[Observation]:
        """Parse gobuster output into Observations."""
        observations: List[Observation] = []

        for match in GOBUSTER_PATTERN.finditer(output):
            path = match.group(1)
            status = int(match.group(2))
            data = self._sanitize_data({
                "path": f"/{path}",
                "status_code": status,
                "tool": "gobuster",
            })
            if not self._is_duplicate(ObservationType.SERVICE_DETECTED.value, data):
                observations.append(
                    Observation(
                        engagement_id=engagement_id,
                        target_id=target_id,
                        observation_type=ObservationType.SERVICE_DETECTED,
                        data=data,
                        phase=phase,
                    )
                )

        return observations

    def _parse_generic(
        self,
        output: str,
        tool: str,
        engagement_id: str,
        target_id: Optional[str],
        phase: EngagementPhase,
    ) -> List[Observation]:
        """Generic parser for unrecognized tools — emit as info observation."""
        data = self._sanitize_data({
            "tool": tool,
            "raw_snippet": output[:500],
        })
        return [
            Observation(
                engagement_id=engagement_id,
                target_id=target_id,
                observation_type=ObservationType.ERROR,
                data=data,
                phase=phase,
            )
        ]

    def _detect_credentials(
        self,
        output: str,
        engagement_id: str,
        target_id: Optional[str],
        phase: EngagementPhase,
    ) -> List[Observation]:
        """Detect credentials in tool output.

        # VT-Spec I-01: Credential detection
        """
        observations: List[Observation] = []

        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(output):
                data = self._sanitize_data({
                    "warning": "Potential credential detected in output",
                    "credential_type": "detected",
                })
                if not self._is_duplicate(
                    ObservationType.CREDENTIAL_FOUND.value, data
                ):
                    observations.append(
                        Observation(
                            engagement_id=engagement_id,
                            target_id=target_id,
                            observation_type=ObservationType.CREDENTIAL_FOUND,
                            data=data,
                            phase=phase,
                        )
                    )
                break  # One credential observation per output is enough

        return observations

    def reset_deduplication(self) -> None:
        """Reset deduplication cache (e.g., between phases)."""
        self._seen_hashes.clear()
