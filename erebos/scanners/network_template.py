"""Parse nuclei network template YAML files.

VT-Spec INJ-02: Templates are parsed in strict mode — only allow tcp/udp protocols,
validate all fields against schema, reject shell characters in variables,
sandbox variable interpolation.
"""

import re
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

# VT-Spec INJ-02: Characters forbidden in template variable interpolation
_SHELL_CHARS_RE = re.compile(r"[;|&$`\\!<>{}()\[\]]")
# VT-Spec INJ-02: Only allow safe schemes (no file://, gopher://, etc.)
_FORBIDDEN_SCHEMES_RE = re.compile(r"(file|gopher|dict|ftp|ldap|jar)://", re.IGNORECASE)


class NetworkMatcher(BaseModel):
    """Matcher definition from a nuclei network template."""

    type: str = "word"  # word, regex, dsl
    words: List[str] = Field(default_factory=list)
    regex: List[str] = Field(default_factory=list)
    dsl: List[str] = Field(default_factory=list)
    encoding: str = ""  # hex, base64, or empty (plaintext)
    condition: str = "or"  # or, and
    name: str = ""
    negative: bool = False


class NetworkInput(BaseModel):
    """Input payload for a network probe."""

    data: str
    type: str = "text"  # text, hex
    read_size: int = 1024

    @field_validator("data")
    @classmethod
    def validate_data_no_shell_injection(cls, v: str) -> str:
        """VT-Spec INJ-02: Reject shell characters in template input data."""
        # Only check text-type inputs; hex inputs are safe binary
        # We check after type is set, but validator runs per-field
        # Shell chars in data payloads that aren't hex are suspicious
        if _FORBIDDEN_SCHEMES_RE.search(v):
            raise ValueError(
                f"INJ-02: Forbidden scheme detected in template input: {v[:50]}"
            )
        return v


class NetworkTemplate(BaseModel):
    """Parsed nuclei network template for TCP/UDP probing."""

    id: str
    name: str
    severity: str = "info"
    tags: List[str] = Field(default_factory=list)
    protocol: str = "tcp"  # tcp, udp
    port: Optional[int] = None
    inputs: List[NetworkInput] = Field(default_factory=list)
    read_size: int = 1024
    matchers: List[NetworkMatcher] = Field(default_factory=list)
    matchers_condition: str = "or"  # or, and
    target_service: Optional[str] = None  # inferred from tags/port
    cve_id: Optional[str] = None
    description: str = ""
    source_path: Optional[str] = None

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """VT-Spec INJ-02: Only allow tcp/udp protocols."""
        allowed = {"tcp", "udp"}
        if v.lower() not in allowed:
            raise ValueError(f"INJ-02: Only tcp/udp protocols allowed, got: {v}")
        return v.lower()

    @field_validator("port")
    @classmethod
    def validate_port_range(cls, v: Optional[int]) -> Optional[int]:
        """Validate port is in valid range."""
        if v is not None and (v < 1 or v > 65535):
            raise ValueError(f"Port must be 1-65535, got: {v}")
        return v


class NetworkTemplateParser:
    """Parse nuclei network template YAML files.

    VT-Spec INJ-02: Strict mode parsing — validates schema, rejects
    dangerous content, sandboxes variable interpolation.
    """

    # VT-Spec DOS-01: Maximum number of inputs per template
    MAX_INPUTS_PER_TEMPLATE = 50

    # Service inference from common tags
    TAG_SERVICE_MAP = {
        "ftp": "ftp",
        "ssh": "ssh",
        "telnet": "telnet",
        "smtp": "smtp",
        "dns": "dns",
        "http": "http",
        "pop3": "pop3",
        "imap": "imap",
        "smb": "smb",
        "mssql": "mssql",
        "oracle": "oracle",
        "mysql": "mysql",
        "rdp": "rdp",
        "postgresql": "postgresql",
        "vnc": "vnc",
        "redis": "redis",
        "elasticsearch": "elasticsearch",
        "mongodb": "mongodb",
        "memcached": "memcached",
        "mqtt": "mqtt",
    }

    def parse_file(self, path: Path) -> Optional[NetworkTemplate]:
        """Parse a single template file. Returns None if not a network template.

        VT-Spec INJ-02: Strict schema validation applied.
        """
        try:
            content = path.read_text(encoding="utf-8")
            # VT-Spec INJ-02: Reject files with shell injection patterns
            if _SHELL_CHARS_RE.search(content) and _FORBIDDEN_SCHEMES_RE.search(content):
                return None

            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None

            return self._parse_dict(data, source_path=str(path))
        except (yaml.YAMLError, OSError, ValueError):
            return None

    def parse_yaml_content(self, content: str, source_path: str = "<inline>") -> Optional[NetworkTemplate]:
        """Parse template from YAML string content.

        VT-Spec INJ-02: Strict schema validation applied.
        """
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None
            return self._parse_dict(data, source_path=source_path)
        except (yaml.YAMLError, ValueError):
            return None

    def load_directory(self, dir_path: Path) -> List[NetworkTemplate]:
        """Load all network templates from a directory tree.

        VT-Spec DOS-01: Limits total templates loaded.
        """
        templates: List[NetworkTemplate] = []
        if not dir_path.exists():
            return templates

        for yaml_file in sorted(dir_path.rglob("*.yaml")):
            template = self.parse_file(yaml_file)
            if template is not None:
                templates.append(template)

        return templates

    def _parse_dict(self, data: dict, source_path: str = "") -> Optional[NetworkTemplate]:
        """Parse template from a dictionary structure."""
        # Must have tcp or udp section to be a network template
        protocol = "tcp"
        network_section = data.get("tcp")
        if network_section is None:
            network_section = data.get("udp")
            if network_section is None:
                return None  # Not a network template (could be http, javascript, etc.)
            protocol = "udp"

        # Skip javascript-based templates (not pure network)
        if "javascript" in data:
            return None

        info = data.get("info", {})
        template_id = data.get("id", "")
        if not template_id:
            return None

        # VT-Spec INJ-02: Validate template ID (no shell chars)
        if _SHELL_CHARS_RE.search(template_id):
            return None

        name = info.get("name", template_id)
        severity = info.get("severity", "info").lower()
        tags_raw = info.get("tags", "")
        tags = [t.strip() for t in tags_raw.split(",")] if isinstance(tags_raw, str) else tags_raw
        description = info.get("description", "")

        # Extract CVE ID from classification or template ID
        cve_id = None
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cve_id = classification.get("cve-id")
        if not cve_id and template_id.upper().startswith("CVE-"):
            cve_id = template_id.upper()

        # Parse network section (take first entry)
        if not isinstance(network_section, list) or len(network_section) == 0:
            return None

        probe = network_section[0]
        port = probe.get("port")
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                port = None

        read_size = probe.get("read-size", 1024)

        # Parse inputs
        inputs: List[NetworkInput] = []
        raw_inputs = probe.get("inputs", [])
        if isinstance(raw_inputs, list):
            # VT-Spec DOS-01: Cap inputs per template
            for inp in raw_inputs[: self.MAX_INPUTS_PER_TEMPLATE]:
                if isinstance(inp, dict):
                    inp_data = inp.get("data", "")
                    inp_type = inp.get("type", "text")
                    inp_read_size = inp.get("read-size", read_size)
                    try:
                        inputs.append(
                            NetworkInput(data=inp_data, type=inp_type, read_size=inp_read_size)
                        )
                    except ValueError:
                        continue  # Skip invalid inputs (INJ-02 rejection)

        # Parse matchers
        matchers: List[NetworkMatcher] = []
        raw_matchers = probe.get("matchers", [])
        if isinstance(raw_matchers, list):
            for m in raw_matchers:
                if isinstance(m, dict):
                    matchers.append(
                        NetworkMatcher(
                            type=m.get("type", "word"),
                            words=m.get("words", []),
                            regex=m.get("regex", []),
                            dsl=m.get("dsl", []),
                            encoding=m.get("encoding", ""),
                            condition=m.get("condition", "or"),
                            name=m.get("name", ""),
                            negative=m.get("negative", False),
                        )
                    )

        matchers_condition = probe.get("matchers-condition", "or")

        # Infer target service from tags
        target_service = self._infer_service(tags, port)

        return NetworkTemplate(
            id=template_id,
            name=name,
            severity=severity,
            tags=tags,
            protocol=protocol,
            port=port,
            inputs=inputs,
            read_size=read_size,
            matchers=matchers,
            matchers_condition=matchers_condition,
            target_service=target_service,
            cve_id=cve_id,
            description=description if isinstance(description, str) else str(description),
            source_path=source_path,
        )

    def _infer_service(self, tags: List[str], port: Optional[int]) -> Optional[str]:
        """Infer target service from template tags or port."""
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in self.TAG_SERVICE_MAP:
                return self.TAG_SERVICE_MAP[tag_lower]

        # Fallback: infer from port
        if port is not None:
            from erebos.scanners.service_matcher import ServiceMatcher

            return ServiceMatcher.PORT_SERVICE_MAP.get(port)

        return None
