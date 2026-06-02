"""Configuration management for Erebos.

Config Loading Priority:
------------------------
1. Built-in defaults (from Config class)
2. Repo-local config (./config.yaml)
3. User config (~/.erebos/config.yaml) - HIGHEST PRIORITY

Merging Strategy:
-----------------
- Scalar values: User config overrides repo config
- Lists (e.g., security.allowlist): Merged from both configs, deduplicated
- Dicts (e.g., profiles): Deep merged, with user values taking precedence

Example:
--------
If repo config has:
    security:
      allowlist: ["host1.com", "host2.com"]
      rate_limit: 10

And user config has:
    security:
      allowlist: ["host2.com", "host3.com"]
      rate_limit: 20

Final merged config will be:
    security:
      allowlist: ["host1.com", "host2.com", "host3.com"]  # Merged, deduplicated
      rate_limit: 20  # User value wins
"""

import os
from pathlib import Path
from typing import Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ProfileToolsConfig(BaseModel):
    """Tools configuration for each phase."""

    recon: List[str] = Field(default_factory=list)
    discovery: List[str] = Field(default_factory=list)
    vuln_scan: List[str] = Field(default_factory=list)


class ProfileConfig(BaseModel):
    """Scan profile configuration."""

    name: str
    description: str
    tools: ProfileToolsConfig


class ExecutionConfig(BaseModel):
    """Execution settings."""

    transport: Literal["cli", "mcp"] = "cli"
    timeout_per_tool: int = 300
    max_retries: int = 3
    retry_backoff: str = "exponential"
    concurrency: int = 3
    enable_intelligent_error_handler: bool = False
    error_handler_fallback_chains_path: Optional[str] = None
    # Parallel execution (shannon-pipeline-upgrade)
    parallel: bool = False
    max_concurrency: int = 3  # VT-Spec DOS-001: Hard cap enforced at 10
    # Extra directories to search for tools (prepended to PATH)
    extra_path: List[str] = Field(default_factory=list)


class WorkspaceConfig(BaseModel):
    """Workspace settings."""

    base_dir: str = "./erebos-storage/workspaces"
    auto_resume: bool = True


class SecurityConfig(BaseModel):
    """Security settings."""

    allowlist: List[str] = Field(default_factory=list)
    rate_limit: int = 10
    dry_run: bool = False


class AIConfig(BaseModel):
    """AI enhancement feature flags."""

    enable_target_profile: bool = True
    enable_intelligent_decisions: bool = False
    decision_default_threshold: float = 0.70
    decision_stealth_threshold: float = 0.85
    decision_aggressive_threshold: float = 0.60
    decision_max_latency_ms: float = 50.0


class LLMProviderConfig(BaseModel):
    """Configuration for a single LLM provider in the cascade."""

    provider: Literal["copilot", "claude", "openrouter", "deepseek"] = "copilot"
    model: Optional[str] = None
    rate_limit: int = 10  # requests per minute


class ExploitationConfig(BaseModel):
    """Exploitation engine settings."""

    enabled: bool = True
    dry_run: bool = False
    timeout: int = 30
    templates_dir: Optional[str] = None
    llm_cascade: List[LLMProviderConfig] = Field(
        default_factory=lambda: [
            LLMProviderConfig(provider="copilot", model="claude-sonnet-4.6"),
            LLMProviderConfig(provider="claude", model="claude-sonnet-4-20250514"),
            LLMProviderConfig(provider="openrouter", model="anthropic/claude-sonnet-4-20250514"),
        ]
    )
    redact_patterns: List[str] = Field(default_factory=list)


class FleetConfig(BaseModel):
    """Fleet mode settings."""

    enabled: bool = False
    max_agents: int = 5
    findings_bus: str = "./erebos-storage/findings-bus.jsonl"
    roles: List[str] = Field(
        default_factory=lambda: ["recon", "vuln-scan", "exploit", "reporter"]
    )


class SSEConfig(BaseModel):
    """SSE transport configuration (VT-Spec REQ-011).

    VT-Spec T-001: Default host to 127.0.0.1 for security.
    VT-Spec EOP-001: Mandatory allowlist when SSE enabled.
    VT-Spec DOS-001: Connection limits and timeouts.
    VT-Spec T-002: CORS deny-all default.
    VT-Spec S-003: Trusted proxy configuration.
    """

    enabled: bool = False
    port: int = Field(default=8443, ge=1, le=65535)
    # VT-Spec T-001: Default to loopback to prevent cleartext exposure
    host: str = "127.0.0.1"
    # Token is required at startup (validated in server, not here)
    token: Optional[str] = None
    # VT-Spec REQ-006 / S-003: IP allowlist (CIDR notation supported)
    ip_allowlist: List[str] = Field(default_factory=list)
    # VT-Spec T-002 / REQ-005: CORS deny-all default
    cors_origins: List[str] = Field(default_factory=list)
    # VT-Spec DOS-001 / REQ-003: Connection limits
    max_connections: int = Field(default=50, ge=1, le=500)
    # VT-Spec DOS-001: Per-IP connection limit
    max_connections_per_ip: int = Field(default=5, ge=1, le=50)
    # VT-Spec REQ-003: Heartbeat interval in seconds
    heartbeat_interval: int = Field(default=30, ge=5, le=300)
    # VT-Spec REQ-003: Max connection duration in seconds (1 hour)
    max_duration: int = Field(default=3600, ge=60, le=86400)
    # VT-Spec DOS-001: Idle timeout (no data events) in seconds
    idle_timeout: int = Field(default=300, ge=30, le=3600)
    # VT-Spec T-001: TLS settings
    ssl_certfile: Optional[str] = None
    ssl_keyfile: Optional[str] = None
    # VT-Spec T-001: Explicit insecure flag for non-loopback without TLS
    insecure: bool = False
    # VT-Spec S-003: Trusted proxy IPs (only trust X-Forwarded-For from these)
    trusted_proxies: List[str] = Field(default_factory=list)
    # VT-Spec ID-001: Configurable health endpoint path
    health_path: str = "/health"
    # VT-Spec DOS-002: Request size limit (bytes)
    max_request_size: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    # Rate limiting: failed auth attempts per IP per minute
    auth_rate_limit: int = Field(default=5, ge=1, le=100)


def _default_profiles() -> Dict[str, ProfileConfig]:
    """Return default profile configurations."""
    return {
        "minimal": ProfileConfig(
            name="minimal",
            description="Stealthy scan with minimal footprint",
            tools=ProfileToolsConfig(
                recon=["katana"],
                discovery=[],
                vuln_scan=["nuclei-basic"],
            ),
        ),
        "standard": ProfileConfig(
            name="standard",
            description="Standard scan with common tools",
            tools=ProfileToolsConfig(
                recon=["katana", "nikto"],
                discovery=[],
                vuln_scan=["nuclei-medium"],
            ),
        ),
        "comprehensive": ProfileConfig(
            name="comprehensive",
            description="Full scan with all available tools",
            tools=ProfileToolsConfig(
                recon=["katana", "nikto"],
                discovery=[],
                vuln_scan=["nuclei-full"],
            ),
        ),
        "web-only": ProfileConfig(
            name="web-only",
            description="Web-focused assessment only",
            tools=ProfileToolsConfig(
                recon=["katana"],
                discovery=[],
                vuln_scan=["nuclei-web"],
            ),
        ),
        "vuln-focused": ProfileConfig(
            name="vuln-focused",
            description="Only vulnerability scanning",
            tools=ProfileToolsConfig(
                recon=[],
                discovery=[],
                vuln_scan=["nuclei"],
            ),
        ),
    }


class Config(BaseSettings):
    """Main configuration class."""

    # Profiles
    profiles: Dict[str, ProfileConfig] = Field(default_factory=_default_profiles)

    # Execution settings
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    # Security settings
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    # Workspace settings
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)

    # Exploitation engine settings
    exploitation: ExploitationConfig = Field(default_factory=ExploitationConfig)

    # Fleet mode settings
    fleet: FleetConfig = Field(default_factory=FleetConfig)

    # SSE transport settings (VT-Spec REQ-011)
    sse: SSEConfig = Field(default_factory=SSEConfig)

    # Output directory
    output_dir: str = "./erebos-reports"

    # AI enhancement settings
    ai: AIConfig = Field(default_factory=AIConfig)

    # Config file path
    _config_file: Optional[Path] = None

    class Config:
        env_prefix = "EREBOS_"
        extra = "ignore"

    @classmethod
    def from_yaml(cls, config_path: Path) -> "Config":
        """Load configuration from YAML file."""
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        config = cls(**data)
        config._config_file = config_path
        return config

    def save(self, config_path: Path) -> None:
        """Save configuration to YAML file."""
        data = self.model_dump(exclude={"_config_file"})
        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        self._config_file = config_path


# Global settings instance
_settings: Optional[Config] = None


def _merge_configs(base: Config, override: Config) -> Config:
    """Merge two configs, with override taking precedence.

    Strategy:
    - For scalar values: override wins
    - For lists (like allowlist): merge both, removing duplicates
    - For dicts (like profiles): deep merge, with override values winning

    Args:
        base: Base configuration (lower priority)
        override: Override configuration (higher priority)

    Returns:
        Merged configuration
    """
    # Get the data as dicts for easier manipulation
    base_data = base.model_dump(exclude={"_config_file"})
    override_data = override.model_dump(exclude={"_config_file"}, exclude_unset=True)

    # Deep merge function for nested dicts
    def deep_merge(base_dict: dict, override_dict: dict) -> dict:
        result = base_dict.copy()
        for key, override_value in override_dict.items():
            if key in result:
                base_value = result[key]
                # If both are dicts, merge recursively
                if isinstance(base_value, dict) and isinstance(override_value, dict):
                    result[key] = deep_merge(base_value, override_value)
                # If both are lists, merge and deduplicate
                elif isinstance(base_value, list) and isinstance(override_value, list):
                    # Preserve order: base first, then new items from override
                    seen = set()
                    merged = []
                    for item in base_value + override_value:
                        # Handle both hashable (strings) and non-hashable (dicts) items
                        item_key = str(item) if isinstance(item, dict) else item
                        if item_key not in seen:
                            seen.add(item_key)
                            merged.append(item)
                    result[key] = merged
                else:
                    # Scalar value: override wins
                    result[key] = override_value
            else:
                # New key from override
                result[key] = override_value
        return result

    # Merge the data
    merged_data = deep_merge(base_data, override_data)

    # Create new Config from merged data
    return Config(**merged_data)


def get_settings(config_file: Optional[Path] = None) -> Config:
    """Get the global settings instance.

    Config loading priority (last wins for scalar values, lists are merged):
    1. Built-in defaults (from Config class)
    2. Repo-local config (./config.yaml)
    3. User config (~/.erebos/config.yaml) - HIGHEST PRIORITY

    For list values (like security.allowlist), entries from all sources are merged.
    For scalar values, user config overrides repo config, which overrides defaults.
    """
    global _settings

    if _settings is None:
        if config_file is None:
            # Load and merge configs in priority order: repo → user
            repo_config_path = Path("config.yaml")
            user_config_path = Path.home() / ".erebos" / "config.yaml"

            # Start with defaults
            _settings = Config()

            # Merge repo config if it exists
            if repo_config_path.exists():
                _settings = _merge_configs(_settings, Config.from_yaml(repo_config_path))

            # Merge user config if it exists (highest priority)
            if user_config_path.exists():
                _settings = _merge_configs(_settings, Config.from_yaml(user_config_path))
        else:
            # Explicit config file provided - use it directly without merging
            if config_file.exists():
                _settings = Config.from_yaml(config_file)
            else:
                _settings = Config()

    return _settings


def reset_settings() -> None:
    """Reset the global settings instance."""
    global _settings
    _settings = None


# Alias for backwards compatibility
Settings = Config
