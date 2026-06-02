"""Docker Secrets loader for Erebos.

# VT-Spec ID-002 MEDIUM: Read secrets from /run/secrets/* files, never env vars.
# Fallback to env vars ONLY for local development with warning.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# VT-Spec ID-002: Default secrets mount path
SECRETS_DIR = Path("/run/secrets")


def load_secret(name: str, env_fallback: Optional[str] = None) -> Optional[str]:
    """Load a secret from Docker Secrets file mount.

    # VT-Spec ID-002 MEDIUM: Read secrets from /run/secrets/* files.
    # Falls back to environment variable ONLY with warning.

    Priority:
    1. /run/secrets/{name} (Docker Secrets)
    2. Environment variable {ENV_FALLBACK} (dev only, with warning)
    3. *_FILE env var pointing to a file path

    Args:
        name: Secret name (filename in /run/secrets/).
        env_fallback: Environment variable name for fallback.

    Returns:
        Secret value or None.
    """
    # VT-Spec ID-002: Try Docker Secrets first
    secret_path = SECRETS_DIR / name
    if secret_path.exists():
        try:
            value = secret_path.read_text().strip()
            if value:
                logger.debug(f"Secret '{name}' loaded from Docker Secrets")
                return value
        except (OSError, PermissionError) as e:
            logger.error(f"VT-Spec ID-002: Failed to read secret '{name}': {e}")

    # VT-Spec ID-002: Try *_FILE env var (Docker Secrets pattern)
    if env_fallback:
        file_env = f"{env_fallback}_FILE"
        file_path_str = os.environ.get(file_env)
        if file_path_str:
            file_path = Path(file_path_str)
            if file_path.exists():
                try:
                    value = file_path.read_text().strip()
                    if value:
                        logger.debug(f"Secret '{name}' loaded from {file_env}")
                        return value
                except (OSError, PermissionError) as e:
                    logger.error(f"VT-Spec ID-002: Failed to read {file_env}: {e}")

    # VT-Spec ID-002: Env var fallback (development only — log warning)
    if env_fallback:
        value = os.environ.get(env_fallback)
        if value:
            logger.warning(
                f"VT-Spec ID-002: Secret '{name}' loaded from env var {env_fallback}. "
                f"Use Docker Secrets (/run/secrets/{name}) in production."
            )
            return value

    return None


def load_mcp_token() -> Optional[str]:
    """Load MCP authentication token.

    # VT-Spec ID-002: Prefer Docker Secrets over env vars.
    """
    return load_secret("mcp_token", env_fallback="EREBOS_MCP_TOKEN")


def load_hmac_secret() -> Optional[str]:
    """Load HMAC signing secret.

    # VT-Spec ID-002: Prefer Docker Secrets over env vars.
    """
    return load_secret("hmac_secret", env_fallback="EREBOS_HMAC_SECRET")
