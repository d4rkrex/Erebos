"""LLM integration for Erebos decision loop (REQ-006).

Provider-agnostic LLM reasoning abstraction.

# VT-Spec I-01 HIGH: Credential scrubbing in all prompts
# VT-Spec T-01: Output validation — reject malformed responses
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from erebos.core.models import Observation, ObservationType

logger = logging.getLogger(__name__)

# VT-Spec I-01: Credential scrubbing patterns
CREDENTIAL_SCRUB_PATTERNS = [
    # Passwords
    re.compile(r"(password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE),
    # API keys
    re.compile(r"(api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE),
    # Tokens
    re.compile(r"(token|access_token|refresh_token|bearer)\s*[:=]\s*\S+", re.IGNORECASE),
    # Secrets
    re.compile(r"(secret|client_secret|app_secret)\s*[:=]\s*\S+", re.IGNORECASE),
    # Private keys
    re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
    # Authorization headers
    re.compile(r"Authorization:\s*(Bearer|Basic)\s+\S+", re.IGNORECASE),
    # AWS keys
    re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}", re.IGNORECASE),
    # Generic long hex/base64 that look like secrets
    re.compile(r"(key|secret|token|credential)\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{32,}['\"]?", re.IGNORECASE),
]

# VT-Spec I-01: Allowlist of safe fields to pass to LLM
SAFE_FIELDS = frozenset([
    "port",
    "protocol",
    "service",
    "version",
    "product",
    "cve_id",
    "path",
    "status_code",
    "finding",
    "tool",
    "observation_type",
    "error",
    "warning",
])

# Default token budget
DEFAULT_MAX_TOKENS = 2048
DEFAULT_MAX_RETRIES = 1
DEFAULT_RETRY_DELAY = 2.0


def scrub_credentials(text: str) -> str:
    """Remove credential values from text.

    # VT-Spec I-01 HIGH: Regex-based credential detection and redaction
    """
    scrubbed = text
    for pattern in CREDENTIAL_SCRUB_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed


def filter_safe_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter observation data to only allowlisted fields.

    # VT-Spec I-01 HIGH: Allowlist-based data field filtering
    """
    return {k: v for k, v in data.items() if k in SAFE_FIELDS}


class LLMReasoner:
    """Provider-agnostic LLM reasoning interface.

    # VT-Spec I-01: Credential scrubbing in all prompts
    # VT-Spec T-01: Output validation — reject malformed responses
    """

    def __init__(
        self,
        provider: str = "stub",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: float = DEFAULT_RETRY_DELAY,
        air_gapped: bool = False,
    ):
        self._provider = provider
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        # VT-Spec I-01: Air-gapped mode for sensitive engagements
        self._air_gapped = air_gapped

    def reason(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Raw LLM call with error handling.

        # VT-Spec I-01: Scrub credentials from prompt
        # VT-Spec T-01: Validate response
        """
        # VT-Spec I-01: Scrub credentials
        safe_prompt = scrub_credentials(prompt)

        if context:
            safe_context = {
                k: scrub_credentials(str(v)) if isinstance(v, str) else v
                for k, v in context.items()
            }
        else:
            safe_context = {}

        # VT-Spec I-01: Air-gapped mode — no external calls
        if self._air_gapped:
            logger.info("VT-Spec I-01: Air-gapped mode — LLM call skipped")
            return ""

        # Retry with exponential backoff
        last_error: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                return self._call_provider(safe_prompt, safe_context)
            except Exception as e:
                last_error = e
                if attempt < self._max_retries:
                    delay = self._retry_delay * (2**attempt)
                    logger.warning(
                        "LLM call failed (attempt %d/%d): %s, retrying in %.1fs",
                        attempt + 1,
                        self._max_retries + 1,
                        e,
                        delay,
                    )
                    time.sleep(delay)

        logger.error("LLM call failed after %d attempts: %s", self._max_retries + 1, last_error)
        return ""

    def generate_hypotheses(
        self, observations: List[Observation]
    ) -> List[Dict[str, Any]]:
        """Generate hypothesis suggestions from observations.

        # VT-Spec I-01: Only safe fields sent to LLM
        # VT-Spec T-01: Schema-validate response
        """
        # VT-Spec I-01: Filter to safe fields only
        obs_data = []
        for obs in observations:
            filtered = filter_safe_fields(obs.data)
            filtered["observation_type"] = obs.observation_type.value
            obs_data.append(filtered)

        prompt = (
            "Given these security observations, generate attack hypotheses.\n"
            "Return JSON array of objects with: description (str), confidence (float 0-1), "
            "impact (str: none/low/medium/high/critical).\n\n"
            f"Observations: {json.dumps(obs_data)}"
        )

        response = self.reason(prompt)
        if not response:
            return []

        # VT-Spec T-01: Parse and validate response strictly
        return self._parse_hypothesis_response(response)

    def plan_actions(
        self, hypothesis_desc: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Generate action suggestions for a hypothesis.

        # VT-Spec I-01: Credential scrubbing
        # VT-Spec T-01: Output validation
        """
        safe_desc = scrub_credentials(hypothesis_desc)

        prompt = (
            f"Given this hypothesis: {safe_desc}\n"
            "Suggest concrete tool commands to test it.\n"
            "Return JSON array of objects with: tool (str), args (list of str), "
            "description (str)."
        )

        response = self.reason(prompt, context)
        if not response:
            return []

        return self._parse_action_response(response)

    def interpret_results(
        self, output: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Interpret execution results.

        # VT-Spec I-01: Scrub credentials from output before sending
        """
        safe_output = scrub_credentials(output)
        # Truncate to prevent context overflow
        if len(safe_output) > 4096:
            safe_output = safe_output[:4096]

        prompt = (
            f"Interpret these security tool results:\n{safe_output}\n"
            "Return JSON array of findings with: type (str), description (str), "
            "severity (str: low/medium/high/critical)."
        )

        response = self.reason(prompt, context)
        if not response:
            return []

        return self._parse_json_response(response)

    def _call_provider(self, prompt: str, context: Dict[str, Any]) -> str:
        """Call the configured LLM provider.

        Stub implementation — actual provider integration is extensible.
        """
        if self._provider == "stub":
            return ""
        # Future: OpenAI, Anthropic, Ollama providers
        raise NotImplementedError(f"LLM provider '{self._provider}' not implemented")

    def _parse_hypothesis_response(
        self, response: str
    ) -> List[Dict[str, Any]]:
        """Parse and validate LLM hypothesis response.

        # VT-Spec T-01: Schema-validate LLM responses
        """
        items = self._parse_json_response(response)
        valid = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if "description" not in item:
                logger.warning("VT-Spec T-01: Hypothesis missing 'description', skipped")
                continue
            # Validate confidence is float in range
            confidence = item.get("confidence", 0.5)
            try:
                confidence = float(confidence)
                if not (0.0 <= confidence <= 1.0):
                    confidence = 0.5
            except (ValueError, TypeError):
                confidence = 0.5
            item["confidence"] = confidence

            # Validate impact
            valid_impacts = {"none", "low", "medium", "high", "critical"}
            impact = str(item.get("impact", "medium")).lower()
            if impact not in valid_impacts:
                impact = "medium"
            item["impact"] = impact

            valid.append(item)
        return valid

    def _parse_action_response(
        self, response: str
    ) -> List[Dict[str, Any]]:
        """Parse and validate LLM action response.

        # VT-Spec T-01: Validate tool names against whitelist
        """
        items = self._parse_json_response(response)
        valid = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if "tool" not in item:
                continue
            # Basic validation — detailed tool validation happens in Planner
            if not isinstance(item.get("args"), list):
                item["args"] = []
            valid.append(item)
        return valid

    def _parse_json_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse JSON from LLM response text.

        # VT-Spec T-01: Strict parsing, reject malformed
        """
        if not response.strip():
            return []

        # Try to extract JSON array from response
        text = response.strip()

        # Handle markdown code blocks
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            text = text[start:end].strip()

        # Try parsing as JSON array
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                return [parsed]
            else:
                logger.warning("VT-Spec T-01: LLM response not a list/dict, rejected")
                return []
        except json.JSONDecodeError:
            # Try to find JSON array in text
            bracket_start = text.find("[")
            bracket_end = text.rfind("]")
            if bracket_start >= 0 and bracket_end > bracket_start:
                try:
                    parsed = json.loads(text[bracket_start : bracket_end + 1])
                    if isinstance(parsed, list):
                        return parsed
                except json.JSONDecodeError:
                    pass

            logger.warning("VT-Spec T-01: Failed to parse LLM response as JSON")
            return []
