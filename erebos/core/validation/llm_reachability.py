"""Stage B LLM enhancement — uses LLM for deep reachability analysis.

When the deterministic Stage B (Reachability) returns UNCERTAIN,
this module can optionally invoke an LLM to analyze the code path
and determine if the vulnerability is reachable from an entry point.

Only invoked when:
1. Deterministic Stage B returns UNCERTAIN
2. Source context is available with code snippet
3. LLM cascade is configured

This is the most expensive validation step — use scorecard trust to
short-circuit when the LLM has proven reliable for a CWE class.
"""

from __future__ import annotations

import logging
from typing import Optional

from erebos.core.finding import Finding
from erebos.core.validation.stages import (
    SourceContext,
    StageResult,
    StageVerdict,
)

logger = logging.getLogger(__name__)

# System prompt for reachability analysis
_REACHABILITY_PROMPT = """You are a security code auditor. Analyze the following code for reachability.

Given:
- A vulnerability finding ({cwe}) at {file_path}:{line_number}
- The code snippet where it was found
- Available entry points and data flow information

Determine: Can an external attacker reach this code path through a public entry point?

Consider:
1. Is there a route/handler that calls this code?
2. Is user-controlled input passed to the vulnerable function?
3. Are there authentication/authorization checks blocking access?
4. Are there input validation or sanitization steps?

Respond with ONLY one of:
- REACHABLE: Attacker can reach this code from a public endpoint
- UNREACHABLE: Code is not reachable from external input
- UNCERTAIN: Cannot determine with available information

Then a brief (1-2 sentence) explanation.
"""


class LLMReachabilityAnalyzer:
    """Uses LLM to assess code reachability when deterministic analysis fails."""

    def __init__(self, llm_cascade=None):
        """Initialize with optional LLM cascade.

        Args:
            llm_cascade: LLMCascade instance from exploits module.
                         If None, will attempt to create from settings.
        """
        self._cascade = llm_cascade

    def _get_cascade(self):
        """Lazy-load LLM cascade from settings."""
        if self._cascade is not None:
            return self._cascade

        try:
            from erebos.exploits.llm_cascade import LLMCascade

            self._cascade = LLMCascade()
            return self._cascade
        except Exception as e:
            logger.debug(f"LLM cascade not available: {e}")
            return None

    def analyze_reachability(
        self,
        finding: Finding,
        source_context: SourceContext,
    ) -> Optional[StageResult]:
        """Analyze reachability using LLM.

        Returns StageResult or None if LLM is not available.
        """
        cascade = self._get_cascade()
        if not cascade:
            return None

        if not source_context.code_snippet:
            return None

        # Check scorecard — if LLM is trusted for this CWE, use cached decision
        cwe = finding.cwe or "generic"
        try:
            from erebos.core.scorecard import ModelScorecard

            sc = ModelScorecard()
            if sc.should_short_circuit("llm-reachability", cwe):
                logger.debug(f"Scorecard: LLM trusted for {cwe}, short-circuiting")
                # Trust the deterministic analysis
                return None
        except Exception:
            pass

        # Build prompt
        prompt = _REACHABILITY_PROMPT.format(
            cwe=cwe,
            file_path=source_context.file_path or "unknown",
            line_number=source_context.line_number or 0,
        )

        context_text = f"""
Code snippet:
```
{source_context.code_snippet[:500]}
```

File: {source_context.file_path}
Function: {source_context.function_name or 'unknown'}
Entry points: {', '.join(source_context.entry_points) or 'none detected'}
Data flow: {' → '.join(source_context.data_flow[:3]) or 'not traced'}
Sanitizers: {', '.join(source_context.sanitizers) or 'none detected'}
Language: {source_context.language or 'unknown'}
"""

        try:
            # Use cascade to get LLM response (sync wrapper)
            import asyncio

            response = asyncio.run(cascade.generate_text(prompt + "\n\n" + context_text))

            if not response:
                return None

            return self._parse_response(response)

        except Exception as e:
            logger.debug(f"LLM reachability analysis failed: {e}")
            return None

    def _parse_response(self, response: str) -> StageResult:
        """Parse LLM response into a StageResult."""
        response_upper = response.strip().upper()

        if response_upper.startswith("REACHABLE"):
            verdict = StageVerdict.PASS
            confidence = 0.75
        elif response_upper.startswith("UNREACHABLE"):
            verdict = StageVerdict.FAIL
            confidence = 0.7
        else:
            verdict = StageVerdict.UNCERTAIN
            confidence = 0.4

        # Extract reasoning (after the verdict word)
        reasoning = response.strip()
        for prefix in ("REACHABLE:", "UNREACHABLE:", "UNCERTAIN:"):
            if reasoning.upper().startswith(prefix):
                reasoning = reasoning[len(prefix) :].strip()
                break

        return StageResult(
            stage="B-LLM",
            verdict=verdict,
            confidence=confidence,
            reasoning=f"LLM analysis: {reasoning[:200]}",
            evidence={"source": "llm", "raw_response": response[:300]},
        )
