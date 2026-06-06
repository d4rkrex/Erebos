"""LLM Model Scorecard — per-model reliability tracking.

Tracks how well each LLM model performs at validating findings by CWE class.
Uses Wilson confidence interval to determine when a cheap model is reliable
enough to short-circuit expensive validation.

Inspired by RAPTOR's scorecard system.
"""

from erebos.core.scorecard.tracker import ModelScorecard, ScorecardEntry, DecisionEvent

__all__ = ["ModelScorecard", "ScorecardEntry", "DecisionEvent"]
