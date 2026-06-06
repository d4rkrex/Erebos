"""Finding validation pipeline inspired by RAPTOR's Stages A-D methodology.

Validates exploitability of findings through progressive stages:
- Stage A: Pattern Validity (is this a real vulnerability pattern?)
- Stage B: Reachability (can an attacker reach this code path?)
- Stage C: Exploitability (does a concrete attack path exist?)
- Stage D: Practicality (is exploitation realistic in context?)

Each stage can short-circuit: a confident "not vulnerable" at any stage
stops further (expensive) analysis.
"""

from erebos.core.validation.pipeline import ValidationPipeline, ValidationResult
from erebos.core.validation.stages import (
    StageA_PatternValidity,
    StageB_Reachability,
    StageC_Exploitability,
    StageD_Practicality,
    ValidationStage,
    StageVerdict,
)
from erebos.core.validation.llm_reachability import LLMReachabilityAnalyzer

__all__ = [
    "ValidationPipeline",
    "ValidationResult",
    "StageA_PatternValidity",
    "StageB_Reachability",
    "StageC_Exploitability",
    "StageD_Practicality",
    "ValidationStage",
    "StageVerdict",
    "LLMReachabilityAnalyzer",
]
