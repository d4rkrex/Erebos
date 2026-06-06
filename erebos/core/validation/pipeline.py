"""Validation pipeline: orchestrates Stages A-D for finding validation.

Usage:
    pipeline = ValidationPipeline()
    results = pipeline.validate_findings(findings)
    # results contains validated findings with exploitation_status updated
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from erebos.core.finding import Finding
from erebos.core.validation.stages import (
    SourceContext,
    StageA_PatternValidity,
    StageB_Reachability,
    StageC_Exploitability,
    StageD_Practicality,
    StageResult,
    StageVerdict,
    ValidationStage,
)

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a single finding through the pipeline."""

    finding: Finding
    stage_results: List[StageResult] = field(default_factory=list)
    final_verdict: StageVerdict = StageVerdict.UNCERTAIN
    confidence: float = 0.0
    short_circuited_at: Optional[str] = None
    exploitation_status: str = "pending"

    @property
    def is_valid(self) -> bool:
        """Whether the finding passed validation."""
        return self.final_verdict == StageVerdict.PASS

    @property
    def is_false_positive(self) -> bool:
        """Whether the finding was determined to be a false positive."""
        return self.final_verdict == StageVerdict.FAIL

    @property
    def needs_manual_review(self) -> bool:
        """Whether the finding needs manual review (uncertain)."""
        return self.final_verdict == StageVerdict.UNCERTAIN


@dataclass
class PipelineStats:
    """Aggregate statistics from a validation run."""

    total_findings: int = 0
    passed: int = 0
    failed: int = 0
    uncertain: int = 0
    short_circuited: Dict[str, int] = field(default_factory=dict)

    @property
    def false_positive_rate(self) -> float:
        """Percentage of findings filtered as FP."""
        if self.total_findings == 0:
            return 0.0
        return self.failed / self.total_findings

    @property
    def pass_rate(self) -> float:
        """Percentage of findings that passed validation."""
        if self.total_findings == 0:
            return 0.0
        return self.passed / self.total_findings


class ValidationPipeline:
    """Orchestrates multi-stage finding validation.

    Runs findings through Stages A → B → C → D sequentially.
    Short-circuits on confident FAIL at any stage.
    """

    def __init__(
        self,
        confidence_threshold: float = 0.7,
        skip_stages: Optional[List[str]] = None,
        enable_llm: bool = False,
        enable_consensus: bool = False,
        project_path: Optional[str] = None,
    ):
        """Initialize pipeline.

        Args:
            confidence_threshold: Minimum confidence to short-circuit on FAIL.
            skip_stages: Stage names to skip (e.g., ["D"] to skip practicality).
            enable_llm: Enable LLM-enhanced Stage B reachability analysis.
            enable_consensus: Enable multi-LLM consensus voting (requires multiple
                LLM providers configured). Default False — not everyone has multiple LLMs.
            project_path: Project root for project-specific learning. Default: CWD.
        """
        self._confidence_threshold = confidence_threshold
        self._skip_stages = set(skip_stages or [])
        self._enable_llm = enable_llm
        self._enable_consensus = enable_consensus
        self._stages: List[ValidationStage] = self._build_stages()
        self._stats = PipelineStats()
        self._llm_analyzer = None
        self._sage = None
        self._project_learning = None
        self._consensus_voter = None

        # Initialize SAGE memory (cross-scan knowledge)
        try:
            from erebos.core.sage import SageMemory, SageQuery

            self._sage = SageQuery(SageMemory())
        except Exception as e:
            logger.debug(f"SAGE memory unavailable: {e}")

        # Initialize project-specific learning
        try:
            from pathlib import Path
            from erebos.core.learning import ProjectLearning

            path = Path(project_path) if project_path else None
            self._project_learning = ProjectLearning(project_path=path)
        except Exception as e:
            logger.debug(f"Project learning unavailable: {e}")

    def _build_stages(self) -> List[ValidationStage]:
        """Build the ordered list of validation stages."""
        all_stages: List[ValidationStage] = [
            StageA_PatternValidity(),
            StageB_Reachability(),
            StageC_Exploitability(),
            StageD_Practicality(),
        ]
        return [s for s in all_stages if s.name not in self._skip_stages]

    def validate_finding(
        self,
        finding: Finding,
        source_context: Optional[SourceContext] = None,
    ) -> ValidationResult:
        """Validate a single finding through all stages.

        Short-circuits on confident FAIL. Accumulates stage results.
        Pre-checks: SAGE known FP patterns + project-specific suppressions.
        """
        result = ValidationResult(finding=finding)

        # Pre-check 1: SAGE known FP (cross-scan memory)
        if self._sage:
            try:
                is_fp, fp_confidence = self._sage.is_known_fp(
                    finding.title, finding.tool, finding.cwe
                )
                if is_fp and fp_confidence >= self._confidence_threshold:
                    result.final_verdict = StageVerdict.FAIL
                    result.confidence = fp_confidence
                    result.short_circuited_at = "SAGE"
                    result.exploitation_status = "false_positive"
                    result.stage_results.append(
                        StageResult(
                            stage="SAGE",
                            verdict=StageVerdict.FAIL,
                            confidence=fp_confidence,
                            reasoning="Known false positive from SAGE memory",
                        )
                    )
                    self._stats.failed += 1
                    self._stats.short_circuited["SAGE"] = (
                        self._stats.short_circuited.get("SAGE", 0) + 1
                    )
                    return result
            except Exception as e:
                logger.debug(f"SAGE check failed: {e}")

        # Pre-check 2: Project-specific learning (suppress repeated FPs)
        if self._project_learning:
            try:
                suppress, pattern = self._project_learning.should_suppress(
                    finding.title, finding.cwe, source_context.file_path if source_context else None
                )
                if suppress:
                    result.final_verdict = StageVerdict.FAIL
                    result.confidence = pattern.confidence if pattern else 0.8
                    result.short_circuited_at = "PROJECT"
                    result.exploitation_status = "false_positive"
                    result.stage_results.append(
                        StageResult(
                            stage="PROJECT",
                            verdict=StageVerdict.FAIL,
                            confidence=result.confidence,
                            reasoning=f"Suppressed by project learning: {pattern.description}"
                            if pattern
                            else "Suppressed by project learning",
                        )
                    )
                    self._stats.failed += 1
                    self._stats.short_circuited["PROJECT"] = (
                        self._stats.short_circuited.get("PROJECT", 0) + 1
                    )
                    return result
            except Exception as e:
                logger.debug(f"Project learning check failed: {e}")

        for stage in self._stages:
            try:
                stage_result = stage.evaluate(finding, source_context)
            except Exception as e:
                logger.warning(f"Stage {stage.name} error for finding {finding.id}: {e}")
                stage_result = StageResult(
                    stage=stage.name,
                    verdict=StageVerdict.UNCERTAIN,
                    confidence=0.0,
                    reasoning=f"Stage error: {e}",
                )

            result.stage_results.append(stage_result)

            # LLM enhancement: when Stage B is uncertain and we have source context
            if (
                stage.name == "B"
                and stage_result.verdict == StageVerdict.UNCERTAIN
                and self._enable_llm
                and source_context
                and source_context.code_snippet
            ):
                llm_result = self._try_llm_reachability(finding, source_context)
                if llm_result:
                    result.stage_results.append(llm_result)
                    stage_result = llm_result  # Use LLM result for short-circuit check

            # Short-circuit on confident FAIL
            if (
                stage_result.verdict == StageVerdict.FAIL
                and stage_result.confidence >= self._confidence_threshold
            ):
                result.final_verdict = StageVerdict.FAIL
                result.confidence = stage_result.confidence
                result.short_circuited_at = stage.name
                result.exploitation_status = "false_positive"
                logger.debug(
                    f"Finding {finding.id} rejected at Stage {stage.name}: "
                    f"{stage_result.reasoning}"
                )
                break
        else:
            # All stages completed — determine final verdict from aggregate
            result.final_verdict, result.confidence = self._aggregate_verdicts(result.stage_results)
            if result.final_verdict == StageVerdict.PASS:
                result.exploitation_status = "potential"
            else:
                result.exploitation_status = "pending"

        # Post-validation: record decision to SAGE + project learning for future scans
        self._record_learning(finding, result, source_context)

        return result

    def validate_findings(
        self,
        findings: List[Finding],
        source_contexts: Optional[Dict[str, SourceContext]] = None,
    ) -> Tuple[List[ValidationResult], PipelineStats]:
        """Validate a batch of findings.

        Args:
            findings: List of findings to validate.
            source_contexts: Optional mapping of finding.id -> SourceContext.

        Returns:
            Tuple of (results, stats).
        """
        contexts = source_contexts or {}
        self._stats = PipelineStats(total_findings=len(findings))
        results: List[ValidationResult] = []

        for finding in findings:
            ctx = contexts.get(finding.id)
            result = self.validate_finding(finding, ctx)
            results.append(result)

            # Update stats
            if result.final_verdict == StageVerdict.PASS:
                self._stats.passed += 1
            elif result.final_verdict == StageVerdict.FAIL:
                self._stats.failed += 1
                if result.short_circuited_at:
                    stage_key = f"Stage {result.short_circuited_at}"
                    self._stats.short_circuited[stage_key] = (
                        self._stats.short_circuited.get(stage_key, 0) + 1
                    )
            else:
                self._stats.uncertain += 1

        logger.info(
            f"Validation complete: {self._stats.passed} passed, "
            f"{self._stats.failed} FP, {self._stats.uncertain} uncertain "
            f"(FP rate: {self._stats.false_positive_rate:.1%})"
        )

        return results, self._stats

    def _aggregate_verdicts(self, stages: List[StageResult]) -> Tuple[StageVerdict, float]:
        """Aggregate stage verdicts into a final decision.

        Strategy: Weighted average of confidences for PASS verdicts.
        If any stage is uncertain with low confidence, overall is uncertain.
        """
        if not stages:
            return StageVerdict.UNCERTAIN, 0.0

        pass_scores = []
        uncertain_count = 0

        for sr in stages:
            if sr.verdict == StageVerdict.PASS:
                pass_scores.append(sr.confidence)
            elif sr.verdict == StageVerdict.UNCERTAIN:
                uncertain_count += 1

        if not pass_scores:
            return StageVerdict.UNCERTAIN, 0.3

        avg_confidence = sum(pass_scores) / len(pass_scores)

        # If too many uncertain stages, degrade confidence
        if uncertain_count > len(stages) / 2:
            return StageVerdict.UNCERTAIN, avg_confidence * 0.6

        if avg_confidence >= 0.6:
            return StageVerdict.PASS, avg_confidence
        else:
            return StageVerdict.UNCERTAIN, avg_confidence

    @property
    def stats(self) -> PipelineStats:
        """Get current pipeline statistics."""
        return self._stats

    def _try_llm_reachability(
        self, finding: Finding, source_context: SourceContext
    ) -> Optional[StageResult]:
        """Attempt LLM-enhanced reachability analysis.

        Only called when deterministic Stage B is uncertain and LLM is enabled.
        """
        if self._llm_analyzer is None:
            try:
                from erebos.core.validation.llm_reachability import LLMReachabilityAnalyzer

                self._llm_analyzer = LLMReachabilityAnalyzer()
            except Exception:
                return None

        try:
            return self._llm_analyzer.analyze_reachability(finding, source_context)
        except Exception as e:
            logger.debug(f"LLM reachability failed: {e}")
            return None

    def _record_learning(
        self,
        finding: Finding,
        result: "ValidationResult",
        source_context: Optional[SourceContext],
    ) -> None:
        """Record validation decision to SAGE and project learning for future improvement."""
        decision = (
            "false_positive"
            if result.final_verdict == StageVerdict.FAIL
            else "confirmed"
            if result.final_verdict == StageVerdict.PASS
            else "uncertain"
        )

        # Record to SAGE memory
        if self._sage and hasattr(self._sage, "_sage"):
            try:
                self._sage._sage.record_decision(
                    finding_title=finding.title,
                    tool=finding.tool,
                    cwe=finding.cwe,
                    decision=decision,
                    project_stack="",
                    target=finding.target or "",
                )
            except Exception as e:
                logger.debug(f"SAGE record failed: {e}")

        # Record to project learning
        if self._project_learning and decision != "uncertain":
            try:
                file_path = source_context.file_path if source_context else None
                self._project_learning.learn_from_validation(
                    title=finding.title,
                    tool=finding.tool,
                    cwe=finding.cwe,
                    file_path=file_path,
                    decision=decision,
                )
            except Exception as e:
                logger.debug(f"Project learning record failed: {e}")
