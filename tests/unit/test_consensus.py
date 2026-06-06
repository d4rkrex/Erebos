"""Tests for consensus voting."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from erebos.core.consensus import ConsensusVoter, VoteStrategy
from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.core.scorecard import DecisionEvent, ModelScorecard


@pytest.fixture
def sample_finding() -> Finding:
    """Create a representative finding for consensus tests."""
    return Finding(
        id="finding-1",
        tool="nuclei",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="Potential SQL injection in login endpoint.",
        evidence=FindingEvidence(output="SQL syntax error near user input"),
        cwe="CWE-89",
        phase_found=Phase.VULN_SCAN,
    )


@pytest.fixture
def another_finding() -> Finding:
    """Create a second finding for batch tests."""
    return Finding(
        id="finding-2",
        tool="dalfox",
        severity=Severity.MEDIUM,
        title="Reflected XSS",
        description="Potential reflected XSS in search parameter.",
        evidence=FindingEvidence(output="Reflected payload observed in response"),
        cwe="CWE-79",
        phase_found=Phase.VULN_SCAN,
    )


def test_majority_voting_reaches_consensus(sample_finding, monkeypatch):
    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.MAJORITY,
        min_voters=2,
    )
    responses = {
        "copilot": "VULNERABLE: Evidence indicates exploitable injection. confidence: 0.9",
        "claude": "VULNERABLE: The payload reaches a SQL sink. confidence: 0.8",
        "openrouter": "NOT_VULNERABLE: This looks like a benign error page. confidence: 0.4",
    }
    monkeypatch.setattr(
        voter,
        "_ask_provider",
        AsyncMock(side_effect=lambda provider, prompt: responses[provider]),
    )

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    assert result.consensus_reached is True
    assert result.final_verdict == "vulnerable"
    assert result.agreement_ratio == pytest.approx(2 / 3)
    assert len(result.votes) == 3


def test_supermajority_accepts_two_of_three(sample_finding, monkeypatch):
    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.SUPERMAJORITY,
        min_voters=3,
    )
    responses = {
        "copilot": "VULNERABLE: Sink is externally reachable.",
        "claude": "VULNERABLE: Query uses unsanitized user input.",
        "openrouter": "UNCERTAIN: Need more runtime context.",
    }
    monkeypatch.setattr(
        voter,
        "_ask_provider",
        AsyncMock(side_effect=lambda provider, prompt: responses[provider]),
    )

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    assert result.consensus_reached is True
    assert result.final_verdict == "vulnerable"
    assert result.agreement_ratio == pytest.approx(2 / 3)


def test_unanimous_requires_all_votes_to_match(sample_finding, monkeypatch):
    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.UNANIMOUS,
        min_voters=3,
    )
    responses = {
        "copilot": "VULNERABLE: Sink is reachable.",
        "claude": "VULNERABLE: Exploitation looks feasible.",
        "openrouter": "NOT_VULNERABLE: Compensating controls block execution.",
    }
    monkeypatch.setattr(
        voter,
        "_ask_provider",
        AsyncMock(side_effect=lambda provider, prompt: responses[provider]),
    )

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    assert result.consensus_reached is False
    assert result.final_verdict == "uncertain"
    assert result.agreement_ratio == pytest.approx(2 / 3)


def test_weighted_voting_prefers_high_reliability_model(sample_finding, monkeypatch, tmp_path):
    scorecard = ModelScorecard(storage_path=tmp_path / "scorecard.json")
    for _ in range(9):
        scorecard.record(
            DecisionEvent(model="copilot", cwe_class="CWE-89", decision="tp", correct=True)
        )
        scorecard.record(
            DecisionEvent(model="claude", cwe_class="CWE-89", decision="tp", correct=False)
        )
        scorecard.record(
            DecisionEvent(model="openrouter", cwe_class="CWE-89", decision="tp", correct=False)
        )
    scorecard.record(
        DecisionEvent(model="copilot", cwe_class="CWE-89", decision="tp", correct=False)
    )
    scorecard.record(DecisionEvent(model="claude", cwe_class="CWE-89", decision="tp", correct=True))
    scorecard.record(
        DecisionEvent(model="openrouter", cwe_class="CWE-89", decision="tp", correct=True)
    )

    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.WEIGHTED,
        min_voters=3,
        scorecard=scorecard,
    )
    responses = {
        "copilot": "NOT_VULNERABLE: Historical pattern suggests a false positive.",
        "claude": "VULNERABLE: I believe the issue is exploitable.",
        "openrouter": "VULNERABLE: Payload appears exploitable.",
    }
    monkeypatch.setattr(
        voter,
        "_ask_provider",
        AsyncMock(side_effect=lambda provider, prompt: responses[provider]),
    )

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    assert result.consensus_reached is True
    assert result.final_verdict == "not_vulnerable"
    assert result.agreement_ratio == pytest.approx(0.9 / 1.1)


def test_consensus_not_reached_when_min_voters_missing(sample_finding, monkeypatch):
    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.MAJORITY,
        min_voters=3,
    )

    async def ask_provider(provider, prompt):
        if provider == "copilot":
            return "VULNERABLE: Strong evidence."
        raise asyncio.TimeoutError

    mocked = AsyncMock(side_effect=ask_provider)
    monkeypatch.setattr(voter, "_ask_provider", mocked)

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    assert result.consensus_reached is False
    assert result.final_verdict == "uncertain"
    assert len(result.votes) == 1
    assert mocked.await_count == 3


@pytest.mark.parametrize(
    ("response", "expected_verdict", "expected_confidence"),
    [
        ("VULNERABLE: Clear exploit path.", "vulnerable", 0.85),
        ("NOT VULNERABLE: Protected by auth. confidence: 0.2", "not_vulnerable", 0.2),
        ("VERDICT: UNCERTAIN - Need more context", "uncertain", 0.5),
        ("Likely not_vulnerable due to sanitization. confidence: 75%", "not_vulnerable", 0.75),
    ],
)
def test_parse_vote_handles_multiple_response_formats(
    response,
    expected_verdict,
    expected_confidence,
):
    voter = ConsensusVoter()

    vote = voter._parse_vote("copilot", response)

    assert vote.verdict == expected_verdict
    assert vote.confidence == pytest.approx(expected_confidence)


def test_batch_voting_returns_results_for_each_finding(
    sample_finding,
    another_finding,
    monkeypatch,
):
    voter = ConsensusVoter(
        providers=["copilot", "claude"],
        strategy=VoteStrategy.MAJORITY,
        min_voters=2,
    )

    async def ask_provider(provider, prompt):
        if "SQL Injection" in prompt:
            return "VULNERABLE: Confirmed."
        return "NOT_VULNERABLE: Reflected input is encoded."

    monkeypatch.setattr(voter, "_ask_provider", AsyncMock(side_effect=ask_provider))

    results = asyncio.run(
        voter.vote_batch(
            [sample_finding, another_finding],
            contexts={sample_finding.id: "Login flow is internet-exposed."},
        )
    )

    assert len(results) == 2
    assert results[0].finding_id == sample_finding.id
    assert results[0].final_verdict == "vulnerable"
    assert results[1].finding_id == another_finding.id
    assert results[1].final_verdict == "not_vulnerable"


def test_timeout_handling_skips_non_responding_voter(sample_finding, monkeypatch):
    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.MAJORITY,
        min_voters=2,
    )

    async def ask_provider(provider, prompt):
        if provider == "claude":
            raise asyncio.TimeoutError
        return "VULNERABLE: Confirmed exploit path."

    monkeypatch.setattr(voter, "_ask_provider", AsyncMock(side_effect=ask_provider))

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    assert result.consensus_reached is True
    assert result.final_verdict == "vulnerable"
    assert len(result.votes) == 2


def test_agreement_ratio_and_confidence_are_calculated(sample_finding, monkeypatch):
    voter = ConsensusVoter(
        providers=["copilot", "claude", "openrouter"],
        strategy=VoteStrategy.MAJORITY,
        min_voters=3,
    )
    responses = {
        "copilot": "VULNERABLE: Confirmed injection. confidence: 0.9",
        "claude": "VULNERABLE: Exploitable path found. confidence: 0.6",
        "openrouter": "NOT_VULNERABLE: WAF blocks the payload. confidence: 0.3",
    }
    monkeypatch.setattr(
        voter,
        "_ask_provider",
        AsyncMock(side_effect=lambda provider, prompt: responses[provider]),
    )

    result = asyncio.run(voter.vote_on_finding(sample_finding))

    expected_agreement = 2 / 3
    expected_avg_confidence = (0.9 + 0.6 + 0.3) / 3
    assert result.agreement_ratio == pytest.approx(expected_agreement)
    assert result.confidence == pytest.approx(expected_agreement * expected_avg_confidence)
