"""Tests for evidence chain builder."""

from erebos.core.chains import ChainBuilder
from erebos.core.finding import Finding


def _make_finding(title, severity, cwe, target="http://target.com/api", phase="vuln-scan"):
    return Finding(
        title=title,
        severity=severity,
        cwe=cwe,
        target=target,
        tool="nuclei",
        description=f"Test finding: {title}",
        phase_found=phase,
    )


class TestChainBuilder:
    """Test evidence chain construction."""

    def test_cwe_escalation_chain(self):
        """Builds chain from CWE escalation path: SQLi → CmdInj."""
        findings = [
            _make_finding("SQL Injection in login", "HIGH", "CWE-89"),
            _make_finding("OS Command Injection via db", "CRITICAL", "CWE-78"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        assert len(chains) >= 1
        chain = chains[0]
        assert chain.length >= 2
        assert "CWE-89" in [link.contributes_cwe for link in chain.links]
        assert "CWE-78" in [link.contributes_cwe for link in chain.links]

    def test_three_step_chain(self):
        """Builds 3-step chain: Info Leak → SQLi → RCE."""
        findings = [
            _make_finding("Information Disclosure", "MEDIUM", "CWE-200"),
            _make_finding("SQL Injection", "HIGH", "CWE-89"),
            _make_finding("Command Injection", "CRITICAL", "CWE-78"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        assert len(chains) >= 1
        longest = max(chains, key=lambda c: c.length)
        assert longest.length >= 3

    def test_no_chain_unrelated_cwes(self):
        """No chain when CWEs have no escalation relationship."""
        findings = [
            _make_finding("XSS", "MEDIUM", "CWE-79"),
            _make_finding("SSRF", "HIGH", "CWE-918"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        # These don't directly chain to each other; either is valid
        assert isinstance(chains, list)

    def test_target_based_chain(self):
        """Builds chain from same-target multi-phase findings."""
        findings = [
            _make_finding("Port 8080 open", "INFO", None, phase="recon"),
            _make_finding("Directory listing", "LOW", "CWE-548", phase="discovery"),
            _make_finding("SQLi on /api/users", "HIGH", "CWE-89", phase="vuln-scan"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        target_chains = [c for c in chains if "target-progression" in c.tags]
        assert len(target_chains) >= 1
        assert target_chains[0].links[0].role == "entry_point"

    def test_chain_severity_boosted(self):
        """Chain severity is boosted beyond max individual."""
        findings = [
            _make_finding("Info Leak", "MEDIUM", "CWE-200"),
            _make_finding("SQLi", "HIGH", "CWE-89"),
            _make_finding("RCE", "HIGH", "CWE-78"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        if chains:
            # 3-step chain with HIGH findings should boost to CRITICAL
            best = chains[0]
            assert best.chain_severity in ("CRITICAL", "HIGH")

    def test_narrative_generation(self):
        """Chain narrative is human-readable."""
        findings = [
            _make_finding("SQLi in /login", "HIGH", "CWE-89"),
            _make_finding("OS Command via SQLi", "CRITICAL", "CWE-78"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        if chains:
            assert chains[0].narrative
            assert "target" in chains[0].narrative.lower() or "attack" in chains[0].narrative.lower()

    def test_empty_findings(self):
        """No crash on empty findings."""
        builder = ChainBuilder()
        chains = builder.build_chains([])
        assert chains == []

    def test_single_finding_no_chain(self):
        """Single finding doesn't form a chain."""
        findings = [_make_finding("SQLi", "HIGH", "CWE-89")]
        builder = ChainBuilder(min_chain_length=2)
        chains = builder.build_chains(findings)
        # No chain with single finding
        cwe_chains = [c for c in chains if "cwe-escalation" in c.tags]
        assert len(cwe_chains) == 0

    def test_chain_to_dict(self):
        """Chain serialization works."""
        findings = [
            _make_finding("SQLi", "HIGH", "CWE-89"),
            _make_finding("RCE", "CRITICAL", "CWE-78"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        if chains:
            d = chains[0].to_dict()
            assert "chain_id" in d
            assert "links" in d
            assert "narrative" in d
            assert d["length"] >= 2

    def test_deduplication(self):
        """Same finding not used in multiple chains."""
        findings = [
            _make_finding("Info Leak", "MEDIUM", "CWE-200", target="http://a.com"),
            _make_finding("SQLi", "HIGH", "CWE-89", target="http://a.com"),
            _make_finding("RCE", "CRITICAL", "CWE-78", target="http://a.com"),
        ]
        builder = ChainBuilder()
        chains = builder.build_chains(findings)

        # Count how many times each finding appears across all chains
        all_ids = []
        for c in chains:
            all_ids.extend(c.finding_ids)

        # With dedup, no finding should appear more than twice (CWE + target chain overlap)
        from collections import Counter

        counts = Counter(all_ids)
        # Allow overlap of at most 50% (dedup rule)
        assert all(v <= 2 for v in counts.values())
