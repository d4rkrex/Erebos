"""Unit tests for Erebos Phase 3: Skills & Knowledge.

Tests cover:
- Skill Loader: safe YAML, alias rejection, schema validation, hot-reload integrity
- Skill Catalog: trigger matching, regex timeout, phase filtering
- Skills Library: all YAML files load, valid schema, MITRE IDs
- Knowledge Graph: CRUD, isolation, path queries, max limits, credential hashing
- Observation Store: store/query, dedup, isolation
- Artifact Store: store/retrieve, integrity verify, tamper detection
- MITRE: coverage tracking, suggestions
- Brain integration: skill-driven hypotheses, template planning, safe variable substitution
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from erebos.core.models import (
    EngagementPhase,
    Observation,
    ObservationType,
)
from erebos.knowledge.artifacts import ArtifactIntegrityError, ArtifactRef, ArtifactStore
from erebos.knowledge.graph import (
    GraphLimitExceeded,
    KnowledgeGraph,
    _validate_engagement_id,
)
from erebos.knowledge.observations import ObservationStore
from erebos.skills.catalog import (
    ActionTemplate,
    Skill,
    SkillCatalog,
    SkillSummary,
    TriggerPattern,
    SAFE_TEMPLATE_VARIABLES,
)
from erebos.skills.loader import SkillLoadError, SkillLoader
from erebos.skills.mitre import MITRE_DATABASE, MitreMapper, TechniqueInfo


# ─── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def skill_library_path():
    return Path(__file__).parent.parent.parent / "erebos" / "skills" / "library"


@pytest.fixture
def sample_skill() -> Skill:
    return Skill(
        name="test_scan",
        description="Test port scan",
        version="1.0",
        triggers=[
            TriggerPattern(observation_type="port_open", field_match={"port": 80})
        ],
        tools_required=["nmap"],
        technique_id="T1046",
        phase_applicable=["recon"],
        actions=[
            ActionTemplate(
                tool="nmap",
                args_template=["-sV", "-p", "80", "{target}"],
                description="Scan port 80",
            )
        ],
    )


@pytest.fixture
def sample_observation() -> Observation:
    return Observation(
        engagement_id="test-engagement-001",
        target_id="target-1",
        observation_type=ObservationType.PORT_OPEN,
        data={"port": 80, "service": "http", "protocol": "tcp"},
        phase=EngagementPhase.RECON,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SKILL LOADER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestSkillLoader:
    """Tests for SkillLoader — T-SKG-01, T-SKG-06."""

    def test_load_valid_yaml(self, tmp_dir: Path):
        """Load a valid skill YAML file."""
        skill_data = {
            "name": "test_skill",
            "description": "A test skill",
            "version": "1.0",
            "technique_id": "T1046",
            "phase_applicable": ["recon"],
            "triggers": [{"observation_type": "port_open", "field_match": {}}],
            "tools_required": ["nmap"],
            "actions": [
                {"tool": "nmap", "args_template": ["-sV", "{target}"], "description": "scan"}
            ],
        }
        yaml_file = tmp_dir / "test.yaml"
        yaml_file.write_text(yaml.dump(skill_data))

        loader = SkillLoader()
        skill = loader.load_file(yaml_file)

        assert skill.name == "test_skill"
        assert skill.technique_id == "T1046"
        assert len(skill.actions) == 1
        assert skill.actions[0].args_template == ["-sV", "{target}"]

    def test_reject_yaml_anchors(self, tmp_dir: Path):
        """VT-Spec T-SKG-01: Reject YAML with anchors/aliases."""
        content = "name: test\nbase: &base_val\n  tool: nmap\nactions:\n  - <<: *base_val\n    args_template: ['-sV']\n"
        yaml_file = tmp_dir / "anchored.yaml"
        yaml_file.write_text(content)

        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="T-SKG-01"):
            loader.load_file(yaml_file)

    def test_safe_load_only(self, tmp_dir: Path):
        """VT-Spec T-SKG-06: Only yaml.safe_load, no custom constructors."""
        # Python object tag should fail with safe_load
        content = "name: !!python/object:os.system 'echo pwned'\nactions: []\n"
        yaml_file = tmp_dir / "unsafe.yaml"
        yaml_file.write_text(content)

        loader = SkillLoader()
        with pytest.raises(SkillLoadError):
            loader.load_file(yaml_file)

    def test_reject_oversized_file(self, tmp_dir: Path):
        """VT-Spec T-SKG-01: Reject files exceeding size limit."""
        yaml_file = tmp_dir / "large.yaml"
        yaml_file.write_text("x" * (256 * 1024 + 1))

        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="exceeds max size"):
            loader.load_file(yaml_file)

    def test_schema_validation_missing_name(self, tmp_dir: Path):
        """Schema validation rejects files without 'name' field."""
        yaml_file = tmp_dir / "no_name.yaml"
        yaml_file.write_text(yaml.dump({"actions": [{"tool": "nmap", "args_template": ["-sV"]}]}))

        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="Schema validation"):
            loader.load_file(yaml_file)

    def test_schema_validation_args_not_list(self, tmp_dir: Path):
        """VT-Spec T-SKG-05: Reject args_template that is a string."""
        yaml_file = tmp_dir / "bad_args.yaml"
        yaml_file.write_text(
            yaml.dump({"name": "bad", "actions": [{"tool": "nmap", "args_template": "-sV {target}"}]})
        )

        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="Schema validation"):
            loader.load_file(yaml_file)

    def test_load_directory(self, skill_library_path: Path):
        """Load all skills from the library directory."""
        loader = SkillLoader()
        skills = loader.load_directory(skill_library_path)
        assert len(skills) >= 8  # We have 8 skill files

    def test_hot_reload_integrity(self, tmp_dir: Path):
        """VT-Spec T-SKG-01: Hot-reload verifies SHA-256 integrity."""
        skill_data = {
            "name": "hot_skill",
            "actions": [{"tool": "nmap", "args_template": ["-sV"]}],
            "phase_applicable": ["recon"],
        }
        yaml_file = tmp_dir / "hot.yaml"
        yaml_file.write_text(yaml.dump(skill_data))

        loader = SkillLoader()
        skill = loader.load_file(yaml_file)
        assert skill.name == "hot_skill"

        # No change → returns None
        result = loader.hot_reload(yaml_file)
        assert result is None

        # Modify file → returns new skill
        skill_data["description"] = "Updated"
        yaml_file.write_text(yaml.dump(skill_data))
        result = loader.hot_reload(yaml_file)
        assert result is not None
        assert result.description == "Updated"

    def test_hot_reload_rejects_corrupt(self, tmp_dir: Path):
        """VT-Spec T-SKG-01: Hot-reload rejects invalid files."""
        skill_data = {
            "name": "valid",
            "actions": [{"tool": "nmap", "args_template": ["-sV"]}],
        }
        yaml_file = tmp_dir / "will_corrupt.yaml"
        yaml_file.write_text(yaml.dump(skill_data))

        loader = SkillLoader()
        loader.load_file(yaml_file)

        # Corrupt the file (add anchors)
        yaml_file.write_text("name: &bad_anchor\nactions: *bad_anchor\n")
        result = loader.hot_reload(yaml_file)
        assert result is None

    def test_nonexistent_file(self):
        """Load non-existent file raises error."""
        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="not found"):
            loader.load_file(Path("/nonexistent/skill.yaml"))

    def test_nonexistent_directory(self):
        """Load non-existent directory raises error."""
        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="not found"):
            loader.load_directory(Path("/nonexistent/dir"))


# ═══════════════════════════════════════════════════════════════════════════════
# SKILL CATALOG TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestSkillCatalog:
    """Tests for SkillCatalog — T-SKG-02, T-SKG-05."""

    def test_register_and_get(self, sample_skill: Skill):
        """Register and retrieve a skill."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)

        result = catalog.get_skill("test_scan")
        assert result is not None
        assert result.name == "test_scan"

    def test_unregister(self, sample_skill: Skill):
        """Unregister removes a skill."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)
        catalog.unregister("test_scan")
        assert catalog.get_skill("test_scan") is None

    def test_list_skills_all(self, sample_skill: Skill):
        """List all registered skills."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)
        skills = catalog.list_skills()
        assert len(skills) == 1
        assert skills[0].name == "test_scan"

    def test_list_skills_by_phase(self, sample_skill: Skill):
        """List skills filtered by phase."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)

        # Match
        assert len(catalog.list_skills(phase="recon")) == 1
        # No match
        assert len(catalog.list_skills(phase="exploitation")) == 0

    def test_trigger_matching(self, sample_skill: Skill, sample_observation: Observation):
        """Match observations against skill triggers."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)

        matched = catalog.match_triggers([sample_observation], "recon")
        assert len(matched) == 1
        assert matched[0].name == "test_scan"

    def test_trigger_no_match_wrong_phase(self, sample_skill: Skill, sample_observation: Observation):
        """Skills not matching phase are filtered out."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)

        matched = catalog.match_triggers([sample_observation], "exploitation")
        assert len(matched) == 0

    def test_trigger_no_match_wrong_type(self, sample_skill: Skill):
        """Observation type mismatch doesn't trigger skill."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)

        obs = Observation(
            engagement_id="test",
            observation_type=ObservationType.CREDENTIAL_FOUND,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        matched = catalog.match_triggers([obs], "recon")
        assert len(matched) == 0

    def test_trigger_field_match(self):
        """Field matching works correctly."""
        skill = Skill(
            name="ssh_test",
            phase_applicable=["recon"],
            triggers=[TriggerPattern(observation_type="port_open", field_match={"port": 22})],
            actions=[ActionTemplate(tool="nmap", args_template=["-p", "22", "{target}"])],
        )
        catalog = SkillCatalog()
        catalog.register(skill)

        # Port 22 → match
        obs_22 = Observation(
            engagement_id="test",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 22},
            phase=EngagementPhase.RECON,
        )
        assert len(catalog.match_triggers([obs_22], "recon")) == 1

        # Port 80 → no match
        obs_80 = Observation(
            engagement_id="test",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        assert len(catalog.match_triggers([obs_80], "recon")) == 0

    def test_reject_catastrophic_backtracking_regex(self):
        """VT-Spec T-SKG-02: Reject regex with nested quantifiers."""
        with pytest.raises(ValueError, match="T-SKG-02"):
            TriggerPattern(
                observation_type="port_open",
                field_match={},
                regex_pattern="(a+)+$",
            )

    def test_regex_match_safe(self):
        """Regex matching works for safe patterns."""
        skill = Skill(
            name="version_detect",
            phase_applicable=["recon"],
            triggers=[
                TriggerPattern(
                    observation_type="service_detected",
                    field_match={},
                    regex_pattern=r"Apache/\d+",
                )
            ],
            actions=[ActionTemplate(tool="nmap", args_template=["-sV", "{target}"])],
        )
        catalog = SkillCatalog()
        catalog.register(skill)

        obs = Observation(
            engagement_id="test",
            observation_type=ObservationType.SERVICE_DETECTED,
            data={"version": "Apache/2.4.51"},
            phase=EngagementPhase.RECON,
        )
        matched = catalog.match_triggers([obs], "recon")
        assert len(matched) == 1

    def test_action_template_must_be_list(self):
        """VT-Spec T-SKG-05: args_template must be a list."""
        with pytest.raises(Exception):
            ActionTemplate(tool="nmap", args_template="-sV {target}")  # type: ignore

    def test_safe_template_variables(self):
        """VT-Spec T-SKG-05: Only safe variables in allowlist."""
        assert "target" in SAFE_TEMPLATE_VARIABLES
        assert "port" in SAFE_TEMPLATE_VARIABLES
        assert "service" in SAFE_TEMPLATE_VARIABLES
        assert "url" in SAFE_TEMPLATE_VARIABLES
        # Dangerous ones NOT in allowlist
        assert "cmd" not in SAFE_TEMPLATE_VARIABLES
        assert "shell" not in SAFE_TEMPLATE_VARIABLES


# ═══════════════════════════════════════════════════════════════════════════════
# SKILLS LIBRARY TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestSkillsLibrary:
    """Tests for the YAML skill library files."""

    def test_all_yaml_files_load(self, skill_library_path: Path):
        """All skill YAML files in library load successfully."""
        loader = SkillLoader()
        skills = loader.load_directory(skill_library_path)
        assert len(skills) >= 8

    def test_all_skills_have_valid_schema(self, skill_library_path: Path):
        """All skills pass schema validation."""
        loader = SkillLoader()
        for yaml_file in skill_library_path.rglob("*.yaml"):
            skill = loader.load_file(yaml_file)
            assert skill.name, f"Skill missing name: {yaml_file}"
            assert skill.actions, f"Skill missing actions: {yaml_file}"

    def test_all_skills_have_mitre_ids(self, skill_library_path: Path):
        """All skills have MITRE technique IDs."""
        loader = SkillLoader()
        skills = loader.load_directory(skill_library_path)
        for skill in skills:
            assert skill.technique_id, f"Skill {skill.name} missing technique_id"
            assert skill.technique_id.startswith("T"), (
                f"Skill {skill.name} has invalid technique_id: {skill.technique_id}"
            )

    def test_all_skills_args_are_lists(self, skill_library_path: Path):
        """VT-Spec T-SKG-05: All action args_template are lists."""
        loader = SkillLoader()
        skills = loader.load_directory(skill_library_path)
        for skill in skills:
            for action in skill.actions:
                assert isinstance(action.args_template, list), (
                    f"Skill {skill.name} action has non-list args_template"
                )

    def test_no_anchors_in_library(self, skill_library_path: Path):
        """VT-Spec T-SKG-01: No anchors/aliases in library YAML files."""
        import re

        anchor_pattern = re.compile(r"[&*]\w+")
        for yaml_file in skill_library_path.rglob("*.yaml"):
            content = yaml_file.read_text()
            assert not anchor_pattern.search(content), (
                f"Anchors/aliases found in {yaml_file}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE GRAPH TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestKnowledgeGraph:
    """Tests for KnowledgeGraph — T-SKG-03, T-SKG-07, T-SKG-08."""

    def test_create_with_valid_id(self):
        """Create graph with valid engagement ID."""
        graph = KnowledgeGraph("engagement-001")
        assert graph.engagement_id == "engagement-001"
        assert graph.node_count == 0

    def test_reject_path_traversal_id(self):
        """VT-Spec T-SKG-03: Reject engagement_id with path traversal."""
        with pytest.raises(ValueError, match="T-SKG-03"):
            KnowledgeGraph("../etc/passwd")

        with pytest.raises(ValueError, match="T-SKG-03"):
            KnowledgeGraph("eng/../../etc")

        with pytest.raises(ValueError, match="T-SKG-03"):
            KnowledgeGraph("")

    def test_reject_invalid_id_format(self):
        """VT-Spec T-SKG-03: Reject engagement_id with invalid characters."""
        with pytest.raises(ValueError, match="T-SKG-03"):
            KnowledgeGraph("eng id with spaces")

        with pytest.raises(ValueError, match="T-SKG-03"):
            KnowledgeGraph("eng;DROP TABLE")

    def test_add_host(self):
        """Add host node."""
        graph = KnowledgeGraph("test-eng")
        graph.add_host("192.168.1.1", hostname="target.local")
        hosts = graph.get_hosts()
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.1"
        assert hosts[0]["hostname"] == "target.local"

    def test_add_service(self):
        """Add service connected to host."""
        graph = KnowledgeGraph("test-eng")
        graph.add_host("192.168.1.1")
        graph.add_service("192.168.1.1", 80, "http", "Apache/2.4")

        services = graph.get_services("192.168.1.1")
        assert len(services) == 1
        assert services[0]["port"] == 80
        assert services[0]["version"] == "Apache/2.4"

    def test_add_vulnerability(self):
        """Add vulnerability to a service."""
        graph = KnowledgeGraph("test-eng")
        graph.add_host("192.168.1.1")
        graph.add_service("192.168.1.1", 80, "http")
        graph.add_vulnerability("192.168.1.1", 80, "CVE-2021-1234", "high")

        vulns = graph.get_vulnerabilities("192.168.1.1")
        assert len(vulns) == 1
        assert vulns[0]["vuln_id"] == "CVE-2021-1234"
        assert vulns[0]["severity"] == "high"

    def test_credential_stored_as_hash(self):
        """VT-Spec T-SKG-07: Credentials stored as hash only."""
        graph = KnowledgeGraph("test-eng")
        graph.add_host("192.168.1.1")

        # Hash the credential before storing
        password = "SuperSecret123"
        cred_hash = hashlib.sha256(password.encode()).hexdigest()
        graph.add_credential("192.168.1.1", "admin", cred_hash)

        # Verify graph stores hash, not plaintext
        for node, data in graph._graph.nodes(data=True):
            if data.get("type") == "credential":
                assert data["credential_hash"] == cred_hash
                assert password not in str(data)

    def test_attack_paths(self):
        """Find attack paths between nodes."""
        graph = KnowledgeGraph("test-eng")
        graph.add_host("192.168.1.1")
        graph.add_service("192.168.1.1", 80, "http")
        graph.add_vulnerability("192.168.1.1", 80, "CVE-2021-1234", "high")

        paths = graph.get_attack_paths("192.168.1.1", "vuln:CVE-2021-1234@192.168.1.1:80")
        assert len(paths) >= 1

    def test_attack_paths_nonexistent(self):
        """No paths for nonexistent nodes."""
        graph = KnowledgeGraph("test-eng")
        paths = graph.get_attack_paths("1.1.1.1", "2.2.2.2")
        assert paths == []

    def test_max_node_limit(self):
        """VT-Spec T-SKG-08: Reject beyond max nodes."""
        graph = KnowledgeGraph("test-eng", max_nodes=5, max_edges=100)

        for i in range(5):
            graph.add_host(f"10.0.0.{i}")

        with pytest.raises(GraphLimitExceeded, match="T-SKG-08"):
            graph.add_host("10.0.0.99")

    def test_max_edge_limit(self):
        """VT-Spec T-SKG-08: Reject beyond max edges."""
        graph = KnowledgeGraph("test-eng", max_nodes=100, max_edges=3)

        graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")  # 1 edge
        graph.add_service("10.0.0.1", 443, "https")  # 2 edges
        graph.add_service("10.0.0.1", 22, "ssh")  # 3 edges

        with pytest.raises(GraphLimitExceeded, match="T-SKG-08"):
            graph.add_service("10.0.0.1", 3306, "mysql")  # Would be 4th edge

    def test_engagement_isolation(self):
        """VT-Spec T-SKG-03: Separate instances per engagement."""
        graph1 = KnowledgeGraph("eng-1")
        graph2 = KnowledgeGraph("eng-2")

        graph1.add_host("10.0.0.1")
        assert graph1.node_count == 1
        assert graph2.node_count == 0

    def test_enrich_from_observations(self):
        """Enrich graph from observation list."""
        graph = KnowledgeGraph("test-eng")
        obs = Observation(
            engagement_id="test-eng",
            target_id="10.0.0.1",
            observation_type=ObservationType.PORT_OPEN,
            data={"host": "10.0.0.1", "port": 80, "service": "http"},
            phase=EngagementPhase.RECON,
        )
        graph.enrich_from_observations([obs])
        assert graph.node_count >= 2  # host + service


# ═══════════════════════════════════════════════════════════════════════════════
# OBSERVATION STORE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestObservationStore:
    """Tests for ObservationStore — T-SKG-03."""

    def test_store_and_query(self, tmp_dir: Path):
        """Store and retrieve observations."""
        store = ObservationStore(tmp_dir)
        obs = Observation(
            engagement_id="eng-1",
            target_id="target-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        result = store.store(obs, "eng-1")
        assert result is True

        queried = store.query("eng-1")
        assert len(queried) == 1
        assert queried[0].observation_type == ObservationType.PORT_OPEN

    def test_deduplication(self, tmp_dir: Path):
        """Duplicate observations are rejected."""
        store = ObservationStore(tmp_dir)
        obs = Observation(
            engagement_id="eng-1",
            target_id="target-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        assert store.store(obs, "eng-1") is True
        assert store.store(obs, "eng-1") is False  # Duplicate

    def test_engagement_isolation(self, tmp_dir: Path):
        """VT-Spec T-SKG-03: Observations isolated per engagement."""
        store = ObservationStore(tmp_dir)
        obs = Observation(
            engagement_id="eng-1",
            target_id="target-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        store.store(obs, "eng-1")

        # Different engagement sees nothing
        assert store.query("eng-2") == []
        assert store.count("eng-2") == 0

    def test_query_by_type(self, tmp_dir: Path):
        """Query filtered by observation type."""
        store = ObservationStore(tmp_dir)

        obs1 = Observation(
            engagement_id="eng-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        obs2 = Observation(
            engagement_id="eng-1",
            observation_type=ObservationType.SERVICE_DETECTED,
            data={"service": "http"},
            phase=EngagementPhase.RECON,
        )
        store.store(obs1, "eng-1")
        store.store(obs2, "eng-1")

        results = store.query("eng-1", obs_type="port_open")
        assert len(results) == 1

    def test_count(self, tmp_dir: Path):
        """Count observations for engagement."""
        store = ObservationStore(tmp_dir)
        obs = Observation(
            engagement_id="eng-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        store.store(obs, "eng-1")
        assert store.count("eng-1") == 1

    def test_reject_invalid_engagement_id(self, tmp_dir: Path):
        """VT-Spec T-SKG-03: Reject invalid engagement IDs."""
        store = ObservationStore(tmp_dir)
        obs = Observation(
            engagement_id="eng-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        with pytest.raises(ValueError, match="T-SKG-03"):
            store.store(obs, "../etc/passwd")

    def test_deduplicate_list(self, tmp_dir: Path):
        """Deduplicate a list of observations."""
        store = ObservationStore(tmp_dir)
        obs = Observation(
            engagement_id="eng-1",
            observation_type=ObservationType.PORT_OPEN,
            data={"port": 80},
            phase=EngagementPhase.RECON,
        )
        unique = store.deduplicate([obs, obs, obs])
        assert len(unique) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT STORE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestArtifactStore:
    """Tests for ArtifactStore — T-SKG-04."""

    def test_store_and_retrieve(self, tmp_dir: Path):
        """Store and retrieve artifact data."""
        store = ArtifactStore(tmp_dir)
        data = b"nmap scan output here"

        ref = store.store(data, "eng-1", "recon", "nmap", "scan.txt")
        assert ref.sha256_hash == hashlib.sha256(data).hexdigest()
        assert ref.size == len(data)

        retrieved = store.retrieve(ref)
        assert retrieved == data

    def test_integrity_verification(self, tmp_dir: Path):
        """VT-Spec T-SKG-04: Verify hash on retrieve."""
        store = ArtifactStore(tmp_dir)
        data = b"original data"

        ref = store.store(data, "eng-1", "recon", "nmap", "output.txt")
        assert store.verify_integrity(ref) is True

    def test_tamper_detection(self, tmp_dir: Path):
        """VT-Spec T-SKG-04: Detect tampered artifacts."""
        store = ArtifactStore(tmp_dir)
        data = b"original data"

        ref = store.store(data, "eng-1", "recon", "nmap", "output.txt")

        # Tamper with the file
        Path(ref.path).write_bytes(b"tampered data")

        with pytest.raises(ArtifactIntegrityError, match="T-SKG-04"):
            store.retrieve(ref)

        assert store.verify_integrity(ref) is False

    def test_list_artifacts(self, tmp_dir: Path):
        """List all artifacts for an engagement."""
        store = ArtifactStore(tmp_dir)
        store.store(b"data1", "eng-1", "recon", "nmap", "scan1.txt")
        store.store(b"data2", "eng-1", "recon", "nikto", "scan2.txt")

        artifacts = store.list_artifacts("eng-1")
        assert len(artifacts) == 2

    def test_reject_invalid_engagement_id(self, tmp_dir: Path):
        """VT-Spec T-SKG-03: Reject path traversal in engagement_id."""
        store = ArtifactStore(tmp_dir)
        with pytest.raises(ValueError, match="T-SKG-03"):
            store.store(b"data", "../etc", "recon", "nmap", "scan.txt")

    def test_atomic_write(self, tmp_dir: Path):
        """VT-Spec T-SKG-04: Atomic write leaves no temp files on success."""
        store = ArtifactStore(tmp_dir)
        store.store(b"data", "eng-1", "recon", "nmap", "scan.txt")

        # Check no .tmp_ files remain
        artifact_dir = tmp_dir / "artifacts" / "eng-1" / "recon"
        tmp_files = list(artifact_dir.glob(".tmp_*"))
        assert len(tmp_files) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE MAPPER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestMitreMapper:
    """Tests for MitreMapper."""

    def test_map_skill(self, sample_skill: Skill):
        """Map a skill to its MITRE technique."""
        mapper = MitreMapper()
        info = mapper.map_skill(sample_skill)
        assert info is not None
        assert info.technique_id == "T1046"
        assert info.tactic == "discovery"

    def test_map_skill_no_technique(self):
        """Skill without technique_id returns None."""
        mapper = MitreMapper()
        skill = Skill(name="no_mitre", actions=[])
        assert mapper.map_skill(skill) is None

    def test_coverage_tracking(self):
        """Track technique coverage for engagement."""
        mapper = MitreMapper()
        mapper.record_technique_used("eng-1", "T1046")
        mapper.record_technique_used("eng-1", "T1595")

        coverage = mapper.get_coverage("eng-1")
        assert "discovery" in coverage
        assert "T1046" in coverage["discovery"]
        assert "reconnaissance" in coverage
        assert "T1595" in coverage["reconnaissance"]

    def test_suggest_untried(self):
        """Suggest techniques not yet attempted."""
        mapper = MitreMapper()
        mapper.record_technique_used("eng-1", "T1046")

        suggestions = mapper.suggest_untried("eng-1")
        technique_ids = [s.technique_id for s in suggestions]
        assert "T1046" not in technique_ids
        assert len(suggestions) == len(MITRE_DATABASE) - 1

    def test_coverage_report(self):
        """Generate coverage report."""
        mapper = MitreMapper()
        mapper.record_technique_used("eng-1", "T1046")

        report = mapper.generate_coverage_report("eng-1")
        assert report["engagement_id"] == "eng-1"
        assert report["techniques_tried"] == 1
        assert report["techniques_total"] == len(MITRE_DATABASE)

    def test_empty_coverage(self):
        """Empty coverage for unknown engagement."""
        mapper = MitreMapper()
        coverage = mapper.get_coverage("unknown")
        assert coverage == {}


# ═══════════════════════════════════════════════════════════════════════════════
# BRAIN INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestBrainIntegration:
    """Tests for skill-driven hypotheses and template planning."""

    def test_skill_template_variable_substitution(self):
        """VT-Spec T-SKG-05: Safe variable substitution via shlex.quote."""
        import shlex

        template = ["-sV", "-p", "{port}", "{target}"]
        variables = {"target": "192.168.1.1", "port": "80"}

        # Safe substitution
        result = []
        for arg in template:
            substituted = arg
            for var_name in SAFE_TEMPLATE_VARIABLES:
                placeholder = "{" + var_name + "}"
                if placeholder in substituted:
                    value = variables.get(var_name, "")
                    # VT-Spec T-SKG-05: shlex.quote for safety
                    substituted = substituted.replace(placeholder, shlex.quote(value))
            result.append(substituted)

        assert result == ["-sV", "-p", "80", "192.168.1.1"]

    def test_template_rejects_dangerous_variables(self):
        """VT-Spec T-SKG-05: Only allowlisted variables are substituted."""
        import shlex

        template = ["-cmd", "{dangerous_var}", "{target}"]
        variables = {"target": "10.0.0.1", "dangerous_var": "; rm -rf /"}

        result = []
        for arg in template:
            substituted = arg
            for var_name in SAFE_TEMPLATE_VARIABLES:
                placeholder = "{" + var_name + "}"
                if placeholder in substituted:
                    value = variables.get(var_name, "")
                    substituted = substituted.replace(placeholder, shlex.quote(value))
            result.append(substituted)

        # dangerous_var not in allowlist → NOT substituted
        assert "{dangerous_var}" in result[1]
        assert "rm -rf" not in result[1]

    def test_template_shlex_quote_prevents_injection(self):
        """VT-Spec T-SKG-05: shlex.quote prevents command injection."""
        import shlex

        template = ["-sV", "{target}"]
        # Attacker tries to inject via target field
        variables = {"target": "10.0.0.1; cat /etc/passwd"}

        result = []
        for arg in template:
            substituted = arg
            for var_name in SAFE_TEMPLATE_VARIABLES:
                placeholder = "{" + var_name + "}"
                if placeholder in substituted:
                    value = variables.get(var_name, "")
                    substituted = substituted.replace(placeholder, shlex.quote(value))
            result.append(substituted)

        # The injected command is quoted safely
        assert ";" not in result[1] or result[1].startswith("'")
        # shlex.quote wraps in single quotes
        assert result[1] == "'10.0.0.1; cat /etc/passwd'"

    def test_skill_driven_hypothesis_generation(self, sample_skill: Skill, sample_observation: Observation):
        """Skills matched by catalog can drive hypothesis generation."""
        catalog = SkillCatalog()
        catalog.register(sample_skill)

        matched = catalog.match_triggers([sample_observation], "recon")
        assert len(matched) == 1

        # Each matched skill becomes a potential hypothesis
        skill = matched[0]
        assert skill.technique_id == "T1046"
        assert len(skill.actions) >= 1

    def test_engagement_id_validation(self):
        """VT-Spec T-SKG-03: validate_engagement_id function."""
        # Valid
        _validate_engagement_id("eng-001")
        _validate_engagement_id("my_engagement_123")

        # Invalid
        with pytest.raises(ValueError):
            _validate_engagement_id("")
        with pytest.raises(ValueError):
            _validate_engagement_id("../../../etc/passwd")
        with pytest.raises(ValueError):
            _validate_engagement_id("eng/bad")
        with pytest.raises(ValueError):
            _validate_engagement_id("a" * 200)
