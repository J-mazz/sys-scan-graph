"""
Tests for enricher.py finding enrichment and augmentation module.
"""

from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock

from sys_scan_agent.enricher import (
    _compute_finding_tags, _merge_finding_tags, _initialize_finding_risk,
    _process_finding_enrichment, _derive_host_metadata, _apply_host_role_adjustments,
    _perform_initial_risk_recomputation, augment
)
from sys_scan_agent.models import AgentState, Report, ScannerResult, Finding


class TestComputeFindingTags:
    """Test _compute_finding_tags function."""

    def test_compute_tags_network_port(self):
        """Test tag computation for network port finding."""
        metadata = {"port": 8080, "state": "LISTEN", "severity": "medium"}
        tags = _compute_finding_tags(metadata, "network")

        expected_tags = {"scanner:network", "severity:medium", "network_port", "listening"}
        assert tags == expected_tags

    def test_compute_tags_suid(self):
        """Test tag computation for SUID finding."""
        metadata = {"suid": "true", "severity": "high"}
        tags = _compute_finding_tags(metadata, "suid")

        expected_tags = {"scanner:suid", "severity:high", "suid"}
        assert tags == expected_tags

    def test_compute_tags_kernel_param(self):
        """Test tag computation for kernel parameter finding."""
        metadata = {"sysctl_key": "net.ipv4.ip_forward", "severity": "low"}
        tags = _compute_finding_tags(metadata, "kernel_params")

        expected_tags = {"scanner:kernel_params", "severity:low", "kernel_param"}
        assert tags == expected_tags

    def test_compute_tags_module(self):
        """Test tag computation for kernel module finding."""
        metadata = {"module": "suspicious_module", "severity": "medium"}
        tags = _compute_finding_tags(metadata, "modules")

        expected_tags = {"scanner:modules", "severity:medium", "module"}
        assert tags == expected_tags

    def test_compute_tags_minimal(self):
        """Test tag computation with minimal metadata."""
        metadata = {"severity": "info"}
        tags = _compute_finding_tags(metadata, "process")

        expected_tags = {"scanner:process", "severity:info"}
        assert tags == expected_tags

    def test_compute_tags_unknown_severity(self):
        """Test tag computation with unknown severity."""
        metadata = {}
        tags = _compute_finding_tags(metadata, "unknown")

        expected_tags = {"scanner:unknown", "severity:unknown"}
        assert tags == expected_tags


class TestMergeFindingTags:
    """Test _merge_finding_tags function."""

    def test_merge_tags_empty_existing(self):
        """Test merging tags when finding has no existing tags."""
        finding = MagicMock()
        finding.tags = None

        base_tags = {"tag1", "tag2", "tag3"}
        _merge_finding_tags(finding, base_tags)

        assert finding.tags == ["tag1", "tag2", "tag3"]  # Should be sorted

    def test_merge_tags_with_existing(self):
        """Test merging tags when finding has existing tags."""
        finding = MagicMock()
        finding.tags = ["existing1", "tag2"]

        base_tags = {"tag1", "tag2", "tag3"}
        _merge_finding_tags(finding, base_tags)

        # Should preserve existing and add new ones
        assert set(finding.tags) == {"existing1", "tag1", "tag2", "tag3"}

    def test_merge_tags_no_duplicates(self):
        """Test that duplicate tags are not added."""
        finding = MagicMock()
        finding.tags = ["tag1", "tag2"]

        base_tags = {"tag1", "tag3"}
        _merge_finding_tags(finding, base_tags)

        assert set(finding.tags) == {"tag1", "tag2", "tag3"}


class TestInitializeFindingRisk:
    """Test _initialize_finding_risk function."""

    def test_initialize_risk_no_existing_subscores(self):
        """Test risk initialization when no subscores exist."""
        finding = MagicMock()
        finding.risk_subscores = None
        finding.tags = ["listening", "network_port"]
        finding.category = "network_socket"
        finding.severity = "high"

        severity_base = {"high": 4}
        policy_multiplier = {"network_socket": 1.3}

        _initialize_finding_risk(finding, severity_base, policy_multiplier, "network")

        assert finding.risk_subscores == {
            "impact": 5.2,  # 4 * 1.3
            "exposure": 1.5,  # listening (1.0) + network_port (0.5)
            "anomaly": 0.0,
            "confidence": 1.0
        }

    def test_initialize_risk_existing_subscores(self):
        """Test that existing subscores are not overwritten."""
        finding = MagicMock()
        finding.risk_subscores = {"impact": 1.0, "exposure": 2.0, "anomaly": 3.0, "confidence": 4.0}
        finding.tags = []
        finding.category = "process"
        finding.severity = "low"

        severity_base = {"low": 2}
        policy_multiplier = {"process": 1.0}

        _initialize_finding_risk(finding, severity_base, policy_multiplier, "process")

        # Should not change existing subscores
        assert finding.risk_subscores == {"impact": 1.0, "exposure": 2.0, "anomaly": 3.0, "confidence": 4.0}

    def test_initialize_risk_suid_high_exposure(self):
        """Test high exposure calculation for SUID."""
        finding = MagicMock()
        finding.risk_subscores = None
        finding.tags = ["suid", "listening", "network_port", "routing", "nat"]
        finding.category = "privilege_escalation_surface"
        finding.severity = "critical"

        severity_base = {"critical": 5}
        policy_multiplier = {"privilege_escalation_surface": 1.5}

        _initialize_finding_risk(finding, severity_base, policy_multiplier, "suid")

        assert finding.risk_subscores["impact"] == 7.5  # 5 * 1.5
        assert finding.risk_subscores["exposure"] == 3.0  # Capped at 3.0

    def test_initialize_risk_unknown_category(self):
        """Test risk initialization with unknown category."""
        finding = MagicMock()
        finding.risk_subscores = None
        finding.tags = []
        finding.category = None
        finding.severity = "medium"

        severity_base = {"medium": 3}
        policy_multiplier = {"unknown": 1.0}

        _initialize_finding_risk(finding, severity_base, policy_multiplier, "unknown")

        assert finding.risk_subscores["impact"] == 3.0  # 3 * 1.0


class TestProcessFindingEnrichment:
    """Test _process_finding_enrichment function."""

    def test_process_enrichment_basic(self):
        """Test basic finding enrichment processing."""
        finding = MagicMock()
        finding.category = None
        finding.metadata = {"port": 80, "state": "LISTEN", "severity": "medium"}
        finding.tags = None
        finding.risk_subscores = None
        finding.severity = "medium"

        scanner_result = MagicMock()
        scanner_result.scanner = "network"
        scanner_result.findings = [finding]

        severity_base = {"medium": 3}
        policy_multiplier = {"network_socket": 1.3}

        _process_finding_enrichment(scanner_result, "network_socket", severity_base, policy_multiplier)

        assert finding.category == "network_socket"
        assert "network_port" in finding.tags
        assert "listening" in finding.tags
        assert finding.risk_subscores is not None

    def test_process_enrichment_existing_category(self):
        """Test enrichment when finding already has category."""
        finding = MagicMock()
        finding.category = "existing_category"
        finding.metadata = {}
        finding.tags = []
        finding.risk_subscores = None
        finding.severity = "low"

        scanner_result = MagicMock()
        scanner_result.scanner = "test"
        scanner_result.findings = [finding]

        _process_finding_enrichment(scanner_result, "inferred_category", {}, {})

        # Should keep existing category
        assert finding.category == "existing_category"


class TestDeriveHostMetadata:
    """Test _derive_host_metadata function."""

    def test_derive_host_metadata_basic(self):
        """Test basic host metadata derivation."""
        state = MagicMock()
        state.report.meta.host_id = None
        state.report.meta.scan_id = None
        state.raw_report = {
            "meta": {
                "hostname": "test-host",
                "kernel": "5.4.0-test"
            }
        }

        _derive_host_metadata(state)

        assert state.report.meta.host_id is not None
        assert len(state.report.meta.host_id) == 32  # SHA256 hex length
        assert state.report.meta.scan_id is not None
        assert len(state.report.meta.scan_id) == 32  # UUID hex length

    def test_derive_host_metadata_existing_host_id(self):
        """Test derivation when host_id already exists."""
        state = MagicMock()
        state.report.meta.host_id = "existing-host-id"
        state.report.meta.scan_id = None
        state.raw_report = {"meta": {"hostname": "test", "kernel": "test"}}

        _derive_host_metadata(state)

        assert state.report.meta.host_id == "existing-host-id"  # Should not change
        assert state.report.meta.scan_id is not None  # Should still generate scan_id

    def test_derive_host_metadata_no_report(self):
        """Test derivation with no report."""
        state = MagicMock()
        state.report = None

        # Should not crash
        _derive_host_metadata(state)

    def test_derive_host_metadata_minimal_meta(self):
        """Test derivation with minimal metadata."""
        state = MagicMock()
        state.report.meta.host_id = None
        state.report.meta.scan_id = None
        state.raw_report = {"meta": {}}  # Empty meta

        _derive_host_metadata(state)

        assert state.report.meta.host_id is not None
        assert state.report.meta.scan_id is not None


class TestApplyHostRoleAdjustments:
    """Test _apply_host_role_adjustments function."""

    def test_apply_adjustments_no_audit_module(self):
        """Test adjustments when audit module is not available."""
        state = MagicMock()
        state.report.results = []

        with patch.dict('sys.modules', {'sys_scan_agent.audit': None}):
            # Should not crash
            _apply_host_role_adjustments(state)


class TestPerformInitialRiskRecomputation:
    """Test _perform_initial_risk_recomputation function."""

    def test_perform_recomputation_missing_score(self):
        """Test recomputation for findings missing risk_score."""
        finding = MagicMock()
        finding.risk_subscores = {"impact": 2.0, "exposure": 1.0, "anomaly": 0.5, "confidence": 0.9}
        finding.risk_score = None

        scanner_result = MagicMock()
        scanner_result.findings = [finding]

        state = MagicMock()
        state.report.results = [scanner_result]

        with patch('sys_scan_agent.enricher._recompute_finding_risk') as mock_recompute:
            _perform_initial_risk_recomputation(state)

            mock_recompute.assert_called_once_with(finding)

    def test_perform_recomputation_existing_score(self):
        """Test no recomputation when risk_score exists."""
        finding = MagicMock()
        finding.risk_subscores = {"impact": 2.0, "exposure": 1.0, "anomaly": 0.5, "confidence": 0.9}
        finding.risk_score = 50

        scanner_result = MagicMock()
        scanner_result.findings = [finding]

        state = MagicMock()
        state.report.results = [scanner_result]

        with patch('sys_scan_agent.enricher._recompute_finding_risk') as mock_recompute:
            _perform_initial_risk_recomputation(state)

            mock_recompute.assert_not_called()

    def test_perform_recomputation_no_subscores(self):
        """Test no recomputation when no subscores."""
        finding = MagicMock()
        finding.risk_subscores = None
        finding.risk_score = None

        scanner_result = MagicMock()
        scanner_result.findings = [finding]

        state = MagicMock()
        state.report.results = [scanner_result]

        with patch('sys_scan_agent.enricher._recompute_finding_risk') as mock_recompute:
            _perform_initial_risk_recomputation(state)

            mock_recompute.assert_not_called()


class TestAugment:
    """Test augment function."""

    def test_augment_basic(self):
        """Test basic augmentation functionality."""
        # Create a mock state with report
        state = MagicMock()
        state.report.meta.host_id = None
        state.report.meta.scan_id = None
        state.raw_report = {"meta": {"hostname": "test-host", "kernel": "5.4.0"}}

        finding = MagicMock()
        finding.category = None
        finding.metadata = {"port": 80, "severity": "medium"}
        finding.tags = None
        finding.risk_subscores = None
        finding.severity = "medium"

        scanner_result = MagicMock()
        scanner_result.scanner = "network"
        scanner_result.findings = [finding]

        state.report.results = [scanner_result]

        result = augment(state)

        assert result == state
        assert state.report.meta.host_id is not None
        assert state.report.meta.scan_id is not None
        assert finding.category == "network_socket"

    def test_augment_no_report(self):
        """Test augmentation with no report."""
        state = MagicMock()
        state.report = None

        result = augment(state)
        assert result == state

    def test_augment_empty_results(self):
        """Test augmentation with empty results."""
        state = MagicMock()
        state.report.results = None

        result = augment(state)
        assert result == state