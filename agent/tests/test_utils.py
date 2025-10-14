"""
Tests for utils.py shared utilities.
"""

from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock

from sys_scan_agent.utils import (
    CAT_MAP, POLICY_MULTIPLIER, SEVERITY_BASE,
    _recompute_finding_risk, _log_error
)
from sys_scan_agent.models import AgentWarning


class TestConstants:
    """Test constant definitions."""

    def test_cat_map_completeness(self):
        """Test that CAT_MAP contains expected mappings."""
        expected_mappings = {
            "process": "process",
            "network": "network_socket",
            "kernel_params": "kernel_param",
            "kernel_modules": "kernel_module",
            "modules": "kernel_module",
            "world_writable": "filesystem",
            "suid": "privilege_escalation_surface",
            "ioc": "ioc",
            "mac": "mac",
            "integrity": "integrity",
            "rules": "rule_enrichment"
        }

        assert CAT_MAP == expected_mappings

    def test_policy_multiplier_values(self):
        """Test POLICY_MULTIPLIER contains expected values."""
        expected_multipliers = {
            "ioc": 2.0,
            "privilege_escalation_surface": 1.5,
            "network_socket": 1.3,
            "kernel_module": 1.2,
            "kernel_param": 1.1,
        }

        assert POLICY_MULTIPLIER == expected_multipliers

    def test_severity_base_values(self):
        """Test SEVERITY_BASE contains expected values."""
        expected_severities = {
            "info": 1,
            "low": 2,
            "medium": 3,
            "high": 4,
            "critical": 5,
            "error": 4
        }

        assert SEVERITY_BASE == expected_severities


class TestRecomputeFindingRisk:
    """Test _recompute_finding_risk function."""

    def test_recompute_finding_risk_success(self):
        """Test successful risk recomputation."""
        # Create a mock finding with risk_subscores
        finding = MagicMock()
        finding.risk_subscores = {
            "impact": 3.0,
            "exposure": 2.0,
            "anomaly": 1.5,
            "confidence": 0.9
        }

        # Mock the modules that are imported inside the function
        with patch('sys_scan_agent.risk.load_persistent_weights', return_value={"impact": 0.4, "exposure": 0.3, "anomaly": 0.2, "confidence": 0.1}), \
             patch('sys_scan_agent.risk.compute_risk', return_value=(75.5, 45.2)), \
             patch('sys_scan_agent.calibration.apply_probability', return_value=0.85):

            _recompute_finding_risk(finding)

            # Verify finding was updated
            assert finding.risk_score == 75.5
            assert finding.risk_total == 75.5
            assert finding.probability_actionable == 0.85
            assert finding.risk_subscores["_raw_weighted_sum"] == 45.2

    def test_recompute_finding_risk_no_subscores(self):
        """Test risk recomputation with no risk_subscores."""
        # Create a simple object without risk_subscores
        class SimpleFinding:
            pass

        finding = SimpleFinding()

        # Should not crash and should not modify finding
        _recompute_finding_risk(finding)

        # Should not have set risk_score
        assert not hasattr(finding, 'risk_score')

    def test_recompute_finding_risk_computation_error(self):
        """Test risk recomputation with computation error."""
        finding = MagicMock()
        finding.risk_subscores = {
            "impact": 3.0,
            "exposure": 2.0,
            "anomaly": 1.5,
            "confidence": 0.9
        }

        # Mock to raise ValueError
        with patch('sys_scan_agent.risk.load_persistent_weights', side_effect=ValueError("Computation error")), \
             patch('sys_scan_agent.audit.log_stage') as mock_log:

            _recompute_finding_risk(finding)

            # Should log error
            mock_log.assert_called_with(
                'risk_recompute_error',
                error="Computation error",
                type="ValueError"
            )

    def test_recompute_finding_risk_unexpected_error(self):
        """Test risk recomputation with unexpected error."""
        finding = MagicMock()
        finding.risk_subscores = {
            "impact": 3.0,
            "exposure": 2.0,
            "anomaly": 1.5,
            "confidence": 0.9
        }

        # Mock to raise unexpected error
        with patch('sys_scan_agent.risk.load_persistent_weights', side_effect=RuntimeError("Unexpected error")), \
             patch('sys_scan_agent.audit.log_stage') as mock_log:

            _recompute_finding_risk(finding)

            # Should log unexpected error
            mock_log.assert_called_with(
                'risk_recompute_error_unexpected',
                error="Unexpected error",
                type="RuntimeError"
            )


class TestLogError:
    """Test _log_error function."""

    def test_log_error_with_state(self):
        """Test error logging with state attachment."""
        from sys_scan_agent.models import AgentState

        state = AgentState()
        state.agent_warnings = []

        error = ValueError("Test error")

        with patch('sys_scan_agent.audit.log_stage') as mock_log:
            _log_error("test_stage", error, state, "test_module", "warning", "test hint")

            # Should add warning to state
            assert len(state.agent_warnings) == 1
            warning = state.agent_warnings[0]
            assert warning['module'] == "test_module"
            assert warning['stage'] == "test_stage"
            assert warning['error_type'] == "ValueError"
            assert warning['message'] == "Test error"
            assert warning['severity'] == "warning"
            assert warning['hint'] == "test hint"

            # Should log to audit
            mock_log.assert_called_with(
                'test_stage_error',
                error="Test error",
                type="ValueError"
            )

    def test_log_error_without_state(self):
        """Test error logging without state."""
        error = RuntimeError("Test runtime error")

        with patch('sys_scan_agent.audit.log_stage') as mock_log:
            _log_error("another_stage", error, None, "another_module", "error")

            # Should log to audit
            mock_log.assert_called_with(
                'another_stage_error',
                error="Test runtime error",
                type="RuntimeError"
            )

    def test_log_error_state_append_fails(self):
        """Test error logging when state append fails."""
        state = MagicMock()
        state.agent_warnings.append.side_effect = Exception("Append failed")

        error = Exception("Test exception")

        with patch('sys_scan_agent.audit.log_stage') as mock_log:
            # Should not crash despite append failure
            _log_error("stage", error, state, "module")

            # Should still log to audit
            mock_log.assert_called_with(
                'stage_error',
                error="Test exception",
                type="Exception"
            )

    def test_log_error_audit_fails(self):
        """Test error logging when audit logging fails."""
        error = Exception("Test exception")

        with patch('sys_scan_agent.audit.log_stage', side_effect=Exception("Audit failed")):
            # Should not crash despite audit failure
            _log_error("stage", error, None, "module")

            # Function should complete without raising