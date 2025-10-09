from __future__ import annotations
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import typer
from typer.testing import CliRunner

from sys_scan_graph_agent.cli import (
    app, _notify, build_fleet_report, risk_weights, risk_calibration,
    risk_decision, keygen, sign, verify
)
from sys_scan_graph_agent import models


@pytest.fixture
def runner():
    """CLI runner for testing typer commands."""
    return CliRunner()


@pytest.fixture
def temp_dir(tmp_path):
    """Temporary directory for test files."""
    return tmp_path


@pytest.fixture
def sample_report_data():
    """Sample report data for testing."""
    return {
        "meta": {
            "hostname": "test-host",
            "host_id": "test-host-123"
        },
        "summary": {
            "finding_count_total": 5,
            "finding_count_emitted": 5
        },
        "results": [
            {
                "scanner": "test_scanner",
                "findings": [
                    {
                        "id": "finding-1",
                        "title": "Test Finding 1",
                        "severity": "medium",
                        "risk_score": 5,
                        "metadata": {"test": "data"}
                    },
                    {
                        "id": "finding-2",
                        "title": "Test Finding 2",
                        "severity": "high",
                        "risk_score": 8,
                        "metadata": {"test": "data2"}
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_report_file(temp_dir, sample_report_data):
    """Create a temporary report file."""
    report_path = temp_dir / "test_report.json"
    report_path.write_text(json.dumps(sample_report_data))
    return report_path


class TestUtilityFunctions:
    """Test utility functions in CLI module."""

    def test_notify_disabled(self):
        """Test that _notify is disabled for air-gapped deployment."""
        cfg = MagicMock()
        message = "Test message"

        # Should not raise exception and should print disabled message
        with patch('sys_scan_graph_agent.cli.print') as mock_print:
            _notify(cfg, message)
            mock_print.assert_called_with("[yellow]Notification disabled: Air-gapped deployment - external communications not allowed[/]")

    @patch('sys_scan_graph_agent.cli.baseline.BaselineStore')
    def test_build_fleet_report_basic(self, mock_store_class, temp_dir):
        """Test build_fleet_report with basic data."""
        # Mock the baseline store
        mock_store = MagicMock()
        mock_store_class.return_value = mock_store

        # Mock latest_metric_values to return some data
        mock_store.latest_metric_values.return_value = [
            ("host1", 10.0, 1234567890),
            ("host2", 15.0, 1234567891),
            ("host3", 12.0, 1234567892)
        ]

        # Mock recent_module_first_seen
        mock_store.recent_module_first_seen.return_value = {
            "module_a": ["host1", "host2", "host3"],
            "module_b": ["host1", "host2"]
        }

        # Mock risk metrics
        mock_store.latest_metric_values.side_effect = lambda metric: {
            'finding.count.total': [("host1", 10.0, 1234567890), ("host2", 15.0, 1234567891)],
            'risk.sum.medium_high': [("host1", 25.0, 1234567890), ("host2", 75.0, 1234567891)]
        }.get(metric, [])

        db_path = temp_dir / "test.db"
        result = build_fleet_report(db_path, top_n=2, recent_seconds=3600, module_min_hosts=2)

        # Verify structure
        assert "generated_ts" in result
        assert result["host_count"] == 2
        assert "metric_mean" in result
        assert "metric_std" in result
        assert len(result["top_outlier_hosts"]) <= 2
        assert len(result["newly_common_modules"]) >= 1  # module_a has 3 hosts
        assert "risk_distribution" in result

        # Verify newly common modules filtering
        common_modules = result["newly_common_modules"]
        for mod in common_modules:
            assert mod["host_count"] >= 2  # module_min_hosts = 2


class TestRiskCommands:
    """Test risk-related CLI commands."""

    def test_risk_weights_show(self, runner):
        """Test risk_weights command with show option."""
        with patch('sys_scan_graph_agent.cli.risk.load_persistent_weights') as mock_load, \
             patch('sys_scan_graph_agent.cli.risk.describe') as mock_describe:

            mock_load.return_value = {"impact": 0.4, "exposure": 0.3, "anomaly": 0.3}
            mock_describe.return_value = "Risk weights description"

            result = runner.invoke(app, ["risk-weights", "--show"])

            assert result.exit_code == 0
            mock_describe.assert_called_once()

    def test_risk_weights_update(self, runner):
        """Test risk_weights command with update options."""
        with patch('sys_scan_graph_agent.cli.risk.load_persistent_weights') as mock_load, \
             patch('sys_scan_graph_agent.cli.risk.save_persistent_weights') as mock_save:

            mock_load.return_value = {"impact": 0.4, "exposure": 0.3, "anomaly": 0.3}

            result = runner.invoke(app, ["risk-weights", "--impact", "0.5", "--exposure", "0.4"])

            assert result.exit_code == 0
            mock_save.assert_called_once_with({"impact": 0.5, "exposure": 0.4, "anomaly": 0.3})

    def test_risk_calibration_show(self, runner):
        """Test risk_calibration command with show option."""
        with patch('sys_scan_graph_agent.cli.calibration.load_calibration') as mock_load:
            mock_load.return_value = {"version": "test", "type": "logistic", "params": {"a": -3.0, "b": 0.15}}

            result = runner.invoke(app, ["risk-calibration", "--show"])

            assert result.exit_code == 0
            # Should print the calibration data
            assert "test" in result.output

    def test_risk_calibration_update(self, runner):
        """Test risk_calibration command with update options."""
        with patch('sys_scan_graph_agent.cli.calibration.load_calibration') as mock_load, \
             patch('sys_scan_graph_agent.cli.calibration.save_calibration') as mock_save:

            mock_load.return_value = {"version": "test", "type": "logistic", "params": {"a": -3.0, "b": 0.15}}

            result = runner.invoke(app, ["risk-calibration", "--a", "-2.5", "--version", "updated"])

            assert result.exit_code == 0
            expected_cal = {"version": "updated", "type": "logistic", "params": {"a": -2.5, "b": 0.15}}
            mock_save.assert_called_once_with(expected_cal)


class TestIntegrityCommands:
    """Test integrity-related CLI commands."""

    def test_keygen(self, runner, temp_dir):
        """Test keygen command."""
        with patch('sys_scan_graph_agent.cli.generate_keypair') as mock_gen:
            mock_gen.return_value = ("test_sk_base64", "test_vk_base64")

            result = runner.invoke(app, ["keygen", "--out-dir", str(temp_dir), "--prefix", "test"])

            assert result.exit_code == 0
            assert "Generated keypair" in result.output

            # Check files were created
            sk_file = temp_dir / "test.sk"
            vk_file = temp_dir / "test.vk"
            assert sk_file.exists()
            assert vk_file.exists()
            assert sk_file.read_text() == "test_sk_base64\n"
            assert vk_file.read_text() == "test_vk_base64\n"

    def test_sign(self, runner, sample_report_file):
        """Test sign command."""
        with patch('sys_scan_graph_agent.integrity.sign_file') as mock_sign:
            mock_sign.return_value = ("test_digest", "test_sig_base64")

            key_file = sample_report_file.parent / "test_key"
            key_file.write_text("test_key_data")

            result = runner.invoke(app, ["sign", "--report", str(sample_report_file), "--signing-key", str(key_file)])

            assert result.exit_code == 0
            assert "Signed" in result.output
            assert "test_digest" in result.output

    def test_verify_valid(self, runner, sample_report_file):
        """Test verify command with valid signature."""
        with patch('sys_scan_graph_agent.integrity.verify_file') as mock_verify:
            mock_verify.return_value = {"digest_match": True, "signature_valid": True}

            key_file = sample_report_file.parent / "test_key"
            key_file.write_text("test_key_data")

            result = runner.invoke(app, ["verify", "--report", str(sample_report_file), "--verify-key", str(key_file)])

            assert result.exit_code == 0
            assert "Verification status" in result.output

    def test_verify_invalid(self, runner, sample_report_file):
        """Test verify command with invalid signature."""
        with patch('sys_scan_graph_agent.integrity.verify_file') as mock_verify:
            mock_verify.return_value = {"digest_match": False, "signature_valid": False}

            key_file = sample_report_file.parent / "test_key"
            key_file.write_text("test_key_data")

            result = runner.invoke(app, ["verify", "--report", str(sample_report_file), "--verify-key", str(key_file)])

            assert result.exit_code == 10  # Should exit with error code
            assert "Verification status" in result.output


class TestRuleCommands:
    """Test rule-related CLI commands."""

    def test_rule_lint_no_issues(self, runner, temp_dir):
        """Test rule_lint command with no issues."""
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()

        # Create a valid rule file
        rule_file = rules_dir / "test_rule.json"
        rule_file.write_text(json.dumps({
            "id": "test_rule",
            "title": "Test Rule",
            "description": "A test rule",
            "severity": "medium",
            "tags": ["test"],
            "condition": "finding.id == 'test'",
            "actions": []
        }))

        with patch('sys_scan_graph_agent.rules.load_rules_dir') as mock_load, \
             patch('sys_scan_graph_agent.rules.lint_rules') as mock_lint:

            mock_load.return_value = [{"id": "test_rule"}]
            mock_lint.return_value = []  # No issues

            result = runner.invoke(app, ["rule-lint", "--rules-dir", str(rules_dir)])

            assert result.exit_code == 0
            assert "No lint issues detected" in result.output

    def test_rule_lint_with_issues(self, runner, temp_dir):
        """Test rule_lint command with issues."""
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()

        with patch('sys_scan_graph_agent.rules.load_rules_dir') as mock_load, \
             patch('sys_scan_graph_agent.rules.lint_rules') as mock_lint:

            mock_load.return_value = [{"id": "test_rule"}]
            mock_lint.return_value = [
                {"rule_id": "test_rule", "code": "ERROR", "detail": "Test error"}
            ]

            result = runner.invoke(app, ["rule-lint", "--rules-dir", str(rules_dir)])

            assert result.exit_code == 1  # Should exit with error
            assert "test_rule" in result.output
            assert "ERROR" in result.output


class TestValidationCommands:
    """Test validation-related CLI commands."""

    def test_validate_report_valid(self, runner, sample_report_file, temp_dir):
        """Test validate_report command with valid report."""
        schema_file = temp_dir / "test_schema.json"
        schema_file.write_text(json.dumps({
            "type": "object",
            "properties": {
                "meta": {"type": "object"},
                "summary": {"type": "object"},
                "results": {"type": "array"}
            }
        }))

        with patch('sys_scan_graph_agent.cli.run_intelligence_workflow') as mock_workflow:
            mock_workflow.return_value = (MagicMock(correlations=[]), {})

            result = runner.invoke(app, [
                "validate-report",
                "--report", str(sample_report_file),
                "--schema", str(schema_file),
                "--max-ms", "1000"
            ])

            assert result.exit_code == 0
            assert "Validation OK" in result.output

    def test_validate_report_invalid_schema(self, runner, sample_report_file, temp_dir):
        """Test validate_report command with invalid schema."""
        schema_file = temp_dir / "test_schema.json"
        schema_file.write_text(json.dumps({
            "type": "object",
            "properties": {
                "invalid_field": {"type": "string"}
            },
            "required": ["invalid_field"]
        }))

        result = runner.invoke(app, [
            "validate-report",
            "--report", str(sample_report_file),
            "--schema", str(schema_file)
        ])

        assert result.exit_code == 3  # Schema validation error
        assert "Schema validation error" in result.output