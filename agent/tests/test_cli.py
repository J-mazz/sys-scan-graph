from __future__ import annotations
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import typer
from typer.testing import CliRunner

from sys_scan_agent.cli import (
    app, _notify, build_fleet_report, risk_weights, risk_calibration,
    risk_decision, keygen, sign, verify, run_intelligence_workflow
)
from sys_scan_agent import models


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
        with patch('sys_scan_agent.cli.print') as mock_print:
            _notify(cfg, message)
            mock_print.assert_called_with("[yellow]Notification disabled: Air-gapped deployment - external communications not allowed[/]")

    @patch('sys_scan_agent.cli.baseline.BaselineStore')
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
        with patch('sys_scan_agent.cli.risk.load_persistent_weights') as mock_load, \
             patch('sys_scan_agent.cli.risk.describe') as mock_describe:

            mock_load.return_value = {"impact": 0.4, "exposure": 0.3, "anomaly": 0.3}
            mock_describe.return_value = "Risk weights description"

            result = runner.invoke(app, ["risk-weights", "--show"])

            assert result.exit_code == 0
            mock_describe.assert_called_once()

    def test_risk_weights_update(self, runner):
        """Test risk_weights command with update options."""
        with patch('sys_scan_agent.cli.risk.load_persistent_weights') as mock_load, \
             patch('sys_scan_agent.cli.risk.save_persistent_weights') as mock_save:

            mock_load.return_value = {"impact": 0.4, "exposure": 0.3, "anomaly": 0.3}

            result = runner.invoke(app, ["risk-weights", "--impact", "0.5", "--exposure", "0.4"])

            assert result.exit_code == 0
            mock_save.assert_called_once_with({"impact": 0.5, "exposure": 0.4, "anomaly": 0.3})

    def test_risk_calibration_show(self, runner):
        """Test risk_calibration command with show option."""
        with patch('sys_scan_agent.cli.calibration.load_calibration') as mock_load:
            mock_load.return_value = {"version": "test", "type": "logistic", "params": {"a": -3.0, "b": 0.15}}

            result = runner.invoke(app, ["risk-calibration", "--show"])

            assert result.exit_code == 0
            # Should print the calibration data
            assert "test" in result.output

    def test_risk_calibration_update(self, runner):
        """Test risk_calibration command with update options."""
        with patch('sys_scan_agent.cli.calibration.load_calibration') as mock_load, \
             patch('sys_scan_agent.cli.calibration.save_calibration') as mock_save:

            mock_load.return_value = {"version": "test", "type": "logistic", "params": {"a": -3.0, "b": 0.15}}

            result = runner.invoke(app, ["risk-calibration", "--a", "-2.5", "--version", "updated"])

            assert result.exit_code == 0
            expected_cal = {"version": "updated", "type": "logistic", "params": {"a": -2.5, "b": 0.15}}
            mock_save.assert_called_once_with(expected_cal)


class TestIntegrityCommands:
    """Test integrity-related CLI commands."""

    def test_keygen(self, runner, temp_dir):
        """Test keygen command."""
        with patch('sys_scan_agent.cli.generate_keypair') as mock_gen:
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
        with patch('sys_scan_agent.cli.sign_file') as mock_sign:
            mock_sign.return_value = ("test_digest", "test_sig_base64")

            key_file = sample_report_file.parent / "test_key"
            key_file.write_text("test_key_data")

            result = runner.invoke(app, ["sign", "--report", str(sample_report_file), "--signing-key", str(key_file)])

            assert result.exit_code == 0
            assert "Signed" in result.output
            assert "test_digest" in result.output

    def test_verify_valid(self, runner, sample_report_file):
        """Test verify command with valid signature."""
        with patch('sys_scan_agent.cli.verify_file') as mock_verify:
            mock_verify.return_value = {"digest_match": True, "signature_valid": True}

            key_file = sample_report_file.parent / "test_key"
            key_file.write_text("test_key_data")

            result = runner.invoke(app, ["verify", "--report", str(sample_report_file), "--verify-key", str(key_file)])

            assert result.exit_code == 0
            assert "Verification status" in result.output

    def test_verify_invalid(self, runner, sample_report_file):
        """Test verify command with invalid signature."""
        with patch('sys_scan_agent.cli.verify_file') as mock_verify:
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

        with patch('sys_scan_agent.rules.load_rules_dir') as mock_load, \
             patch('sys_scan_agent.rules.lint_rules') as mock_lint:

            mock_load.return_value = [{"id": "test_rule"}]
            mock_lint.return_value = []  # No issues

            result = runner.invoke(app, ["rule-lint", "--rules-dir", str(rules_dir)])

            assert result.exit_code == 0
            assert "No lint issues detected" in result.output

    def test_rule_lint_with_issues(self, runner, temp_dir):
        """Test rule_lint command with issues."""
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()

        with patch('sys_scan_agent.rules.load_rules_dir') as mock_load, \
             patch('sys_scan_agent.rules.lint_rules') as mock_lint:

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

        with patch('sys_scan_agent.cli.run_intelligence_workflow') as mock_workflow:
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


class TestIntelligenceWorkflow:
    """Test the intelligence workflow runner."""

    @patch('sys_scan_agent.cli.graph_state.normalize_graph_state')
    @patch('sys_scan_agent.cli.graph.enrich_findings')
    @patch('sys_scan_agent.cli.graph.correlate_findings')
    @patch('sys_scan_agent.cli.graph.risk_analyzer')
    @patch('sys_scan_agent.cli.graph.compliance_checker')
    @patch('sys_scan_agent.cli.graph.metrics_collector')
    @patch('sys_scan_agent.cli.graph._generate_executive_summary')
    @patch('sys_scan_agent.cli.graph._create_reductions')
    @patch('sys_scan_agent.cli.models.EnrichedOutput')
    @patch('sys_scan_agent.cli.models.Reductions')
    @patch('sys_scan_agent.cli.models.Summaries')
    def test_run_intelligence_workflow_success(self, mock_summaries, mock_reductions,
                                               mock_enriched_output, mock_create_reductions,
                                               mock_generate_summary, mock_metrics_collector,
                                               mock_compliance_checker, mock_risk_analyzer,
                                               mock_correlate, mock_enrich, mock_normalize):
        """Test successful intelligence workflow execution."""
        # Mock report data
        report_data = {
            "results": [
                {"findings": [{"id": "test1", "title": "Test finding 1"}]},
                {"findings": [{"id": "test2", "title": "Test finding 2"}]}
            ]
        }

        # Mock normalized state
        mock_normalize.return_value = {
            'raw_findings': [{"id": "test1"}, {"id": "test2"}],
            'enriched_findings': [],
            'correlated_findings': [],
            'correlations': [],
            'risk_assessment': {},
            'metrics': {}
        }

        # Mock graph operations
        mock_enrich.return_value = {'enriched_findings': [{'id': 'test1', 'enriched': True}]}
        mock_correlate.return_value = {'correlations': [{'type': 'test_correlation'}]}

        # Mock async operations
        async def mock_async_op(state):
            return {**state, 'risk_assessment': {'level': 'medium'}}

        mock_risk_analyzer.side_effect = mock_async_op
        mock_compliance_checker.side_effect = mock_async_op
        mock_metrics_collector.side_effect = mock_async_op

        # Mock summary and reductions
        mock_generate_summary.return_value = "Test executive summary"
        mock_create_reductions.return_value = {'total': 2, 'reduced': 1}

        # Mock EnrichedOutput
        mock_enriched = MagicMock()
        mock_enriched.model_dump.return_value = {'test': 'data'}
        mock_enriched_output.return_value = mock_enriched

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(report_data, f)
            report_path = Path(f.name)

        try:
            enriched, final_state = run_intelligence_workflow(report_path)

            # Verify calls
            mock_normalize.assert_called_once()
            mock_enrich.assert_called_once()
            mock_correlate.assert_called_once()
            mock_risk_analyzer.assert_called_once()
            mock_compliance_checker.assert_called_once()
            mock_metrics_collector.assert_called_once()
            mock_generate_summary.assert_called_once()
            mock_create_reductions.assert_called_once()
            mock_enriched_output.assert_called_once()

            assert enriched is not None
            assert final_state is not None

        finally:
            report_path.unlink()

    @patch('sys_scan_agent.cli.graph_state.normalize_graph_state')
    def test_run_intelligence_workflow_exception(self, mock_normalize):
        """Test intelligence workflow with exception."""
        # Mock normalize to raise exception
        mock_normalize.side_effect = Exception("Test error")

        report_data = {"results": []}

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(report_data, f)
            report_path = Path(f.name)

        try:
            with pytest.raises(Exception, match="Test error"):
                run_intelligence_workflow(report_path)
        finally:
            report_path.unlink()


class TestAnalyzeCommand:
    """Test the analyze CLI command."""

    @patch('sys_scan_agent.sandbox.configure')
    @patch('sys_scan_agent.cli.config.load_config')
    @patch('sys_scan_agent.cli.run_intelligence_workflow')
    @patch('sys_scan_agent.cli.report_html.write_html')
    @patch('sys_scan_agent.cli.config.write_manifest')
    def test_analyze_basic(self, mock_write_manifest, mock_write_html, mock_run_workflow,
                          mock_load_config, mock_sandbox_config):
        """Test basic analyze command."""
        # Mock config
        mock_config = MagicMock()
        mock_config.reports.html_enabled = True
        mock_config.reports.html_path = "test.html"
        mock_config.reports.diff_markdown_path = "test.md"
        mock_config.notifications.actionable_delta_threshold = 0.1
        mock_load_config.return_value = mock_config

        # Mock workflow result
        mock_enriched = MagicMock()
        mock_enriched.model_dump.return_value = {"test": "data"}
        mock_enriched.enriched_findings = []
        mock_run_workflow.return_value = (mock_enriched, {'test': 'state'})

        runner = CliRunner()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"results": []}, f)
            report_path = f.name

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "output.json"

            try:
                result = runner.invoke(app, [
                    'analyze',
                    '--report', report_path,
                    '--out', str(out_path)
                ])

                assert result.exit_code == 0
                assert "Wrote enriched output" in result.output
                assert out_path.exists()

                # Verify calls
                mock_run_workflow.assert_called_once()
                mock_write_html.assert_called_once()
                mock_write_manifest.assert_called_once()

            finally:
                Path(report_path).unlink()

    @patch('sys_scan_agent.cli.sandbox')
    @patch('sys_scan_agent.cli.config.load_config')
    @patch('sys_scan_agent.cli.run_intelligence_workflow')
    def test_analyze_dry_run(self, mock_run_workflow, mock_load_config, mock_sandbox):
        """Test analyze command with dry run."""
        mock_sandbox.configure = MagicMock()
        
        mock_config = MagicMock()
        mock_config.reports.html_enabled = False
        mock_load_config.return_value = mock_config

        mock_enriched = MagicMock()
        mock_enriched.model_dump.return_value = {"test": "data"}
        mock_run_workflow.return_value = (mock_enriched, {})

        runner = CliRunner()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"results": []}, f)
            report_path = f.name

        try:
            result = runner.invoke(app, [
                'analyze',
                '--report', report_path,
                '--dry-run'
            ])

            assert result.exit_code == 0
            mock_sandbox.configure.assert_called_with(dry_run=True)

        finally:
            Path(report_path).unlink()

    @patch('sys_scan_agent.cli.config.load_config')
    @patch('sys_scan_agent.cli.run_intelligence_workflow')
    @patch('sys_scan_agent.cli.metrics_exporter.write_metrics_json')
    @patch('sys_scan_agent.cli.metrics_exporter.print_metrics_summary')
    def test_analyze_with_metrics_json(self, mock_print_summary, mock_write_json,
                                      mock_run_workflow, mock_load_config):
        """Test analyze command with JSON metrics export."""
        mock_config = MagicMock()
        mock_config.reports.html_enabled = False
        mock_load_config.return_value = mock_config

        mock_enriched = MagicMock()
        mock_enriched.model_dump.return_value = {"test": "data"}
        mock_run_workflow.return_value = (mock_enriched, {'metrics': 'data'})

        runner = CliRunner()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"results": []}, f)
            report_path = f.name

        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_path = Path(tmpdir) / "metrics.json"

            try:
                result = runner.invoke(app, [
                    'analyze',
                    '--report', report_path,
                    '--metrics-out', str(metrics_path)
                ])

                assert result.exit_code == 0
                assert "Metrics exported to JSON" in result.output
                mock_write_json.assert_called_once()
                mock_print_summary.assert_called_once()

            finally:
                Path(report_path).unlink()

    @patch('sys_scan_agent.cli.config.load_config')
    @patch('sys_scan_agent.cli.run_intelligence_workflow')
    @patch('sys_scan_agent.cli.metrics_exporter.export_metrics_csv')
    def test_analyze_with_metrics_csv(self, mock_export_csv, mock_run_workflow, mock_load_config):
        """Test analyze command with CSV metrics export."""
        mock_config = MagicMock()
        mock_config.reports.html_enabled = False
        mock_load_config.return_value = mock_config

        mock_enriched = MagicMock()
        mock_enriched.model_dump.return_value = {"test": "data"}
        mock_run_workflow.return_value = (mock_enriched, {})

        runner = CliRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_path = Path(tmpdir) / "metrics.csv"

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"results": []}, f)
                report_path = f.name

            try:
                result = runner.invoke(app, [
                    'analyze',
                    '--report', report_path,
                    '--metrics-out', str(metrics_path)
                ])

                assert result.exit_code == 0
                assert "Metrics exported to CSV" in result.output
                mock_export_csv.assert_called_once()

            finally:
                Path(report_path).unlink()


class TestValidateBatchCommand:
    """Test the validate-batch CLI command."""

    @patch('sys_scan_agent.cli.run_intelligence_workflow')
    def test_validate_batch_success(self, mock_run_workflow, runner, temp_dir):
        """Test successful batch validation."""
        # Create multiple report files
        report_files = []
        for i in range(3):
            report_path = temp_dir / f"report_{i}.json"
            report_path.write_text(json.dumps({
                "summary": {"finding_count_total": i + 1},
                "results": [{"findings": [{"id": f"finding_{i}"}]}]
            }))
            report_files.append(report_path)

        # Create schema file in a different location to avoid confusion
        schema_dir = temp_dir / "schema"
        schema_dir.mkdir()
        schema_path = schema_dir / "schema.json"
        schema_path.write_text(json.dumps({"type": "object"}))

        mock_run_workflow.return_value = (MagicMock(correlations=[]), {})

        result = runner.invoke(app, [
            'validate-batch',
            '--dir', str(temp_dir),
            '--schema', str(schema_path),
            '--require', '3'
        ])

        assert result.exit_code == 0
        assert "Batch complete" in result.output
        assert mock_run_workflow.call_count == 3

    def test_validate_batch_insufficient_files(self, runner, temp_dir):
        """Test batch validation with insufficient files."""
        # Create only 2 files but require 5
        for i in range(2):
            report_path = temp_dir / f"report_{i}.json"
            report_path.write_text(json.dumps({"test": "data"}))

        schema_path = temp_dir / "schema.json"
        schema_path.write_text(json.dumps({"type": "object"}))

        result = runner.invoke(app, [
            'validate-batch',
            '--dir', str(temp_dir),
            '--schema', str(schema_path),
            '--require', '5'
        ])

        assert result.exit_code == 5
        assert "Not enough fixtures" in result.output

    def test_validate_batch_schema_error(self, runner, temp_dir):
        """Test batch validation with schema error."""
        # Create report that won't match schema
        report_path = temp_dir / "report.json"
        report_path.write_text(json.dumps({"invalid_field": "value"}))

        schema_path = temp_dir / "schema.json"
        schema_path.write_text(json.dumps({
            "type": "object",
            "required": ["required_field"]
        }))

        result = runner.invoke(app, [
            'validate-batch',
            '--dir', str(temp_dir),
            '--schema', str(schema_path),
            '--require', '1'
        ])

        assert result.exit_code == 7
        assert "schema_error" in result.output


class TestRiskDecisionCommand:
    """Test the risk-decision CLI command."""

    @patch('sys_scan_agent.cli.run_intelligence_workflow')
    @patch('sys_scan_agent.cli.baseline.BaselineStore')
    def test_risk_decision(self, mock_store_class, mock_run_workflow, runner):
        """Test risk decision recording."""
        mock_store = MagicMock()
        mock_store_class.return_value = mock_store

        mock_enriched = MagicMock()
        mock_enriched.enriched_findings = []
        mock_run_workflow.return_value = (mock_enriched, {})

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"results": []}, f)
            report_path = f.name

        try:
            result = runner.invoke(app, [
                'risk-decision',
                '--report', report_path,
                '--finding-id', 'test-finding-id',
                '--decision', 'tp'
            ])

            assert result.exit_code == 0
            assert "Decision recorded" in result.output
            mock_store.update_calibration_decision.assert_called_once()

        finally:
            Path(report_path).unlink()


class TestRuleDryRunCommand:
    """Test the rule-dry-run CLI command."""

    @patch('sys_scan_agent.cli.load_rules_dir')
    @patch('sys_scan_agent.cli.dry_run_apply')
    @patch('sys_scan_agent.cli.models.Finding')
    def test_rule_dry_run_with_matches(self, mock_finding, mock_apply, mock_load, runner, temp_dir):
        """Test rule dry run with matches."""
        mock_load.return_value = {"rules": []}
        mock_apply.return_value = {
            "rule1": ["finding1", "finding2"],
            "rule2": []
        }

        mock_finding_instance = MagicMock()
        mock_finding.return_value = mock_finding_instance

        # Create findings JSON
        findings_data = [
            {"id": "finding1", "title": "Test finding 1", "severity": "high", "risk_score": 80},
            {"id": "finding2", "title": "Test finding 2", "severity": "medium", "risk_score": 50}
        ]
        findings_path = temp_dir / "findings.json"
        findings_path.write_text(json.dumps(findings_data))

        # Create rules directory
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()

        result = runner.invoke(app, [
            'rule-dry-run',
            '--rules-dir', str(rules_dir),
            '--findings-json', str(findings_path)
        ])

        assert result.exit_code == 0
        assert "rule1" in result.output
        assert "finding1, finding2" in result.output
        assert "rule2" in result.output
        assert "(no matches)" in result.output


class TestBaselineIntegrityCommand:
    """Test the baseline-integrity CLI command."""

    @patch('sys_scan_agent.cli.baseline.BaselineStore')
    def test_baseline_integrity_complete(self, mock_store_class, runner):
        """Test baseline integrity with complete data."""
        mock_store = MagicMock()
        mock_store_class.return_value = mock_store
        mock_store.scan_days_present.return_value = {
            "2024-01-01": True,
            "2024-01-02": True,
            "2024-01-03": True
        }

        result = runner.invoke(app, [
            'baseline-integrity',
            '--host', 'test-host',
            '--days', '3'
        ])

        assert result.exit_code == 0
        assert "OK" in result.output
        mock_store.scan_days_present.assert_called_once_with('test-host', 3)

    @patch('sys_scan_agent.cli.baseline.BaselineStore')
    def test_baseline_integrity_missing_days(self, mock_store_class, runner):
        """Test baseline integrity with missing days."""
        mock_store = MagicMock()
        mock_store_class.return_value = mock_store
        mock_store.scan_days_present.return_value = {
            "2024-01-01": True,
            "2024-01-02": False,
            "2024-01-03": True
        }

        result = runner.invoke(app, [
            'baseline-integrity',
            '--host', 'test-host',
            '--days', '3'
        ])

        assert result.exit_code == 0
        assert "OK" in result.output
        assert "MISSING" in result.output
        assert "Missing 1 day(s)" in result.output


class TestRarityGenerateCommand:
    """Test the rarity-generate-cmd CLI command."""

    @patch('sys_scan_agent.cli.rarity_generate_func')
    def test_rarity_generate_cmd(self, mock_generate, runner, temp_dir):
        """Test rarity generation command."""
        mock_generate.return_value = Path("test_rarity.yaml")

        out_path = temp_dir / "rarity.yaml"

        result = runner.invoke(app, [
            'rarity-generate-cmd',
            '--out', str(out_path)
        ])

        assert result.exit_code == 0
        assert "Generated rarity file" in result.output
        mock_generate.assert_called_once()


class TestSandboxCommand:
    """Test the sandbox CLI command."""

    @patch('sys_scan_agent.cli.sandbox')
    def test_sandbox_configure(self, mock_sandbox, runner):
        """Test sandbox configuration command."""
        mock_sandbox.configure = MagicMock()
        mock_sandbox.configure.return_value = MagicMock()
        mock_sandbox.configure.return_value.model_dump.return_value = {"dry_run": True}

        result = runner.invoke(app, [
            'sandbox',
            '--dry-run',
            '--timeout', '30.0'
        ])

        assert result.exit_code == 0
        assert "Sandbox updated" in result.output
        mock_sandbox.configure.assert_called_once_with(dry_run=True, timeout_sec=30.0, max_output_bytes=None)


class TestBaselineDiffCommand:
    """Test the baseline-diff CLI command."""

    @patch('sys_scan_agent.cli.baseline.BaselineStore')
    def test_baseline_diff_days(self, mock_store_class, runner):
        """Test baseline diff with days duration."""
        mock_store = MagicMock()
        mock_store_class.return_value = mock_store
        mock_store.diff_since_days.return_value = {"changes": "test_data"}

        result = runner.invoke(app, [
            'baseline-diff',
            '--host', 'test-host',
            '--since', '7d'
        ])

        assert result.exit_code == 0
        mock_store.diff_since_days.assert_called_once_with('test-host', 7)

    @patch('sys_scan_agent.cli.baseline.BaselineStore')
    def test_baseline_diff_hours(self, mock_store_class, runner):
        """Test baseline diff with hours duration."""
        mock_store = MagicMock()
        mock_store_class.return_value = mock_store
        mock_store.diff_since_days.return_value = {"changes": "test_data"}

        result = runner.invoke(app, [
            'baseline-diff',
            '--host', 'test-host',
            '--since', '24h'
        ])

        assert result.exit_code == 0
        mock_store.diff_since_days.assert_called_once_with('test-host', 1)  # 24h = 1 day

    def test_baseline_diff_invalid_duration(self, runner):
        """Test baseline diff with invalid duration."""
        result = runner.invoke(app, [
            'baseline-diff',
            '--host', 'test-host',
            '--since', 'invalid'
        ])

        assert result.exit_code == 2  # Exit code for invalid duration


class TestFleetReportCommand:
    """Test the fleet-report CLI command."""

    @patch('sys_scan_agent.cli.build_fleet_report')
    def test_fleet_report_cmd(self, mock_build, runner, temp_dir):
        """Test fleet report command."""
        mock_build.return_value = {
            "generated_ts": 1234567890,
            "host_count": 5,
            "metric_mean": 10.0,
            "metric_std": 2.0,
            "top_outlier_hosts": [],
            "newly_common_modules": [],
            "risk_distribution": []
        }

        out_path = temp_dir / "fleet.json"

        result = runner.invoke(app, [
            'fleet-report',
            '--out', str(out_path)
        ])

        assert result.exit_code == 0
        assert "Wrote fleet report" in result.output
        assert out_path.exists()
        mock_build.assert_called_once()


class TestAuditTailCommand:
    """Test the audit-tail CLI command."""

    @patch('sys_scan_agent.cli.tail_since')
    def test_audit_tail(self, mock_tail, runner):
        """Test audit tail command."""
        mock_tail.return_value = [
            {"timestamp": "2024-01-01", "event": "test1"},
            {"timestamp": "2024-01-02", "event": "test2"}
        ]

        result = runner.invoke(app, [
            'audit-tail',
            '--since', '1h',
            '--limit', '10'
        ])

        assert result.exit_code == 0
        assert "2 record(s)" in result.output
        mock_tail.assert_called_once_with('1h', limit=10)


class TestRuleGapMineCommand:
    """Test the rule-gap-mine CLI command."""

    @patch('sys_scan_agent.cli.mine_gap_candidates')
    @patch('sys_scan_agent.cli.refine_with_llm')
    def test_rule_gap_mine_without_refine(self, mock_refine, mock_mine, runner, temp_dir):
        """Test rule gap mining without LLM refinement."""
        mock_mine.return_value = {
            "suggestions": [{"rule": "test_rule"}],
            "candidates": [],
            "selected": 1,
            "total_candidates": 5
        }

        input_dir = temp_dir / "input"
        input_dir.mkdir()
        out_path = temp_dir / "output.json"

        result = runner.invoke(app, [
            'rule-gap-mine',
            '--dir', str(input_dir),
            '--out', str(out_path)
        ])

        assert result.exit_code == 0
        assert "Wrote suggestions" in result.output
        assert "selected=1" in result.output
        assert "refined=False" in result.output
        mock_refine.assert_not_called()

    @patch('sys_scan_agent.cli.mine_gap_candidates')
    @patch('sys_scan_agent.cli.refine_with_llm')
    def test_rule_gap_mine_with_refine(self, mock_refine, mock_mine, runner, temp_dir):
        """Test rule gap mining with LLM refinement."""
        mock_mine.return_value = {
            "suggestions": [{"rule": "test_rule"}],
            "candidates": [{"key": "test_key", "example_titles": ["example1"]}],
            "selected": 1,
            "total_candidates": 5
        }
        mock_refine.return_value = [{"rule": "refined_rule"}]

        input_dir = temp_dir / "input"
        input_dir.mkdir()
        out_path = temp_dir / "output.json"

        result = runner.invoke(app, [
            'rule-gap-mine',
            '--dir', str(input_dir),
            '--refine',
            '--out', str(out_path)
        ])

        assert result.exit_code == 0
        assert "refined=True" in result.output
        mock_refine.assert_called_once()


class TestVerifySignatureCommand:
    """Test the verify-signature CLI command."""

    @patch('sys_scan_agent.cli.verify_file')
    def test_verify_signature_valid(self, mock_verify, runner, sample_report_file):
        """Test verify signature command with valid signature."""
        mock_verify.return_value = {
            "digest_match": True,
            "signature_valid": True
        }

        key_file = sample_report_file.parent / "test_key"
        key_file.write_text("test_key_data")

        result = runner.invoke(app, [
            'verify-signature',
            '--report', str(sample_report_file),
            '--verify-key', str(key_file)
        ])

        assert result.exit_code == 0
        assert "Verification status" in result.output

    @patch('sys_scan_agent.cli.verify_file')
    def test_verify_signature_invalid(self, mock_verify, runner, sample_report_file):
        """Test verify signature command with invalid signature."""
        mock_verify.return_value = {
            "digest_match": False,
            "signature_valid": False
        }

        key_file = sample_report_file.parent / "test_key"
        key_file.write_text("test_key_data")

        result = runner.invoke(app, [
            'verify-signature',
            '--report', str(sample_report_file),
            '--verify-key', str(key_file)
        ])

        assert result.exit_code == 10
        assert "Verification status" in result.output