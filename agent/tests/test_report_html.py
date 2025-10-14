"""Tests for HTML report generation module.

This module tests the HTML report rendering functionality including:
- Executive summary rendering
- Risk analysis sections by severity
- Compliance data tables
- Finding and correlation rendering
- Edge cases and error handling
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
import json
from datetime import datetime

from sys_scan_agent import report_html, models


class TestRenderHTML:
    """Test HTML report rendering functionality."""

    def test_render_minimal_output(self):
        """Test rendering with minimal EnrichedOutput data."""
        # Create minimal mock objects
        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Minimal test summary"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}  # Add empty metrics dict

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert "<!DOCTYPE html>" in html_output
        assert "sys-scan Enriched Report" in html_output
        assert "Minimal test summary" in html_output
        assert "Findings (0)" in html_output
        assert "Correlations" in html_output

    def test_render_with_findings_all_severities(self):
        """Test rendering with findings of all severity levels."""
        # Create mock findings with different severities
        findings = []
        severities = ['critical', 'high', 'medium', 'low', 'info']

        for i, sev in enumerate(severities):
            finding = MagicMock()
            finding.id = f"finding_{i}"
            finding.title = f"Test Finding {i}"
            finding.severity = sev
            finding.risk_total = 10 - i  # Higher risk for more severe
            finding.risk_score = 10 - i
            finding.description = f"Description for {sev} finding"
            finding.tags = [f"tag_{sev}"]
            finding.baseline_status = "new"
            finding.metadata = {}
            finding.risk_subscores = {
                'impact': 5, 'exposure': 3, 'anomaly': 2, 'confidence': 4
            }
            finding.probability_actionable = 0.8
            finding.rationale = [f"Rationale for {sev}"]
            findings.append(finding)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Test summary with all severities"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = findings
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        # Check that all severity sections are present
        assert "Critical Risk Analysis (1 findings)" in html_output
        assert "High Risk Analysis (1 findings)" in html_output
        assert "Medium Risk Analysis (1 findings)" in html_output
        assert "Low Risk Analysis (1 findings)" in html_output

        # Check that findings are rendered
        for i in range(len(findings)):
            assert f"Test Finding {i}" in html_output

    def test_render_with_compliance_data(self):
        """Test rendering with compliance summary and gaps data."""
        # Create mock compliance data
        compliance_summary = {
            'pci_dss': {
                'passed': 15,
                'failed': 3,
                'not_applicable': 2,
                'total_controls': 20,
                'score': 85.0
            },
            'hipaa': {
                'passed': 12,
                'failed': 1,
                'not_applicable': 0,
                'total_controls': 13,
                'score': 92.3
            }
        }

        compliance_gaps = [
            {
                'standard': 'pci_dss',
                'control_id': 'PCI-1.2.3',
                'severity': 'high',
                'remediation_hint': 'Enable encryption'
            },
            {
                'standard': 'hipaa',
                'control_id': 'HIPAA-164.312',
                'severity': 'medium',
                'remediation_hint': 'Implement access controls'
            }
        ]

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Compliance test summary"
        mock_summaries.attack_coverage = None

        # Mock metrics with compliance data
        metrics = {
            'compliance_summary': compliance_summary,
            'compliance_gaps': compliance_gaps,
            'total_findings': 25
        }

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        # Mock the metrics access
        mock_output.summaries.metrics = metrics

        html_output = report_html.render(mock_output)

        # Check compliance table rendering
        assert "pci_dss" in html_output
        assert "hipaa" in html_output
        assert "15" in html_output  # PCI passed
        assert "3" in html_output   # PCI failed
        assert "85.0" in html_output  # PCI score

        # Check compliance gaps section
        assert "Compliance Gaps" in html_output
        assert "PCI-1.2.3" in html_output
        assert "HIPAA-164.312" in html_output
        assert "Enable encryption" in html_output

    def test_render_with_attack_coverage(self):
        """Test rendering with ATT&CK coverage data."""
        attack_coverage = {
            'technique_count': 45,
            'covered_techniques': ['T1059', 'T1078', 'T1566'],
            'coverage_percentage': 78.5
        }

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Attack coverage test"
        mock_summaries.attack_coverage = attack_coverage
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert "ATT&CK Coverage" in html_output
        assert "Techniques: 45" in html_output

    def test_render_with_correlations(self):
        """Test rendering with correlation data."""
        correlations = []
        for i in range(3):
            corr = MagicMock()
            corr.title = f"Correlation {i}"
            corr.rationale = f"Rationale for correlation {i}"
            corr.related_finding_ids = [f"finding_{j}" for j in range(i+1)]
            correlations.append(corr)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Correlation test summary"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = correlations
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert f"3 correlation(s)" in html_output
        for i in range(3):
            assert f"Correlation {i}" in html_output
            assert f"Rationale for correlation {i}" in html_output
            assert f"{i+1} findings" in html_output

    def test_render_with_detailed_findings(self):
        """Test rendering with detailed finding information."""
        findings = []

        # Critical finding with detailed metadata
        critical_finding = MagicMock()
        critical_finding.id = "critical_1"
        critical_finding.title = "Critical Security Issue"
        critical_finding.severity = "critical"
        critical_finding.risk_total = 95
        critical_finding.risk_score = 95
        critical_finding.description = "Deleted executable running"
        critical_finding.tags = ["malware", "deleted_executable"]
        critical_finding.baseline_status = "new"
        critical_finding.metadata = {"deleted_executable": True}
        critical_finding.risk_subscores = {'impact': 10, 'exposure': 9, 'anomaly': 8, 'confidence': 9}
        critical_finding.probability_actionable = 0.95
        critical_finding.rationale = ["High risk malware indicator"]
        findings.append(critical_finding)

        # High finding with world-writable executable
        high_finding = MagicMock()
        high_finding.id = "high_1"
        high_finding.title = "World Writable Executable"
        high_finding.severity = "high"
        high_finding.risk_total = 75
        high_finding.risk_score = 75
        high_finding.description = "Executable with world write permissions"
        high_finding.tags = ["permissions", "world_writable"]
        high_finding.baseline_status = "known"
        high_finding.metadata = {"world_writable": True}
        high_finding.risk_subscores = {'impact': 7, 'exposure': 8, 'anomaly': 6, 'confidence': 7}
        high_finding.probability_actionable = 0.85
        high_finding.rationale = ["Privilege escalation risk"]
        findings.append(high_finding)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Detailed findings test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = findings
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        # Check critical analysis section
        assert "Critical Risk Analysis (1 findings)" in html_output
        assert "deleted executable" in html_output

        # Check high analysis section
        assert "High Risk Analysis (1 findings)" in html_output
        assert "world_writable" in html_output

        # Check finding details
        assert "Critical Security Issue" in html_output
        assert "World Writable Executable" in html_output

    def test_render_with_empty_summaries(self):
        """Test rendering when summaries is None."""
        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = []
        mock_output.summaries = None

        html_output = report_html.render(mock_output)

        assert "(no executive summary)" in html_output
        assert "Findings (0)" in html_output

    def test_render_with_none_findings_and_correlations(self):
        """Test rendering when findings and correlations are None."""
        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "None data test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = None
        mock_output.correlations = None
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert "Findings (0)" in html_output
        assert "0 correlation(s)" in html_output

    def test_render_with_metrics_dict(self):
        """Test rendering with metrics as a dictionary."""
        metrics = {
            'total_findings': 42,
            'processing_time': 120.5,
            'risk_distribution': {'high': 5, 'medium': 15, 'low': 22}
        }

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Metrics test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = metrics

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert "Metrics" in html_output
        assert "total_findings" in html_output
        assert "42" in html_output

    def test_render_with_medium_findings_analysis(self):
        """Test medium risk analysis section rendering."""
        findings = []

        # Create medium severity findings with different types
        medium_types = [
            ("file_capability", "File with capabilities"),
            ("suid_binary", "SUID binary"),
            ("world_writable", "World writable file"),
            ("apparmor", "AppArmor unconfined")
        ]

        for i, (finding_type, title) in enumerate(medium_types):
            finding = MagicMock()
            finding.id = f"medium_{i}"
            finding.title = title
            finding.severity = "medium"
            finding.risk_total = 50 - i*5
            finding.risk_score = 50 - i*5
            finding.description = f"Medium risk {finding_type}"
            finding.tags = [finding_type.replace("_", "-")]
            finding.baseline_status = "known"
            finding.metadata = {finding_type: True}
            finding.risk_subscores = {'impact': 5, 'exposure': 4, 'anomaly': 3, 'confidence': 6}
            finding.probability_actionable = 0.6
            finding.rationale = [f"Medium risk {finding_type} issue"]
            findings.append(finding)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Medium risk analysis test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = findings
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert "Medium Risk Analysis (4 findings)" in html_output
        assert "capabilities" in html_output
        assert "SUID" in html_output
        assert "World writable file" in html_output
        assert "AppArmor" in html_output

    def test_render_with_low_findings_analysis(self):
        """Test low risk analysis section rendering."""
        findings = []

        # Create low severity findings
        low_types = [
            ("rp_filter", "RP filter disabled"),
            ("selinux", "SELinux disabled"),
            ("pattern_match", "Pattern match")
        ]

        for i, (finding_type, title) in enumerate(low_types):
            finding = MagicMock()
            finding.id = f"low_{i}"
            finding.title = title
            finding.severity = "low"
            finding.risk_total = 20 - i*3
            finding.risk_score = 20 - i*3
            finding.description = f"Low risk {finding_type}"
            finding.tags = [finding_type.replace("_", "-")]
            finding.baseline_status = "baseline"
            finding.metadata = {finding_type: True}
            finding.risk_subscores = {'impact': 2, 'exposure': 2, 'anomaly': 1, 'confidence': 4}
            finding.probability_actionable = 0.3
            finding.rationale = [f"Low risk {finding_type} issue"]
            findings.append(finding)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Low risk analysis test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = findings
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        assert "Low Risk Analysis (3 findings)" in html_output
        assert "RP filter disabled" in html_output
        assert "SELinux" in html_output
        assert "pattern" in html_output


class TestWriteHTML:
    """Test HTML file writing functionality."""

    @patch('pathlib.Path.write_text')
    def test_write_html_success(self, mock_write):
        """Test successful HTML file writing."""
        mock_output = MagicMock()
        mock_output.summaries = MagicMock()
        mock_output.summaries.metrics = {}
        test_path = Path("/tmp/test_report.html")

        result = report_html.write_html(mock_output, test_path)

        assert result == test_path
        mock_write.assert_called_once()
        # Verify the call was made with HTML content and UTF-8 encoding
        args, kwargs = mock_write.call_args
        assert kwargs['encoding'] == 'utf-8'
        assert isinstance(args[0], str)  # HTML content should be a string
        assert "<!DOCTYPE html>" in args[0]

    @patch('pathlib.Path.write_text')
    def test_write_html_with_real_output(self, mock_write):
        """Test HTML writing with a more complete output object."""
        # Create a mock output similar to real usage
        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Test executive summary"
        mock_summaries.attack_coverage = {'technique_count': 10}
        mock_summaries.metrics = {}

        mock_finding = MagicMock()
        mock_finding.id = "test_finding"
        mock_finding.title = "Test Finding"
        mock_finding.severity = "high"
        mock_finding.risk_total = 80
        mock_finding.risk_score = 80
        mock_finding.tags = ["test"]
        mock_finding.baseline_status = "new"
        mock_finding.probability_actionable = 0.9
        mock_finding.rationale = ["Test rationale"]

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = [mock_finding]
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        test_path = Path("/tmp/complete_report.html")

        result = report_html.write_html(mock_output, test_path)

        assert result == test_path
        mock_write.assert_called_once()
        args, kwargs = mock_write.call_args
        html_content = args[0]
        assert "Test executive summary" in html_content
        assert "test_finding" in html_content
        assert "High Risk Analysis (1 findings)" in html_content


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_render_with_extremely_large_findings(self):
        """Test rendering with a large number of findings (should be capped)."""
        findings = []
        for i in range(500):  # More than the 400 cap
            finding = MagicMock()
            finding.id = f"finding_{i}"
            finding.title = f"Finding {i}"
            finding.severity = "medium"
            finding.risk_total = 50
            finding.risk_score = 50
            finding.tags = []
            finding.baseline_status = "unknown"
            finding.probability_actionable = 0.5
            finding.rationale = []
            findings.append(finding)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Large findings test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = findings
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        # Should be capped at 400 findings
        assert "Findings (500)" in html_output  # Shows total count
        # But should only render up to the cap
        assert html_output.count("finding_") <= 400

    def test_render_with_malformed_compliance_data(self):
        """Test rendering with malformed compliance data."""
        # Compliance data with missing fields
        compliance_summary = {
            'incomplete_standard': {
                'passed': 5
                # Missing failed, not_applicable, total_controls, score
            }
        }

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "Malformed compliance test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {'compliance_summary': compliance_summary}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = []
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        # Should handle missing fields gracefully
        assert "incomplete_standard" in html_output
        assert "5" in html_output  # passed count should appear

    def test_render_with_special_characters(self):
        """Test rendering with special characters in content."""
        special_chars = "<>&\"'"
        findings = []

        finding = MagicMock()
        finding.id = f"special_{special_chars}"
        finding.title = f"Title with {special_chars}"
        finding.severity = "high"
        finding.risk_total = 70
        finding.risk_score = 70
        finding.tags = [f"tag{special_chars}"]
        finding.baseline_status = "new"
        finding.probability_actionable = 0.7
        finding.rationale = [f"Rationale with {special_chars}"]
        findings.append(finding)

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = f"Summary with {special_chars}"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = findings
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        # Special characters should be HTML escaped
        assert "&lt;" in html_output  # < should be escaped
        assert "&gt;" in html_output  # > should be escaped
        assert "&amp;" in html_output  # & should be escaped
        assert "&quot;" in html_output  # " should be escaped
        assert "&#x27;" in html_output  # ' should be escaped

    def test_render_with_none_risk_scores(self):
        """Test rendering when risk scores are None."""
        finding = MagicMock()
        finding.id = "no_risk_finding"
        finding.title = "Finding with no risk score"
        finding.severity = "medium"
        finding.risk_total = None
        finding.risk_score = None
        finding.tags = []
        finding.baseline_status = "unknown"
        finding.probability_actionable = None
        finding.rationale = []

        mock_summaries = MagicMock()
        mock_summaries.executive_summary = "None risk scores test"
        mock_summaries.attack_coverage = None
        mock_summaries.metrics = {}

        mock_output = MagicMock(spec=models.EnrichedOutput)
        mock_output.enriched_findings = [finding]
        mock_output.correlations = []
        mock_output.summaries = mock_summaries

        html_output = report_html.render(mock_output)

        # Should handle None values gracefully
        assert "no_risk_finding" in html_output
        assert "risk=None" in html_output  # Should show None for missing risk
        assert "prob=0.00" in html_output  # Should default to 0.00 for None probability