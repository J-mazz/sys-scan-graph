"""Tests for report_diff module."""
import pytest
from pathlib import Path
import tempfile
from sys_scan_agent import report_diff, models


def _create_enriched_output(**kwargs):
    """Helper to create EnrichedOutput with required fields."""
    defaults = {
        'correlations': [],
        'reductions': {},
        'summaries': models.Summaries(),
        'actions': [],
        'enriched_findings': []
    }
    defaults.update(kwargs)
    return models.EnrichedOutput(**defaults)


class TestFindingIndex:
    """Tests for _finding_index helper function."""

    def test_finding_index_empty(self):
        """Test _finding_index with no findings."""
        output = _create_enriched_output(enriched_findings=[])
        idx = report_diff._finding_index(output)
        assert idx == {}

    def test_finding_index_single(self):
        """Test _finding_index with single finding."""
        finding = models.Finding(
            id="f1",
            title="Test Finding",
            severity="high",
            risk_score=50
        )
        output = _create_enriched_output(enriched_findings=[finding])
        idx = report_diff._finding_index(output)
        assert len(idx) == 1
        assert idx["f1"] == finding

    def test_finding_index_multiple(self):
        """Test _finding_index with multiple findings."""
        findings = [
            models.Finding(id=f"f{i}", title=f"Finding {i}", severity="high", risk_score=50)
            for i in range(5)
        ]
        output = _create_enriched_output(enriched_findings=findings)
        idx = report_diff._finding_index(output)
        assert len(idx) == 5
        for i, f in enumerate(findings):
            assert idx[f"f{i}"] == f

    def test_finding_index_none_findings(self):
        """Test _finding_index with None enriched_findings."""
        output = _create_enriched_output(enriched_findings=None)
        idx = report_diff._finding_index(output)
        assert idx == {}


class TestRiskBucket:
    """Tests for risk_bucket helper function."""

    def test_risk_bucket_none(self):
        """Test risk bucket for None value."""
        assert report_diff.risk_bucket(None) == 'none'

    def test_risk_bucket_critical(self):
        """Test risk bucket for critical range."""
        assert report_diff.risk_bucket(80) == 'critical'
        assert report_diff.risk_bucket(90) == 'critical'
        assert report_diff.risk_bucket(100) == 'critical'

    def test_risk_bucket_high(self):
        """Test risk bucket for high range."""
        assert report_diff.risk_bucket(60) == 'high'
        assert report_diff.risk_bucket(70) == 'high'
        assert report_diff.risk_bucket(79) == 'high'

    def test_risk_bucket_medium(self):
        """Test risk bucket for medium range."""
        assert report_diff.risk_bucket(40) == 'medium'
        assert report_diff.risk_bucket(50) == 'medium'
        assert report_diff.risk_bucket(59) == 'medium'

    def test_risk_bucket_low(self):
        """Test risk bucket for low range."""
        assert report_diff.risk_bucket(20) == 'low'
        assert report_diff.risk_bucket(30) == 'low'
        assert report_diff.risk_bucket(39) == 'low'

    def test_risk_bucket_info(self):
        """Test risk bucket for info range."""
        assert report_diff.risk_bucket(0) == 'info'
        assert report_diff.risk_bucket(10) == 'info'
        assert report_diff.risk_bucket(19) == 'info'


class TestBuildDiff:
    """Tests for build_diff function."""

    def test_build_diff_empty_reports(self):
        """Test build_diff with empty reports."""
        prev = _create_enriched_output(enriched_findings=[])
        curr = _create_enriched_output(enriched_findings=[])
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 0" in diff
        assert "Removed findings: 0" in diff
        assert "Risk changes: 0" in diff

    def test_build_diff_added_findings(self):
        """Test build_diff with added findings."""
        prev = _create_enriched_output(enriched_findings=[])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="New Finding",
                severity="high",
                risk_score=75
            )
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 1" in diff
        assert "Removed findings: 0" in diff
        assert "f1" in diff
        assert "New Finding" in diff

    def test_build_diff_removed_findings(self):
        """Test build_diff with removed findings."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Old Finding",
                severity="high",
                risk_score=75
            )
        ])
        curr = _create_enriched_output(enriched_findings=[])
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 0" in diff
        assert "Removed findings: 1" in diff
        assert "f1" in diff
        assert "Old Finding" in diff

    def test_build_diff_risk_changed(self):
        """Test build_diff with risk score changes."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Finding",
                severity="high",
                risk_score=50
            )
        ])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Finding",
                severity="high",
                risk_score=75
            )
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 0" in diff
        assert "Removed findings: 0" in diff
        assert "Risk changes: 1" in diff
        assert "+25.0" in diff or "Δ 25.0" in diff

    def test_build_diff_risk_total_vs_risk_score(self):
        """Test build_diff prefers risk_total over risk_score."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Finding",
                severity="high",
                risk_score=50,
                risk_total=60
            )
        ])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Finding",
                severity="high",
                risk_score=50,
                risk_total=80
            )
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Risk changes: 1" in diff
        assert "+20.0" in diff or "Δ 20.0" in diff

    def test_build_diff_no_risk_change(self):
        """Test build_diff with no risk change."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Finding",
                severity="high",
                risk_score=75
            )
        ])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(
                id="f1",
                title="Finding",
                severity="high",
                risk_score=75
            )
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Risk changes: 0" in diff

    def test_build_diff_multiple_changes(self):
        """Test build_diff with multiple types of changes."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(id="f1", title="Old", severity="high", risk_score=50),
            models.Finding(id="f2", title="Changed", severity="high", risk_score=30),
        ])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(id="f2", title="Changed", severity="high", risk_score=70),
            models.Finding(id="f3", title="New", severity="high", risk_score=60),
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 1" in diff
        assert "Removed findings: 1" in diff
        assert "Risk changes: 1" in diff
        assert "f1" in diff  # removed
        assert "f2" in diff  # changed
        assert "f3" in diff  # added

    def test_build_diff_probability_actionable(self):
        """Test build_diff includes probability_actionable delta."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(id="f1", title="F1", severity="high", risk_score=50, probability_actionable=0.5),
            models.Finding(id="f2", title="F2", severity="high", risk_score=50, probability_actionable=0.7),
        ])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(id="f1", title="F1", severity="high", risk_score=50, probability_actionable=0.8),
            models.Finding(id="f2", title="F2", severity="high", risk_score=50, probability_actionable=0.9),
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Probability Actionable Delta" in diff
        assert "Prev avg: 0.600" in diff
        assert "Curr avg: 0.850" in diff
        assert "+0.250" in diff or "Δ=+0.250" in diff

    def test_build_diff_large_number_of_findings(self):
        """Test build_diff with more than 50 findings (tests truncation)."""
        prev_findings = [
            models.Finding(id=f"f{i}", title=f"Finding {i}", severity="high", risk_score=i)
            for i in range(60)
        ]
        curr_findings = [
            models.Finding(id=f"f{i+100}", title=f"New Finding {i}", severity="high", risk_score=i)
            for i in range(60)
        ]
        prev = _create_enriched_output(enriched_findings=prev_findings)
        curr = _create_enriched_output(enriched_findings=curr_findings)
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 60" in diff
        assert "Removed findings: 60" in diff

    def test_build_diff_none_enriched_findings(self):
        """Test build_diff with None enriched_findings."""
        prev = _create_enriched_output(enriched_findings=None)
        curr = _create_enriched_output(enriched_findings=None)
        diff = report_diff.build_diff(prev, curr)

        assert "Added findings: 0" in diff
        assert "Removed findings: 0" in diff

    def test_build_diff_risk_decrease(self):
        """Test build_diff with risk score decrease."""
        prev = _create_enriched_output(enriched_findings=[
            models.Finding(id="f1", title="Finding", severity="high", risk_score=80)
        ])
        curr = _create_enriched_output(enriched_findings=[
            models.Finding(id="f1", title="Finding", severity="high", risk_score=40)
        ])
        diff = report_diff.build_diff(prev, curr)

        assert "Risk changes: 1" in diff
        assert "-40.0" in diff or "Δ -40.0" in diff


class TestWriteDiff:
    """Tests for write_diff function."""

    def test_write_diff_creates_file(self):
        """Test write_diff creates a file with diff content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "diff.md"
            prev = _create_enriched_output(enriched_findings=[])
            curr = _create_enriched_output(enriched_findings=[
                models.Finding(id="f1", title="New", severity="high", risk_score=50)
            ])

            result = report_diff.write_diff(prev, curr, output_path)

            assert result == output_path
            assert output_path.exists()
            content = output_path.read_text(encoding='utf-8')
            assert "Added findings: 1" in content
            assert "f1" in content

    def test_write_diff_overwrites_existing(self):
        """Test write_diff overwrites existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "diff.md"
            output_path.write_text("old content", encoding='utf-8')

            prev = _create_enriched_output(enriched_findings=[])
            curr = _create_enriched_output(enriched_findings=[])

            report_diff.write_diff(prev, curr, output_path)

            content = output_path.read_text(encoding='utf-8')
            assert "old content" not in content
            assert "# Enriched Report Diff" in content
