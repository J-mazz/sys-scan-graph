"""Tests for graph_analysis.py - correlation graph analysis utilities."""
from unittest.mock import MagicMock
import pytest

from sys_scan_agent import graph_analysis
from sys_scan_agent.models import AgentState, Finding, Correlation, Report, ScannerResult, Meta, Summary, SummaryExtension


class TestGraphAnalysis:
    """Test correlation graph analysis utilities."""

    def test_build_bipartite_empty_state(self):
        """Test bipartite graph building with empty state."""
        state = AgentState()
        f2c, c2f = graph_analysis.build_bipartite(state)

        assert f2c == {}
        assert c2f == {}

    def test_build_bipartite_single_correlation(self):
        """Test bipartite graph building with single correlation."""
        finding1 = Finding(id="f1", title="Finding 1", severity="high", risk_score=80)
        finding2 = Finding(id="f2", title="Finding 2", severity="medium", risk_score=50)

        correlation = Correlation(
            id="c1",
            title="Similar pattern correlation",
            rationale="Findings share similar patterns",
            related_finding_ids=["f1", "f2"]
        )

        scanner_result = ScannerResult(
            scanner="test_scanner",
            finding_count=2,
            findings=[finding1, finding2]
        )

        report = Report(
            meta=Meta(),
            summary=Summary(),
            results=[scanner_result],
            summary_extension=SummaryExtension(total_risk_score=130)
        )

        state = AgentState(
            correlations=[correlation],
            report=report
        )

        f2c, c2f = graph_analysis.build_bipartite(state)

        assert f2c == {"f1": {"c1"}, "f2": {"c1"}}
        assert c2f == {"c1": {"f1", "f2"}}

    def test_build_bipartite_multiple_correlations(self):
        """Test bipartite graph building with multiple correlations."""
        finding1 = Finding(id="f1", title="Finding 1", severity="high", risk_score=80)
        finding2 = Finding(id="f2", title="Finding 2", severity="medium", risk_score=50)
        finding3 = Finding(id="f3", title="Finding 3", severity="low", risk_score=20)

        correlation1 = Correlation(
            id="c1",
            title="Similar pattern correlation",
            rationale="Findings share similar patterns",
            related_finding_ids=["f1", "f2"]
        )
        correlation2 = Correlation(
            id="c2",
            title="Causal link correlation",
            rationale="Findings are causally linked",
            related_finding_ids=["f2", "f3"]
        )

        scanner_result = ScannerResult(
            scanner="test_scanner",
            finding_count=3,
            findings=[finding1, finding2, finding3]
        )

        report = Report(
            meta=Meta(),
            summary=Summary(),
            results=[scanner_result],
            summary_extension=SummaryExtension(total_risk_score=150)
        )

        state = AgentState(
            correlations=[correlation1, correlation2],
            report=report
        )

        f2c, c2f = graph_analysis.build_bipartite(state)

        assert f2c == {"f1": {"c1"}, "f2": {"c1", "c2"}, "f3": {"c2"}}
        assert c2f == {"c1": {"f1", "f2"}, "c2": {"f2", "f3"}}

    def test_connected_components_empty_graphs(self):
        """Test connected components with empty graphs."""
        f2c = {}
        c2f = {}
        components = graph_analysis.connected_components(f2c, c2f)

        assert components == []

    def test_connected_components_single_component(self):
        """Test connected components with single component."""
        f2c = {"f1": {"c1"}, "f2": {"c1"}}
        c2f = {"c1": {"f1", "f2"}}
        components = graph_analysis.connected_components(f2c, c2f)

        assert len(components) == 1
        findings, correlations = components[0]
        assert findings == {"f1", "f2"}
        assert correlations == {"c1"}

    def test_connected_components_multiple_components(self):
        """Test connected components with multiple separate components."""
        f2c = {"f1": {"c1"}, "f2": {"c1"}, "f3": {"c2"}}
        c2f = {"c1": {"f1", "f2"}, "c2": {"f3"}}
        components = graph_analysis.connected_components(f2c, c2f)

        assert len(components) == 2

        # Sort components by finding set size for consistent testing
        components.sort(key=lambda x: len(x[0]))

        # First component: f3 -> c2
        findings1, correlations1 = components[0]
        assert findings1 == {"f3"}
        assert correlations1 == {"c2"}

        # Second component: f1, f2 -> c1
        findings2, correlations2 = components[1]
        assert findings2 == {"f1", "f2"}
        assert correlations2 == {"c1"}

    def test_connected_components_isolated_correlation(self):
        """Test connected components with isolated correlation (no findings)."""
        f2c = {"f1": {"c1"}}
        c2f = {"c1": {"f1"}, "c2": set()}  # c2 has no findings
        components = graph_analysis.connected_components(f2c, c2f)

        assert len(components) == 2

        # Sort by correlation set size
        components.sort(key=lambda x: len(x[1]))

        # First component: f1 -> c1
        findings1, correlations1 = components[0]
        assert findings1 == {"f1"}
        assert correlations1 == {"c1"}

        # Second component: isolated correlation c2
        findings2, correlations2 = components[1]
        assert findings2 == set()
        assert correlations2 == {"c2"}

    def test_annotate_and_summarize_no_report(self):
        """Test annotate_and_summarize with state that has no report."""
        state = AgentState(correlations=[])
        # Explicitly set report to None
        state.report = None
        
        result = graph_analysis.annotate_and_summarize(state)
        assert result == {}

    def test_annotate_and_summarize_with_data(self):
        """Test annotate_and_summarize with correlation data."""
        # Create test findings
        finding1 = Finding(id="f1", title="High risk finding", severity="high", risk_score=80)
        finding2 = Finding(id="f2", title="Medium risk finding", severity="medium", risk_score=50)
        finding3 = Finding(id="f3", title="Low risk finding", severity="low", risk_score=20)

        # Create correlations
        correlation1 = Correlation(
            id="c1",
            title="Similar pattern correlation",
            rationale="Findings share similar patterns",
            related_finding_ids=["f1", "f2"]
        )

        # Create report with findings
        scanner_result = ScannerResult(
            scanner="test_scanner",
            finding_count=3,
            findings=[finding1, finding2, finding3]
        )

        report = Report(
            meta=Meta(),
            summary=Summary(),
            results=[scanner_result],
            summary_extension=SummaryExtension(total_risk_score=150)
        )

        state = AgentState(
            correlations=[correlation1],
            report=report
        )

        result = graph_analysis.annotate_and_summarize(state)

        # Check basic structure
        assert "finding_degrees" in result
        assert "clusters" in result
        assert "top_clusters" in result

        # Check finding degrees
        assert result["finding_degrees"] == {"f1": 1, "f2": 1}

        # Check clusters
        assert len(result["clusters"]) == 1
        cluster = result["clusters"][0]
        assert cluster["cluster_id"] == 1
        assert cluster["finding_count"] == 2
        assert cluster["correlation_count"] == 1
        assert set(cluster["finding_ids"]) == {"f1", "f2"}
        assert cluster["correlation_ids"] == ["c1"]
        assert cluster["total_risk_score"] == 130  # 80 + 50
        assert cluster["hub_finding_id"] in ["f1", "f2"]  # Either can be hub when degrees are equal
        assert cluster["hub_degree"] == 1

        # Check top clusters (should be the same as clusters since only one)
        assert len(result["top_clusters"]) == 1
        top_cluster = result["top_clusters"][0]
        assert top_cluster["cluster_id"] == 1
        assert top_cluster["total_risk_score"] == 130
        assert top_cluster["finding_count"] == 2
        assert top_cluster["correlation_count"] == 1
        assert top_cluster["hub_finding_id"] in ["f1", "f2"]
        assert top_cluster["hub_finding_title"] in ["High risk finding", "Medium risk finding"]

    def test_annotate_and_summarize_multiple_clusters(self):
        """Test annotate_and_summarize with multiple clusters."""
        # Create test findings
        finding1 = Finding(id="f1", title="Finding 1", severity="high", risk_score=80)
        finding2 = Finding(id="f2", title="Finding 2", severity="medium", risk_score=50)
        finding3 = Finding(id="f3", title="Finding 3", severity="low", risk_score=20)
        finding4 = Finding(id="f4", title="Finding 4", severity="high", risk_score=90)

        # Create correlations creating two separate clusters
        correlation1 = Correlation(
            id="c1",
            title="Similar pattern correlation",
            rationale="Findings share similar patterns",
            related_finding_ids=["f1", "f2"]
        )
        correlation2 = Correlation(
            id="c2",
            title="Causal link correlation",
            rationale="Findings are causally linked",
            related_finding_ids=["f3", "f4"]
        )

        # Create report with findings
        scanner_result = ScannerResult(
            scanner="test_scanner",
            finding_count=4,
            findings=[finding1, finding2, finding3, finding4]
        )

        report = Report(
            meta=Meta(),
            summary=Summary(),
            results=[scanner_result],
            summary_extension=SummaryExtension(total_risk_score=240)
        )

        state = AgentState(
            correlations=[correlation1, correlation2],
            report=report
        )

        result = graph_analysis.annotate_and_summarize(state)

        # Should have 2 clusters
        assert len(result["clusters"]) == 2
        assert len(result["top_clusters"]) == 2  # Top 5, but only 2 exist

        # Check that clusters are sorted by total risk (highest first)
        top_clusters = result["top_clusters"]
        assert top_clusters[0]["total_risk_score"] >= top_clusters[1]["total_risk_score"]

        # Verify cluster IDs are assigned sequentially
        cluster_ids = [c["cluster_id"] for c in result["clusters"]]
        assert sorted(cluster_ids) == [1, 2]

    def test_annotate_and_summarize_finding_annotations(self):
        """Test that findings get proper cluster_id and graph_degree annotations."""
        # Create test findings
        finding1 = Finding(id="f1", title="Finding 1", severity="high", risk_score=80)
        finding2 = Finding(id="f2", title="Finding 2", severity="medium", risk_score=50)

        # Create correlation
        correlation1 = Correlation(
            id="c1",
            title="Similar pattern correlation",
            rationale="Findings share similar patterns",
            related_finding_ids=["f1", "f2"]
        )

        # Create report with findings
        scanner_result = ScannerResult(
            scanner="test_scanner",
            finding_count=2,
            findings=[finding1, finding2]
        )

        report = Report(
            meta=Meta(),
            summary=Summary(),
            results=[scanner_result],
            summary_extension=SummaryExtension(total_risk_score=130)
        )

        state = AgentState(
            correlations=[correlation1],
            report=report
        )

        result = graph_analysis.annotate_and_summarize(state)

        # Check that findings were annotated
        assert finding1.cluster_id == 1
        assert finding2.cluster_id == 1
        assert finding1.graph_degree == 1
        assert finding2.graph_degree == 1

    def test_connected_components_finding_visited_twice(self):
        """Test connected components where a finding gets added to stack multiple times."""
        # Create a scenario where f2 can be reached through multiple correlations
        # f1 -> c1 -> f2 and f1 -> c2 -> f2, so f2 gets added to stack twice
        f2c = {"f1": {"c1", "c2"}, "f2": {"c1", "c2"}}
        c2f = {"c1": {"f1", "f2"}, "c2": {"f1", "f2"}}
        components = graph_analysis.connected_components(f2c, c2f)

        assert len(components) == 1
        findings, correlations = components[0]
        assert findings == {"f1", "f2"}
        assert correlations == {"c1", "c2"}

    def test_annotate_and_summarize_missing_finding_object(self):
        """Test annotate_and_summarize when correlation references non-existent finding."""
        # Create findings that exist in report
        finding1 = Finding(id="f1", title="Finding 1", severity="high", risk_score=80)

        # Create correlation that references both existing and non-existing findings
        correlation1 = Correlation(
            id="c1",
            title="Correlation with missing finding",
            rationale="References missing finding",
            related_finding_ids=["f1", "f2"]  # f2 doesn't exist in report
        )

        # Create report with only f1
        scanner_result = ScannerResult(
            scanner="test_scanner",
            finding_count=1,
            findings=[finding1]
        )

        report = Report(
            meta=Meta(),
            summary=Summary(),
            results=[scanner_result],
            summary_extension=SummaryExtension(total_risk_score=80)
        )

        state = AgentState(
            correlations=[correlation1],
            report=report
        )

        result = graph_analysis.annotate_and_summarize(state)

        # Should still work, but f2 should be ignored in risk calculation
        assert len(result["clusters"]) == 1
        cluster = result["clusters"][0]
        assert cluster["finding_count"] == 1  # Only f1
        assert cluster["total_risk_score"] == 80  # Only f1's risk
        assert cluster["finding_ids"] == ["f1"]