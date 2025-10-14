import pytest
from datetime import datetime, timezone
from unittest.mock import Mock
try:
    from sys_scan_agent import migration_v3
    from sys_scan_agent import models
    MIGRATION_AVAILABLE = True
except ImportError:
    MIGRATION_AVAILABLE = False
    migration_v3 = None
    models = None


@pytest.mark.skipif(not MIGRATION_AVAILABLE, reason="Migration modules not available")
class TestMigrationV3:
    """Test migration from schema v2 to FactPack v3 structure."""

    def test_finding_to_v3_complete_finding(self):
        """Test conversion of a complete finding to v3 format."""
        finding = Mock(spec=models.Finding)
        finding.id = "test-finding-1"
        finding.title = "Test Finding"
        finding.severity = "high"
        finding.risk_score = 85
        finding.description = "A test finding description"
        finding.category = "malware"
        finding.tags = ["trojan", "backdoor"]
        finding.risk_subscores = {"behavioral": 90, "signature": 80}
        finding.correlation_refs = ["corr-1", "corr-2"]
        finding.baseline_status = "new"
        finding.severity_source = "ml"
        finding.allowlist_reason = None
        finding.metadata = {"path": "/tmp/malware.exe", "size": 1024}

        result = migration_v3.finding_to_v3(finding)

        expected = {
            "id": "test-finding-1",
            "title": "Test Finding",
            "severity": "high",
            "risk_score": 85,
            "description": "A test finding description",
            "category": "malware",
            "tags": ["trojan", "backdoor"],
            "risk_subscores": {"behavioral": 90, "signature": 80},
            "correlation_refs": ["corr-1", "corr-2"],
            "baseline_status": "new",
            "severity_source": "ml",
            "allowlist_reason": None,
            "metadata": {"path": "/tmp/malware.exe", "size": 1024},
        }

        assert result == expected

    def test_finding_to_v3_minimal_finding(self):
        """Test conversion of a minimal finding with defaults."""
        finding = Mock(spec=models.Finding)
        finding.id = "minimal-finding"
        finding.title = "Minimal Finding"
        finding.severity = "low"
        finding.risk_score = 10
        finding.description = None
        finding.category = None
        finding.tags = []
        finding.risk_subscores = None
        finding.correlation_refs = []
        finding.baseline_status = None
        finding.severity_source = None
        finding.allowlist_reason = None
        finding.metadata = {}

        result = migration_v3.finding_to_v3(finding)

        expected = {
            "id": "minimal-finding",
            "title": "Minimal Finding",
            "severity": "low",
            "risk_score": 10,
            "description": "",
            "category": "other",  # CATEGORY_FALLBACK
            "tags": [],
            "risk_subscores": {},
            "correlation_refs": [],
            "baseline_status": "unknown",
            "severity_source": "raw",
            "allowlist_reason": None,
            "metadata": {},
        }

        assert result == expected

    def test_correlation_to_v3_complete_correlation(self):
        """Test conversion of a complete correlation to v3 format."""
        correlation = Mock(spec=models.Correlation)
        correlation.id = "corr-1"
        correlation.title = "Malware Correlation"
        correlation.rationale = "Multiple indicators suggest malware infection"
        correlation.related_finding_ids = ["finding-1", "finding-2", "finding-3"]
        correlation.risk_score_delta = 25
        correlation.tags = ["malware", "infection"]
        correlation.severity = "high"

        result = migration_v3.correlation_to_v3(correlation)

        expected = {
            "id": "corr-1",
            "title": "Malware Correlation",
            "rationale": "Multiple indicators suggest malware infection",
            "related_finding_ids": ["finding-1", "finding-2", "finding-3"],
            "risk_score_delta": 25,
            "tags": ["malware", "infection"],
            "severity": "high",
        }

        assert result == expected

    def test_correlation_to_v3_minimal_correlation(self):
        """Test conversion of a minimal correlation."""
        correlation = Mock(spec=models.Correlation)
        correlation.id = "corr-minimal"
        correlation.title = "Minimal Correlation"
        correlation.rationale = "Basic correlation"
        correlation.related_finding_ids = ["finding-1"]
        correlation.risk_score_delta = 5
        correlation.tags = []
        correlation.severity = "low"

        result = migration_v3.correlation_to_v3(correlation)

        expected = {
            "id": "corr-minimal",
            "title": "Minimal Correlation",
            "rationale": "Basic correlation",
            "related_finding_ids": ["finding-1"],
            "risk_score_delta": 5,
            "tags": [],
            "severity": "low",
        }

        assert result == expected

    def test_migrate_report_to_factpack_v3_complete_report(self):
        """Test migration of a complete report with findings and correlations."""
        # Create mock report
        report = Mock(spec=models.Report)
        report.meta = Mock(spec=models.Meta)
        report.meta.json_schema_version = "2.1"
        report.meta.host_id = "test-host-123"
        report.meta.scan_id = "scan-456"

        # Create mock result with findings
        result = Mock()
        finding1 = Mock(spec=models.Finding)
        finding1.id = "f1"
        finding1.title = "Finding 1"
        finding1.severity = "high"
        finding1.risk_score = 90
        finding1.description = "High risk finding"
        finding1.category = "malware"
        finding1.tags = ["trojan"]
        finding1.risk_subscores = {"behavioral": 95}
        finding1.correlation_refs = ["corr-1"]
        finding1.baseline_status = "new"
        finding1.severity_source = "ml"
        finding1.allowlist_reason = None
        finding1.metadata = {"path": "/tmp/bad.exe"}

        finding2 = Mock(spec=models.Finding)
        finding2.id = "f2"
        finding2.title = "Finding 2"
        finding2.severity = "medium"
        finding2.risk_score = 60
        finding2.description = "Medium risk finding"
        finding2.category = "suspicious"
        finding2.tags = ["suspicious"]
        finding2.risk_subscores = {}
        finding2.correlation_refs = []
        finding2.baseline_status = "unknown"
        finding2.severity_source = "raw"
        finding2.allowlist_reason = None
        finding2.metadata = {}

        result.findings = [finding1, finding2]
        report.results = [result]

        # Create mock correlation
        correlation = Mock(spec=models.Correlation)
        correlation.id = "corr-1"
        correlation.title = "Test Correlation"
        correlation.rationale = "Test rationale"
        correlation.related_finding_ids = ["f1"]
        correlation.risk_score_delta = 10
        correlation.tags = ["test"]
        correlation.severity = "high"

        correlations = [correlation]

        result = migration_v3.migrate_report_to_factpack_v3(report, correlations)

        # Check structure
        assert result["fact_pack_version"] == "3"
        assert result["source_schema"] == "2.1"
        assert result["host_id"] == "test-host-123"
        assert result["scan_id"] == "scan-456"
        assert result["finding_count"] == 2
        assert result["correlation_count"] == 1
        assert len(result["findings"]) == 2
        assert len(result["correlations"]) == 1

        # Check generated_at is recent timestamp
        generated_at = datetime.fromisoformat(result["generated_at"])
        now = datetime.now(timezone.utc)
        time_diff = abs((generated_at - now).total_seconds())
        assert time_diff < 10  # Within 10 seconds

        # Check findings structure
        assert result["findings"][0]["id"] == "f1"
        assert result["findings"][0]["title"] == "Finding 1"
        assert result["findings"][0]["severity"] == "high"
        assert result["findings"][0]["risk_score"] == 90

        assert result["findings"][1]["id"] == "f2"
        assert result["findings"][1]["title"] == "Finding 2"
        assert result["findings"][1]["severity"] == "medium"

        # Check correlations structure
        assert result["correlations"][0]["id"] == "corr-1"
        assert result["correlations"][0]["title"] == "Test Correlation"
        assert result["correlations"][0]["related_finding_ids"] == ["f1"]

    def test_migrate_report_to_factpack_v3_minimal_report(self):
        """Test migration of a minimal report with no findings or correlations."""
        # Create minimal mock report
        report = Mock(spec=models.Report)
        report.meta = Mock(spec=models.Meta)
        report.meta.json_schema_version = None
        report.meta.host_id = None
        report.meta.scan_id = None
        report.results = []

        result = migration_v3.migrate_report_to_factpack_v3(report, [])

        assert result["fact_pack_version"] == "3"
        assert result["source_schema"] == "2"  # default
        assert result["host_id"] == "unknown_host"  # default
        assert result["scan_id"] == "unknown_scan"  # default
        assert result["finding_count"] == 0
        assert result["correlation_count"] == 0
        assert result["findings"] == []
        assert result["correlations"] == []

        # Check timestamp
        generated_at = datetime.fromisoformat(result["generated_at"])
        now = datetime.now(timezone.utc)
        time_diff = abs((generated_at - now).total_seconds())
        assert time_diff < 10

    def test_migrate_report_to_factpack_v3_multiple_results(self):
        """Test migration when report has multiple result sections."""
        # Create report with multiple results
        report = Mock(spec=models.Report)
        report.meta = Mock(spec=models.Meta)
        report.meta.json_schema_version = "2.0"
        report.meta.host_id = "multi-host"
        report.meta.scan_id = "multi-scan"

        # Result 1
        result1 = Mock()
        finding1 = Mock(spec=models.Finding)
        finding1.id = "f1"
        finding1.title = "Finding 1"
        finding1.severity = "high"
        finding1.risk_score = 80
        finding1.description = "Description 1"
        finding1.category = "cat1"
        finding1.tags = []
        finding1.risk_subscores = None
        finding1.correlation_refs = []
        finding1.baseline_status = None
        finding1.severity_source = None
        finding1.allowlist_reason = None
        finding1.metadata = {}
        result1.findings = [finding1]

        # Result 2
        result2 = Mock()
        finding2 = Mock(spec=models.Finding)
        finding2.id = "f2"
        finding2.title = "Finding 2"
        finding2.severity = "low"
        finding2.risk_score = 20
        finding2.description = "Description 2"
        finding2.category = "cat2"
        finding2.tags = []
        finding2.risk_subscores = None
        finding2.correlation_refs = []
        finding2.baseline_status = None
        finding2.severity_source = None
        finding2.allowlist_reason = None
        finding2.metadata = {}
        result2.findings = [finding2]

        report.results = [result1, result2]

        result = migration_v3.migrate_report_to_factpack_v3(report, [])

        assert result["finding_count"] == 2
        assert len(result["findings"]) == 2
        assert result["findings"][0]["id"] == "f1"
        assert result["findings"][1]["id"] == "f2"