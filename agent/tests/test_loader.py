"""
Tests for loader.py data loading and validation module.
"""

from __future__ import annotations
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from sys_scan_agent.loader import (
    _read_and_validate_file_size, _decode_and_canonicalize_text,
    _parse_json_report, _normalize_risk_naming_migration,
    _normalize_finding_risk_fields, _validate_report_schema,
    load_report
)
from sys_scan_agent.models import AgentState


class TestReadAndValidateFileSize:
    """Test _read_and_validate_file_size function."""

    def test_read_valid_file_size(self, tmp_path):
        """Test reading a file within size limits."""
        test_file = tmp_path / "test.json"
        test_content = '{"test": "data"}'
        test_file.write_text(test_content)

        max_mb, raw_bytes = _read_and_validate_file_size(test_file)

        assert max_mb == 5  # default limit
        assert raw_bytes == test_content.encode('utf-8')

    def test_read_file_over_size_limit(self, tmp_path):
        """Test rejection of oversized files."""
        large_file = tmp_path / "large.json"
        # Create a file larger than 5MB
        large_data = {"test": "x" * (6 * 1024 * 1024)}  # ~6MB
        large_file.write_text(json.dumps(large_data))

        with pytest.raises(ValueError, match="Report size.*exceeds maximum"):
            _read_and_validate_file_size(large_file)

    def test_read_file_custom_size_limit(self, tmp_path, monkeypatch):
        """Test custom size limit via environment."""
        monkeypatch.setenv('AGENT_MAX_REPORT_MB', '1')  # 1MB limit

        large_file = tmp_path / "large.json"
        large_data = {"test": "x" * (2 * 1024 * 1024)}  # ~2MB
        large_file.write_text(json.dumps(large_data))

        with pytest.raises(ValueError, match="Report size.*exceeds maximum"):
            _read_and_validate_file_size(large_file)

    def test_read_file_invalid_size_env(self, tmp_path, monkeypatch):
        """Test invalid size environment variable defaults to 5MB."""
        monkeypatch.setenv('AGENT_MAX_REPORT_MB', 'invalid')

        large_file = tmp_path / "large.json"
        large_data = {"test": "x" * (6 * 1024 * 1024)}  # ~6MB
        large_file.write_text(json.dumps(large_data))

        with pytest.raises(ValueError, match="Report size.*exceeds maximum"):
            _read_and_validate_file_size(large_file)


class TestDecodeAndCanonicalizeText:
    """Test _decode_and_canonicalize_text function."""

    def test_decode_valid_utf8(self):
        """Test decoding valid UTF-8."""
        text = "Hello, 世界!"
        raw_bytes = text.encode('utf-8')

        result = _decode_and_canonicalize_text(raw_bytes)
        assert result == text

    def test_decode_invalid_utf8(self):
        """Test rejection of invalid UTF-8."""
        # Create invalid UTF-8 bytes
        raw_bytes = b'\xff\xfe'

        with pytest.raises(ValueError, match="not valid UTF-8"):
            _decode_and_canonicalize_text(raw_bytes)

    def test_canonicalize_newlines_crlf(self):
        """Test CRLF to LF canonicalization."""
        text_with_crlf = "line1\r\nline2\r\nline3"
        raw_bytes = text_with_crlf.encode('utf-8')

        result = _decode_and_canonicalize_text(raw_bytes)
        assert result == "line1\nline2\nline3"

    def test_canonicalize_newlines_cr(self):
        """Test CR to LF canonicalization."""
        text_with_cr = "line1\rline2\rline3"
        raw_bytes = text_with_cr.encode('utf-8')

        result = _decode_and_canonicalize_text(raw_bytes)
        assert result == "line1\nline2\nline3"

    def test_canonicalize_mixed_newlines(self):
        """Test mixed newline canonicalization."""
        text_mixed = "line1\r\nline2\rline3\nline4"
        raw_bytes = text_mixed.encode('utf-8')

        result = _decode_and_canonicalize_text(raw_bytes)
        assert result == "line1\nline2\nline3\nline4"


class TestParseJsonReport:
    """Test _parse_json_report function."""

    def test_parse_valid_json(self):
        """Test parsing valid JSON."""
        valid_json = '{"key": "value", "number": 42}'
        expected = {"key": "value", "number": 42}

        result = _parse_json_report(valid_json)
        assert result == expected

    def test_parse_invalid_json(self):
        """Test rejection of invalid JSON."""
        invalid_json = '{"key": "value", "missing": }'

        with pytest.raises(ValueError, match="JSON parse error"):
            _parse_json_report(invalid_json)


class TestNormalizeFindingRiskFields:
    """Test _normalize_finding_risk_fields function."""

    def test_normalize_legacy_risk_score(self):
        """Test migration from base_severity_score to risk_score."""
        finding = {"base_severity_score": 75}

        _normalize_finding_risk_fields(finding)

        assert finding["risk_score"] == 75
        assert finding["risk_total"] == 75

    def test_normalize_existing_risk_score(self):
        """Test when risk_score already exists."""
        finding = {"risk_score": 80, "base_severity_score": 75}

        _normalize_finding_risk_fields(finding)

        assert finding["risk_score"] == 80  # Should keep existing
        assert finding["risk_total"] == 80

    def test_normalize_invalid_base_severity_score(self):
        """Test invalid base_severity_score defaults to 0."""
        finding = {"base_severity_score": "invalid"}

        _normalize_finding_risk_fields(finding)

        assert finding["risk_score"] == 0
        assert finding["risk_total"] == 0

    def test_normalize_missing_risk_total(self):
        """Test adding risk_total when missing."""
        finding = {"risk_score": 60}

        _normalize_finding_risk_fields(finding)

        assert finding["risk_total"] == 60

    def test_normalize_complete_finding(self):
        """Test finding that already has all fields."""
        finding = {"risk_score": 70, "risk_total": 70, "base_severity_score": 65}

        _normalize_finding_risk_fields(finding)

        assert finding["risk_score"] == 70
        assert finding["risk_total"] == 70


class TestNormalizeRiskNamingMigration:
    """Test _normalize_risk_naming_migration function."""

    def test_normalize_valid_report_structure(self):
        """Test normalization of valid report structure."""
        report_data = {
            "results": [
                {
                    "findings": [
                        {"base_severity_score": 80},
                        {"risk_score": 70}
                    ]
                }
            ]
        }

        _normalize_risk_naming_migration(report_data)

        assert report_data["results"][0]["findings"][0]["risk_score"] == 80
        assert report_data["results"][0]["findings"][1]["risk_score"] == 70

    def test_normalize_invalid_report_structure(self):
        """Test normalization handles invalid structures gracefully."""
        # Test with non-dict data
        _normalize_risk_naming_migration("not a dict")

        # Test with missing results
        _normalize_risk_naming_migration({"other_key": "value"})

        # Test with invalid results
        _normalize_risk_naming_migration({"results": "not a list"})

        # Test with invalid findings
        _normalize_risk_naming_migration({"results": [{"findings": "not a list"}]})

        # Should not crash
        assert True


class TestValidateReportSchema:
    """Test _validate_report_schema function."""

    def test_validate_valid_schema(self):
        """Test validation of valid report schema."""
        valid_report = {
            "meta": {"hostname": "test-host"},
            "summary": {"finding_count_total": 1, "finding_count_emitted": 1},
            "results": [
                {
                    "scanner": "test",
                    "finding_count": 1,
                    "findings": [
                        {
                            "id": "f1",
                            "title": "Test finding",
                            "severity": "medium",
                            "risk_score": 50
                        }
                    ]
                }
            ],
            "collection_warnings": [],
            "scanner_errors": [],
            "summary_extension": {"total_risk_score": 50, "emitted_risk_score": 50}
        }

        result = _validate_report_schema(valid_report)

        assert result.meta.hostname == "test-host"
        assert len(result.results) == 1

    def test_validate_invalid_schema(self):
        """Test rejection of invalid schema."""
        invalid_report = {"invalid": "structure"}

        with pytest.raises(ValueError, match="schema validation failed"):
            _validate_report_schema(invalid_report)


class TestLoadReport:
    """Test load_report function."""

    def test_load_report_success(self, tmp_path):
        """Test successful report loading."""
        report_data = {
            "meta": {"hostname": "test-host"},
            "summary": {"finding_count_total": 1, "finding_count_emitted": 1},
            "results": [
                {
                    "scanner": "test",
                    "finding_count": 1,
                    "findings": [
                        {
                            "id": "f1",
                            "title": "Test finding",
                            "severity": "medium",
                            "risk_score": 50
                        }
                    ]
                }
            ],
            "collection_warnings": [],
            "scanner_errors": [],
            "summary_extension": {"total_risk_score": 50, "emitted_risk_score": 50}
        }

        report_file = tmp_path / "test_report.json"
        report_file.write_text(json.dumps(report_data))

        state = AgentState()
        result_state = load_report(state, report_file)

        # raw_report gets modified in place during normalization, so check key fields
        assert result_state.raw_report["meta"]["hostname"] == "test-host"
        assert result_state.report.meta.hostname == "test-host"
        assert len(result_state.report.results) == 1

    def test_load_report_with_legacy_fields(self, tmp_path):
        """Test loading report with legacy risk fields."""
        report_data = {
            "meta": {"hostname": "test-host"},
            "summary": {"finding_count_total": 1, "finding_count_emitted": 1},
            "results": [
                {
                    "scanner": "test",
                    "finding_count": 1,
                    "findings": [
                        {
                            "id": "f1",
                            "title": "Test finding",
                            "severity": "medium",
                            "base_severity_score": 75  # Legacy field
                        }
                    ]
                }
            ],
            "collection_warnings": [],
            "scanner_errors": [],
            "summary_extension": {"total_risk_score": 75, "emitted_risk_score": 75}
        }

        report_file = tmp_path / "legacy_report.json"
        report_file.write_text(json.dumps(report_data))

        state = AgentState()
        result_state = load_report(state, report_file)

        # Should have migrated base_severity_score to risk_score
        finding = result_state.report.results[0].findings[0]
        assert finding.risk_score == 75
        assert finding.risk_total == 75

    def test_load_report_file_too_large(self, tmp_path):
        """Test rejection of oversized reports."""
        large_file = tmp_path / "large.json"
        large_data = {"test": "x" * (6 * 1024 * 1024)}  # ~6MB
        large_file.write_text(json.dumps(large_data))

        state = AgentState()
        with pytest.raises(ValueError, match="Report size.*exceeds maximum"):
            load_report(state, large_file)

    def test_load_report_invalid_utf8(self, tmp_path):
        """Test rejection of invalid UTF-8."""
        invalid_file = tmp_path / "invalid.json"
        with open(invalid_file, 'wb') as f:
            f.write(b'{"test": "\xff\xfe"}')  # Invalid UTF-8

        state = AgentState()
        with pytest.raises(ValueError, match="not valid UTF-8"):
            load_report(state, invalid_file)

    def test_load_report_invalid_json(self, tmp_path):
        """Test rejection of invalid JSON."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text('{"invalid": json}')

        state = AgentState()
        with pytest.raises(ValueError, match="JSON parse error"):
            load_report(state, invalid_file)

    def test_load_report_invalid_schema(self, tmp_path):
        """Test rejection of invalid schema."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text('{"completely": "wrong"}')

        state = AgentState()
        with pytest.raises(ValueError, match="schema validation failed"):
            load_report(state, invalid_file)