"""
Data loading and validation module for the security scanning pipeline.

This module handles file I/O, parsing, and migrations for loading security reports.
"""

from __future__ import annotations
import json, hashlib
from pathlib import Path
import os
from typing import TYPE_CHECKING

from . import models

# Re-export for backward compatibility
AgentState = models.AgentState
Report = models.Report
Finding = models.Finding
ScannerResult = models.ScannerResult


def _read_and_validate_file_size(path: Path) -> tuple[int, bytes]:
    """Read file bytes and validate size against maximum limit."""
    max_mb_env = os.environ.get('AGENT_MAX_REPORT_MB')
    try:
        max_mb = int(max_mb_env) if max_mb_env else 5
    except ValueError:
        max_mb = 5

    from . import metrics
    mc = metrics.get_metrics_collector()
    with mc.time_stage('load_report.read_bytes'):
        raw_bytes = Path(path).read_bytes()

    size_mb = len(raw_bytes) / (1024 * 1024)
    if size_mb > max_mb:
        raise ValueError(f"Report size {size_mb:.2f} MB exceeds maximum size {max_mb} MB")

    return max_mb, raw_bytes


def _decode_and_canonicalize_text(raw_bytes: bytes) -> str:
    """Decode bytes as UTF-8 and canonicalize newlines."""
    try:
        text = raw_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError as e:
        raise ValueError(f"Report is not valid UTF-8: {e}") from e

    # Canonicalize newlines (CRLF, CR -> LF)
    if '\r' in text:
        text = text.replace('\r\n', '\n').replace('\r', '\n')

    return text


def _parse_json_report(text: str) -> dict:
    """Parse the canonicalized text as JSON."""
    try:
        from . import metrics
        mc = metrics.get_metrics_collector()
        with mc.time_stage('load_report.json_parse'):
            data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Report JSON parse error: {e}") from e
    return data


def _normalize_risk_naming_migration(data: dict) -> None:
    """Normalize risk naming migration from base_severity_score to risk_score."""
    try:
        results = data.get('results') if isinstance(data, dict) else None
        if isinstance(results, list):
            for sr in results:
                findings = sr.get('findings') if isinstance(sr, dict) else None
                if not isinstance(findings, list):
                    continue
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    _normalize_finding_risk_fields(f)
    except Exception as norm_e:
        # Non-fatal; proceed to validation which may still fail with clearer message.
        try:
            from . import audit
            audit.log_stage('load_report.normalization_warning', error=str(norm_e), type=type(norm_e).__name__)
        except Exception:
            pass


def _normalize_finding_risk_fields(f: dict) -> None:
    """Normalize risk_score and risk_total fields for a single finding."""
    # If legacy risk_score missing but new base_severity_score present, copy.
    if 'risk_score' not in f and 'base_severity_score' in f:
        try:
            f['risk_score'] = int(f.get('base_severity_score') or 0)
        except (TypeError, ValueError):
            f['risk_score'] = 0
    # If both present but divergent (shouldn't happen), prefer explicit risk_score and log later.
    # risk_total duplication if absent
    if 'risk_total' not in f and 'risk_score' in f:
        f['risk_total'] = f['risk_score']


def _validate_report_schema(data: dict) -> Report:
    """Validate the report data against the schema."""
    try:
        from . import metrics
        mc = metrics.get_metrics_collector()
        with mc.time_stage('load_report.validate'):
            report = Report.model_validate(data)
    except Exception as e:
        raise ValueError(f"Report schema validation failed: {e}") from e
    return report


def load_report(state: AgentState, path: Path) -> AgentState:
    """Securely load and parse the raw JSON report.

    Hardening steps:
    1. Enforce maximum size (default 5 MB, override via AGENT_MAX_REPORT_MB env).
    2. Read bytes then decode strictly as UTF-8 (reject invalid sequences).
    3. Canonicalize newlines to '\n' before JSON parsing to avoid platform variance.
    """
    # Read and validate file size
    max_mb, raw_bytes = _read_and_validate_file_size(path)

    # Decode and canonicalize text
    text = _decode_and_canonicalize_text(raw_bytes)

    # Parse JSON
    data = _parse_json_report(text)

    # Store raw report
    state.raw_report = data

    # Normalize risk naming migration
    _normalize_risk_naming_migration(data)

    # Validate schema
    state.report = _validate_report_schema(data)

    return state