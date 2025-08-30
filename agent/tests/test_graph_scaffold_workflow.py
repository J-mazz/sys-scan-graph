from __future__ import annotations
"""Integration smoke test for scaffold graph workflow.

Validates that when the LangGraph app is available, a simple state with
raw findings passes through enrich -> correlate -> summarize -> suggest_rules
producing expected keys without raising exceptions.

Falls back to directly invoking the scaffold functions if the compiled
graph `app` is not present (e.g., langgraph not installed in minimal env).
"""

import os
import pytest

from typing import Dict, Any

try:
    from agent.graph import app  # type: ignore
except Exception:  # pragma: no cover
    app = None  # type: ignore

# Import scaffold nodes explicitly for fallback/manual execution
from agent.graph_nodes_scaffold import (
    enrich_findings,
    correlate_findings,
    summarize_host_state,
    suggest_rules,
)


@pytest.mark.parametrize(
    "raw_findings",
    [
        [
            {
                "id": "f1",
                "title": "Suspicious SUID binary",
                "severity": "high",
                "risk_score": 50,
                "metadata": {"path": "/usr/local/bin/suspicious"},
                "tags": ["suid", "baseline:new"],
            },
            {
                "id": "f2",
                "title": "Enable IP forwarding",
                "severity": "medium",
                "risk_score": 20,
                "metadata": {"sysctl_key": "net.ipv4.ip_forward", "value": "1"},
                "tags": ["kernel_param"],
            },
        ]
    ],
)
def test_scaffold_workflow_smoke(raw_findings):
    state: Dict[str, Any] = {"raw_findings": raw_findings}

    # Prefer running through compiled graph app if available
    if app is not None:  # pragma: no branch
        # LangGraph app expects an input dict; run until END
        result = app.invoke(state)
    else:
        # Manual sequential execution mimicking graph edges
        result = enrich_findings(state)
        if callable(correlate_findings):  # type: ignore
            result = correlate_findings(result)
        result = summarize_host_state(result)
        result = suggest_rules(result)

    # Basic assertions on presence and structure
    assert "enriched_findings" in result and result["enriched_findings"], "Enrichment produced no findings"
    # Correlation is optional but if correlations present, ensure refs exist
    if result.get("correlations"):
        # Each correlation should have an id and at least one related finding id
        for c in result["correlations"]:
            assert c.get("id"), "Correlation missing id"
        # Check that at least one enriched finding has a correlation ref
        assert any(f.get("correlation_refs") for f in result.get("correlated_findings", result["enriched_findings"]))
    # Summary may be absent if summarizer iteration capped, but should appear in normal flow
    assert "summary" in result, "Summary missing from state"
    # Suggested rules list (may be empty, but key should exist)
    assert "suggested_rules" in result, "Suggested rules key missing"

    # Ensure no unexpected warnings escalated to errors (warnings list may exist)
    if result.get("warnings"):
        # Allow presence but ensure structure
        for w in result["warnings"]:
            assert isinstance(w, dict), "Warning entries should be dicts"
