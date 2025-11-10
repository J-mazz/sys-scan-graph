"""Test determinism and canonicalization of enriched output."""

import json
import pytest
from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict


def test_canonicalize_enriched_output_dict():
    """Test that canonicalization produces deterministic output ordering."""
    # Test data with intentionally unsorted elements
    test_data = {
        "correlations": [
            {"id": "corr_b", "title": "Correlation B", "related_finding_ids": ["f2", "f1"]},
            {"id": "corr_a", "title": "Correlation A", "related_finding_ids": ["f1", "f3"]},
        ],
        "actions": [
            {"priority": 1, "action": "Low priority action"},
            {"priority": 3, "action": "High priority action"},
            {"priority": 2, "action": "Medium priority action"},
        ],
        "followups": [
            {"finding_id": "f2", "action": "Follow up 2"},
            {"finding_id": "f1", "action": "Follow up 1"},
        ],
        "multi_host_correlation": [
            {"key": "host_b", "correlation": "Host B correlation"},
            {"key": "host_a", "correlation": "Host A correlation"},
        ],
        "other_field": "unchanged_value"
    }

    # Canonicalize the data
    result = canonicalize_enriched_output_dict(test_data)

    # Verify correlations are sorted by id
    assert result["correlations"][0]["id"] == "corr_a"
    assert result["correlations"][1]["id"] == "corr_b"

    # Verify actions are sorted by priority (descending)
    assert result["actions"][0]["priority"] == 3
    assert result["actions"][1]["priority"] == 2
    assert result["actions"][2]["priority"] == 1

    # Verify followups are sorted by finding_id
    assert result["followups"][0]["finding_id"] == "f1"
    assert result["followups"][1]["finding_id"] == "f2"

    # Verify multi_host_correlation is sorted by key
    assert result["multi_host_correlation"][0]["key"] == "host_a"
    assert result["multi_host_correlation"][1]["key"] == "host_b"

    # Verify other fields are unchanged
    assert result["other_field"] == "unchanged_value"


def test_canonicalize_enriched_output_dict_empty():
    """Test canonicalization with empty or missing collections."""
    test_data = {
        "correlations": [],
        "actions": None,
        "followups": [],
    }

    result = canonicalize_enriched_output_dict(test_data)

    assert result["correlations"] == []
    assert result["actions"] is None  # None values should be preserved
    assert result["followups"] == []


def test_canonicalize_enriched_output_dict_json_determinism():
    """Test that canonicalized output produces identical JSON."""
    test_data = {
        "correlations": [
            {"id": "z", "data": "last"},
            {"id": "a", "data": "first"},
        ],
        "actions": [
            {"priority": 1, "action": "low"},
            {"priority": 2, "action": "high"},
        ]
    }

    # Canonicalize twice
    result1 = canonicalize_enriched_output_dict(test_data.copy())
    result2 = canonicalize_enriched_output_dict(test_data.copy())

    # Convert to JSON strings
    json1 = json.dumps(result1, sort_keys=True)
    json2 = json.dumps(result2, sort_keys=True)

    # Should be identical
    assert json1 == json2

    # Verify the ordering is correct
    assert result1["correlations"][0]["id"] == "a"
    assert result1["correlations"][1]["id"] == "z"
    assert result1["actions"][0]["priority"] == 2  # Higher priority first
    assert result1["actions"][1]["priority"] == 1


def test_canonicalize_enriched_output_dict_preserves_structure():
    """Test that canonicalization preserves the overall structure."""
    original = {
        "correlations": [{"id": "b"}, {"id": "a"}],
        "actions": [{"priority": 1}, {"priority": 2}],  # Top-level actions should be sorted
        "nested": {
            "actions": [{"priority": 1}, {"priority": 2}],  # Nested actions should NOT be sorted
            "other": "value"
        },
        "list_field": [3, 1, 2]
    }

    result = canonicalize_enriched_output_dict(original)

    # Top-level correlations should be sorted
    assert result["correlations"][0]["id"] == "a"
    assert result["correlations"][1]["id"] == "b"

    # Top-level actions should be sorted (higher priority first)
    assert result["actions"][0]["priority"] == 2
    assert result["actions"][1]["priority"] == 1

    # Nested actions should NOT be sorted (only top-level fields are sorted)
    assert result["nested"]["actions"][0]["priority"] == 1
    assert result["nested"]["actions"][1]["priority"] == 2

    # Other nested fields should be unchanged
    assert result["nested"]["other"] == "value"

    # Non-specified list fields should be unchanged
    assert result["list_field"] == [3, 1, 2]