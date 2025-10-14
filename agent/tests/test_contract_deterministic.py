"""Contract tests for router deterministic behavior.

This module tests that the router behaves deterministically
when using normalized GraphState.
"""

import pytest
from typing import Dict, Any, List

from sys_scan_agent.graph_state import normalize_graph_state
from sys_scan_agent.graph_nodes_enhanced import advanced_router


class TestRouterDeterministicBehavior:
    """Test that the advanced_router behaves deterministically with normalized state."""

    def test_router_empty_findings(self):
        """Test router behavior with empty findings."""
        state = normalize_graph_state({})

        # Router should handle empty state gracefully
        result = advanced_router(state)  # type: ignore
        assert isinstance(result, str)
        assert result in ["summarize", "error"]  # Expected routing options

    def test_router_high_severity_findings(self):
        """Test router prioritizes high-severity findings."""
        state = normalize_graph_state({
            'enriched_findings': [
                {'id': 'f1', 'severity': 'high', 'category': 'security'},
                {'id': 'f2', 'severity': 'low', 'category': 'info'}
            ]
        })

        result = advanced_router(state)  # type: ignore
        # High severity should trigger appropriate routing
        assert result in ["summarize", "baseline", "risk", "compliance"]

    def test_router_baseline_missing(self):
        """Test router handles missing baseline data."""
        state = normalize_graph_state({
            'enriched_findings': [
                {'id': 'f1', 'severity': 'high'},  # No baseline_status
                {'id': 'f2', 'severity': 'medium', 'baseline_status': 'new'}
            ]
        })

        result = advanced_router(state)  # type: ignore
        # Should detect missing baseline and route appropriately
        assert isinstance(result, str)

    def test_router_compliance_requirements(self):
        """Test router detects compliance requirements."""
        state = normalize_graph_state({
            'enriched_findings': [
                {'id': 'f1', 'category': 'pci_dss', 'severity': 'high'},
                {'id': 'f2', 'category': 'hipaa', 'severity': 'medium'}
            ]
        })

        result = advanced_router(state)  # type: ignore
        # Should prioritize compliance routing
        assert result in ["compliance", "summarize", "risk"]

    def test_router_human_feedback_pending(self):
        """Test router handles pending human feedback."""
        state = normalize_graph_state({
            'human_feedback_pending': True,
            'enriched_findings': [{'id': 'f1', 'severity': 'high'}]
        })

        result = advanced_router(state)  # type: ignore
        # Should prioritize human feedback
        assert result == "human_feedback"

    def test_router_external_data_needs(self):
        """Test router detects external data requirements."""
        state = normalize_graph_state({
            'enriched_findings': [
                {
                    'id': 'f1',
                    'severity': 'medium',
                    'metadata': {'external_ref': 'CVE-2023-12345'}
                }
            ]
        })

        result = advanced_router(state)  # type: ignore
        # Should route for external data processing
        assert result in ["risk", "summarize"]


class TestNormalizationContractCompliance:
    """Test that normalization maintains contract expectations."""

    def test_router_contract_with_normalized_state(self):
        """Test router works correctly with normalized state."""
        # Test various state configurations
        test_cases = [
            {},
            {'enriched_findings': []},
            {'enriched_findings': [{'id': 'f1', 'severity': 'high'}]},
            {'human_feedback_pending': True},
            {'enriched_findings': [], 'human_feedback_pending': False},
        ]

        for test_state in test_cases:
            normalized = normalize_graph_state(test_state)
            result = advanced_router(normalized)  # type: ignore

            # Router should always return a valid string
            assert isinstance(result, str)
            assert len(result) > 0
            assert result != "error" or len(normalized.get('enriched_findings', [])) == 0

    def test_state_immutability_contract(self):
        """Test that normalization doesn't mutate original state."""
        original = {'raw_findings': [{'id': 'f1'}], 'custom_field': 'preserve'}
        original_copy = original.copy()

        normalized = normalize_graph_state(original)

        # Original should be unchanged
        assert original == original_copy

        # Normalized should have additional fields but preserve originals
        assert normalized['raw_findings'] == original['raw_findings']
        assert normalized['custom_field'] == original['custom_field']  # Custom fields preserved

    def test_normalization_deterministic_behavior(self):
        """Test that normalization produces consistent results."""
        test_state = {
            'raw_findings': [{'id': 'f1'}, {'id': 'f2'}],
            'enriched_findings': [{'id': 'f1', 'severity': 'high'}]
        }

        # Run normalization multiple times
        result1 = normalize_graph_state(test_state.copy())
        result2 = normalize_graph_state(test_state.copy())
        result3 = normalize_graph_state(test_state.copy())

        # All results should be identical
        assert result1 == result2 == result3

        # Key fields should be consistent
        for result in [result1, result2, result3]:
            assert result['raw_findings'] == [{'id': 'f1'}, {'id': 'f2'}]
            assert result['enriched_findings'] == [{'id': 'f1', 'severity': 'high'}]
            assert result['correlations'] == []
            assert result['iteration_count'] == 0
            assert result['baseline_cycle_done'] is False

    def test_normalization_preserves_none_values_when_explicit(self):
        """Test that explicit None values in original state are preserved appropriately."""
        # When start_time is explicitly set to None, it should remain None
        state_with_explicit_none = {'start_time': None, 'raw_findings': [{'id': 'f1'}]}

        normalized = normalize_graph_state(state_with_explicit_none)

        # Explicit None should be preserved
        assert normalized['start_time'] is None
        assert normalized['raw_findings'] == [{'id': 'f1'}]

        # Other defaults should still be applied
        assert normalized['enriched_findings'] == []
        assert normalized['iteration_count'] == 0


if __name__ == '__main__':
    pytest.main([__file__])