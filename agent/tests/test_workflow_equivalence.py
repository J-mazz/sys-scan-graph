"""Contract tests for workflow equivalence between baseline and enhanced variants.

This module tests that scaffold (baseline) and enhanced workflows produce
equivalent results for the same input, ensuring contract versioning compliance.
"""

import os
import asyncio
import pytest
from typing import Dict, Any, List
from unittest.mock import patch

# Import types
from ..graph import GraphState
from ..graph_nodes_scaffold import StateType

# Import both workflow variants
from ..graph_nodes_scaffold import (
    enrich_findings,
    correlate_findings,
    summarize_host_state as scaffold_summarize,
    suggest_rules as scaffold_suggest_rules,
    risk_analyzer as scaffold_risk_analyzer,
)

from ..graph_nodes_enhanced import (
    enhanced_enrich_findings,
    enhanced_summarize_host_state as enhanced_summarize,
    enhanced_suggest_rules as enhanced_suggest_rules,
    risk_analyzer as enhanced_risk_analyzer,
)

from ..graph_state import normalize_graph_state


class TestWorkflowEquivalence:
    """Test equivalence between scaffold and enhanced workflow variants."""

    @pytest.fixture
    def test_findings(self) -> List[Dict[str, Any]]:
        """Standard test findings for equivalence testing."""
        return [
            {
                "id": "f1",
                "title": "Suspicious SUID binary",
                "severity": "high",
                "risk_score": 80,
                "metadata": {"path": "/usr/local/bin/suspicious"},
                "tags": ["suid", "baseline:new"],
            },
            {
                "id": "f2",
                "title": "Enable IP forwarding",
                "severity": "medium",
                "risk_score": 30,
                "metadata": {"sysctl_key": "net.ipv4.ip_forward", "value": "1"},
                "tags": ["kernel_param"],
            },
            {
                "id": "f3",
                "title": "Open port 22",
                "severity": "low",
                "risk_score": 10,
                "metadata": {"port": 22, "service": "ssh"},
                "tags": ["network", "baseline:expected"],
            },
        ]

    @pytest.fixture
    def base_state(self, test_findings) -> Dict[str, Any]:
        """Base state for testing."""
        return {
            'raw_findings': test_findings,
            'session_id': 'test_session_equivalence',
            'host_id': 'test_host'
        }

    def normalize_for_comparison(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize state for comparison by removing timing and non-deterministic fields."""
        # Create a copy to avoid mutating original
        normalized = dict(state)  # Convert TypedDict to regular dict

        # Remove timing-related fields that will differ
        metrics = normalized.get('metrics', {}).copy()
        timing_fields = [k for k in metrics.keys() if k.endswith('_duration') or k.endswith('_time')]
        for field in timing_fields:
            metrics.pop(field, None)
        
        # Remove timestamp fields
        if 'node_timestamps' in metrics:
            del metrics['node_timestamps']
        if 'start_time_monotonic' in metrics:
            del metrics['start_time_monotonic']
            
        # Remove ID fields that are generated per run
        if 'node_ids' in metrics:
            del metrics['node_ids']
        if 'telemetry' in metrics:
            telemetry = metrics['telemetry'].copy()
            if 'invocation_id' in telemetry:
                del telemetry['invocation_id']
            if 'current_node' in telemetry:
                del telemetry['current_node']  # This might change during execution
            metrics['telemetry'] = telemetry
            
        if metrics:
            normalized['metrics'] = metrics

        # Remove fields that may be non-deterministic
        fields_to_remove = [
            'start_time', 'start_time_monotonic', 'start_time_iso',
            'final_metrics', 'cache', 'cache_hits', 'cache_keys',
            'iteration_count',  # This increments between runs
            'current_stage',    # This changes during workflow execution
            'session_id'        # May be generated differently
        ]
        for field in fields_to_remove:
            normalized.pop(field, None)

        return normalized

    async def run_scaffold_workflow(self, state: Dict[str, Any]) -> StateType:
        """Run the complete scaffold workflow."""
        # Normalize state first
        state = normalize_graph_state(state)

        # Run workflow steps
        state = enrich_findings(state)
        state = correlate_findings(state)
        state = scaffold_summarize(state)
        state = scaffold_suggest_rules(state)
        state = await scaffold_risk_analyzer(state)

        return state

    async def run_enhanced_workflow(self, state: Dict[str, Any]) -> GraphState:
        """Run the complete enhanced workflow."""
        # Normalize state first
        state = normalize_graph_state(state)

        # Cast to GraphState for enhanced functions
        graph_state = GraphState(**state)

        # Run workflow steps
        graph_state = await enhanced_enrich_findings(graph_state)
        graph_state = await enhanced_summarize(graph_state)
        graph_state = await enhanced_suggest_rules(graph_state)
        graph_state = await enhanced_risk_analyzer(graph_state)

        return graph_state

    @pytest.mark.asyncio
    async def test_enrichment_equivalence(self, base_state):
        """Test that enrichment produces equivalent results."""
        scaffold_state = await self.run_scaffold_workflow(base_state.copy())
        enhanced_state = await self.run_enhanced_workflow(base_state.copy())

        # Normalize for comparison
        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(dict(enhanced_state))

        # Both should have enriched_findings
        assert 'enriched_findings' in scaffold_norm
        assert 'enriched_findings' in enhanced_norm

        # Should have same number of findings
        assert len(scaffold_norm['enriched_findings']) == len(enhanced_norm['enriched_findings'])

        # Each finding should have equivalent core fields
        for scaffold_f, enhanced_f in zip(scaffold_norm['enriched_findings'], enhanced_norm['enriched_findings']):
            assert scaffold_f['id'] == enhanced_f['id']
            assert scaffold_f.get('severity') == enhanced_f.get('severity')
            assert scaffold_f.get('risk_score') == enhanced_f.get('risk_score')

    @pytest.mark.asyncio
    async def test_risk_assessment_equivalence(self, base_state):
        """Test that risk assessment produces equivalent results."""
        scaffold_state = await self.run_scaffold_workflow(base_state.copy())
        enhanced_state = await self.run_enhanced_workflow(base_state.copy())

        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(dict(enhanced_state))

        # Both should have risk_assessment
        assert 'risk_assessment' in scaffold_norm
        assert 'risk_assessment' in enhanced_norm

        scaffold_ra = scaffold_norm['risk_assessment']
        enhanced_ra = enhanced_norm['risk_assessment']

        # Check unified schema fields
        unified_fields = [
            'overall_risk_level', 'overall_risk', 'risk_factors',
            'recommendations', 'confidence_score', 'counts',
            'total_risk_score', 'average_risk_score', 'finding_count'
        ]

        for field in unified_fields:
            assert field in scaffold_ra, f"Scaffold missing {field}"
            assert field in enhanced_ra, f"Enhanced missing {field}"

        # Core quantitative fields should be equivalent
        assert scaffold_ra['finding_count'] == enhanced_ra['finding_count']
        assert scaffold_ra['total_risk_score'] == enhanced_ra['total_risk_score']
        assert scaffold_ra['counts'] == enhanced_ra['counts']

    @pytest.mark.asyncio
    async def test_workflow_contract_compliance(self, base_state):
        """Test that both workflows comply with GraphState contract."""
        scaffold_state = await self.run_scaffold_workflow(base_state.copy())
        enhanced_state = await self.run_enhanced_workflow(base_state.copy())

        # Both should pass GraphState validation
        from ..graph_state import validate_graph_state

        assert validate_graph_state(scaffold_state), "Scaffold state failed validation"
        assert validate_graph_state(dict(enhanced_state)), "Enhanced state failed validation"

        # Both should have required fields from schema
        required_fields = [
            'raw_findings', 'enriched_findings', 'correlations',
            'warnings', 'errors', 'messages', 'risk_assessment'
        ]

        for field in required_fields:
            assert field in scaffold_state, f"Scaffold missing {field}"
            assert field in enhanced_state, f"Enhanced missing {field}"

    @pytest.mark.asyncio
    async def test_deterministic_behavior(self, base_state):
        """Test that both workflows produce deterministic results."""
        # Run scaffold workflow multiple times
        scaffold_results = []
        for _ in range(3):
            result = await self.run_scaffold_workflow(base_state.copy())
            scaffold_results.append(self.normalize_for_comparison(result))

        # Run enhanced workflow multiple times
        enhanced_results = []
        for _ in range(3):
            result = await self.run_enhanced_workflow(base_state.copy())
            enhanced_results.append(self.normalize_for_comparison(dict(result)))

        # All scaffold results should be identical
        assert all(r == scaffold_results[0] for r in scaffold_results), "Scaffold workflow not deterministic"

        # All enhanced results should be identical
        assert all(r == enhanced_results[0] for r in enhanced_results), "Enhanced workflow not deterministic"

    @pytest.mark.asyncio
    async def test_error_handling_equivalence(self, base_state):
        """Test that both workflows handle errors equivalently."""
        # Create state with problematic data
        error_state = base_state.copy()
        error_state['raw_findings'] = [
            {'id': 'bad_finding', 'severity': 'invalid_severity'},  # Invalid data
            {'id': 'good_finding', 'severity': 'high', 'risk_score': 90}
        ]

        scaffold_state = await self.run_scaffold_workflow(error_state.copy())
        enhanced_state = await self.run_enhanced_workflow(error_state.copy())

        # Both should handle errors gracefully (not crash)
        assert isinstance(scaffold_state, dict), "Scaffold error handling failed"
        assert isinstance(enhanced_state, dict), "Enhanced error handling failed"

        # Both should have some findings processed
        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(dict(enhanced_state))

        assert 'enriched_findings' in scaffold_norm
        assert 'enriched_findings' in enhanced_norm

        # Should have at least the good finding
        scaffold_good = [f for f in scaffold_norm['enriched_findings'] if f.get('id') == 'good_finding']
        enhanced_good = [f for f in enhanced_norm['enriched_findings'] if f.get('id') == 'good_finding']

        assert len(scaffold_good) > 0, "Scaffold didn't process good finding"
        assert len(enhanced_good) > 0, "Enhanced didn't process good finding"


class TestContractVersioning:
    """Test contract versioning compliance."""

    def test_schema_version_constants(self):
        """Test that schema version constants are properly defined."""
        from ..graph_state import GRAPH_STATE_SCHEMA_VERSION, GRAPH_STATE_SCHEMA_LAST_UPDATED

        assert GRAPH_STATE_SCHEMA_VERSION, "Schema version not defined"
        assert GRAPH_STATE_SCHEMA_LAST_UPDATED, "Schema last updated not defined"

        # Version should be semantic version format
        import re
        assert re.match(r'^\d+\.\d+\.\d+$', GRAPH_STATE_SCHEMA_VERSION), "Invalid version format"

    def test_workflow_variant_identification(self):
        """Test that workflows can identify their variant."""
        # Scaffold workflow should identify as baseline
        scaffold_state = {'workflow_variant': 'scaffold'}
        normalized = normalize_graph_state(scaffold_state)
        assert normalized.get('current_stage') == 'initializing'  # Default

        # Enhanced workflow should identify as enhanced
        enhanced_state = {'workflow_variant': 'enhanced'}
        normalized = normalize_graph_state(enhanced_state)
        assert normalized.get('current_stage') == 'initializing'  # Default


if __name__ == '__main__':
    pytest.main([__file__])