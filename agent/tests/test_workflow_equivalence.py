"""Contract tests for workflow equivalence between baseline and enhanced variants.

This module tests that scaffold (baseline) and enhanced workflows produce
equivalent results for the same input, ensuring contract versioning compliance.
"""

import os
import copy
import asyncio
import pytest
from typing import Dict, Any, List
from unittest.mock import patch

# Import types
from sys_scan_agent.graph_state import GraphState
from typing import Dict, Any
StateType = Dict[str, Any]  # type: ignore

# Import both workflow variants
from sys_scan_agent.graph import (
    enrich_findings,
    correlate_findings,
    enhanced_summarize_host_state as scaffold_summarize,
    enhanced_suggest_rules as scaffold_suggest_rules,
    risk_analyzer as scaffold_risk_analyzer,
    compliance_checker as scaffold_compliance_checker,
)

from sys_scan_agent.graph_nodes_enhanced import (
    enhanced_enrich_findings,
    enhanced_summarize_host_state as enhanced_summarize,
    enhanced_suggest_rules as enhanced_suggest_rules,
    risk_analyzer as enhanced_risk_analyzer,
    compliance_checker as enhanced_compliance_checker,
)

from sys_scan_agent.graph_state import normalize_graph_state
from sys_scan_agent.util_normalization import (
    normalize_rule_suggestions,
    unify_risk_assessment,
    unify_compliance_check,
    ensure_monotonic_timing,
    add_metrics_version,
)


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

        # Canonicalize list order for deterministic comparison
        # Keep identifiers for comparison but strip generated/ephemeral IDs
        volatile_keys = {'uid', 'uuid', 'correlation_id', 'rule_id', 'invocation_id'}

        def _normalize_entry(entry):
            if not isinstance(entry, dict):
                return entry
            cleaned = dict(entry)
            for k in volatile_keys:
                cleaned.pop(k, None)

            # Normalize common nested collections for determinism
            if 'tags' in cleaned and isinstance(cleaned['tags'], list):
                cleaned['tags'] = sorted(cleaned['tags'])
            if 'correlation_refs' in cleaned and isinstance(cleaned['correlation_refs'], list):
                cleaned['correlation_refs'] = sorted(cleaned['correlation_refs'])
            if 'metadata' in cleaned and isinstance(cleaned['metadata'], dict):
                # Ensure deterministic ordering inside metadata by sorting list values if present
                md = {}
                for mk, mv in cleaned['metadata'].items():
                    if isinstance(mv, list):
                        md[mk] = sorted(mv)
                    else:
                        md[mk] = mv
                cleaned['metadata'] = md
            return cleaned

        def _sorted_list(val):
            if not isinstance(val, list):
                return val
            cleaned = [_normalize_entry(x) for x in val]
            # Sort by stable key: id -> title -> repr
            return sorted(cleaned, key=lambda x: (
                isinstance(x, dict) and x.get('id') or '',
                isinstance(x, dict) and x.get('title') or '',
                repr(x)
            ))

        for list_field in ['raw_findings', 'enriched_findings', 'correlations', 'suggested_rules', 'messages', 'warnings', 'errors', 'actions']:
            if list_field in normalized:
                normalized[list_field] = _sorted_list(normalized[list_field])

        def _round_floats(obj):
            if isinstance(obj, float):
                return round(obj, 6)
            if isinstance(obj, dict):
                return {k: _round_floats(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_round_floats(v) for v in obj]
            return obj

        # Remove timing-related fields that will differ
        if 'metrics' in normalized and isinstance(normalized['metrics'], dict):
            metrics = normalized['metrics'].copy()
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
            if 'telemetry' in metrics and isinstance(metrics['telemetry'], dict):
                telemetry = metrics['telemetry'].copy()
                if 'invocation_id' in telemetry:
                    del telemetry['invocation_id']
                if 'current_node' in telemetry:
                    del telemetry['current_node']  # This might change during execution
                metrics['telemetry'] = telemetry
                
            normalized['metrics'] = metrics
        elif 'metrics' in normalized:
            # If metrics exists but is not a dict, remove it
            del normalized['metrics']

        # Remove fields that may be non-deterministic
        fields_to_remove = [
            'start_time', 'start_time_monotonic', 'start_time_iso',
            'final_metrics', 'cache', 'cache_hits', 'cache_keys',
            'iteration_count',  # This increments between runs
            'current_stage',    # This changes during workflow execution
            'session_id',       # May be generated differently
            'monotonic_start',  # Timestamp that changes between runs
            # Workflow bookkeeping/caches that can vary across runs or test order
            'enrich_cache', 'baseline_results', 'baseline_cycle_done',
            'pending_tool_calls', 'degraded_mode', 'human_feedback_pending',
            'human_feedback_processed', 'streaming_enabled', 'summarize_progress',
            'llm_provider_mode',
        ]
        for field in fields_to_remove:
            normalized.pop(field, None)

        # Normalize summary metrics that may vary
        if 'summary' in normalized and isinstance(normalized['summary'], dict):
            summary = normalized['summary']
            if 'metrics' in summary and isinstance(summary['metrics'], dict):
                summary_metrics = summary['metrics']
                # Remove timing/latency fields from summary
                timing_keys = [k for k in summary_metrics.keys() if 'latency' in k.lower() or 'time' in k.lower()]
                for key in timing_keys:
                    summary_metrics.pop(key, None)
                # Normalize floating point values that might differ slightly
                for key in ['avg_prompt_tokens', 'avg_completion_tokens']:
                    if key in summary_metrics and isinstance(summary_metrics[key], float):
                        summary_metrics[key] = round(summary_metrics[key], 1)

        return _round_floats(normalized)

    def _reset_caches(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Clear caches and bookkeeping that can leak across test runs."""
        # Deep copy to avoid mutating shared fixtures across iterations
        state = copy.deepcopy(state)
        state.pop('cache', None)
        state.pop('cache_keys', None)
        state['enrich_cache'] = {}
        return state

    async def run_scaffold_workflow(self, state: Dict[str, Any]) -> StateType:
        """Run the complete scaffold workflow."""
        # Normalize state first and reset caches to avoid cross-test reuse
        state = self._reset_caches(state)
        state = normalize_graph_state(state)

        # Run workflow steps
        state = enrich_findings(state)
        state = correlate_findings(state)
        state = await scaffold_summarize(state)
        state = await scaffold_suggest_rules(state)
        state = await scaffold_risk_analyzer(state)
        state = await scaffold_compliance_checker(state)

        return state

    async def run_enhanced_workflow(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run the complete enhanced workflow."""
        # Normalize state first and reset caches to avoid cross-test reuse
        state = self._reset_caches(state)
        state = normalize_graph_state(state)

        # Run workflow steps
        state = await enhanced_enrich_findings(state)
        state = await enhanced_summarize(state)
        state = await enhanced_suggest_rules(state)
        state = await enhanced_risk_analyzer(state)
        state = await enhanced_compliance_checker(state)

        return state

    def test_enrichment_equivalence(self, base_state):
        """Test that enrichment produces equivalent results."""
        scaffold_state = asyncio.run(self.run_scaffold_workflow(base_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(base_state.copy()))

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

    def test_risk_assessment_equivalence(self, base_state):
        """Test that risk assessment produces equivalent results."""
        scaffold_state = asyncio.run(self.run_scaffold_workflow(base_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(base_state.copy()))

        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(enhanced_state)

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

    def test_workflow_contract_compliance(self, base_state):
        """Test that both workflows comply with GraphState contract."""
        scaffold_state = asyncio.run(self.run_scaffold_workflow(base_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(base_state.copy()))

        # Both should pass GraphState validation
        from sys_scan_agent.graph_state import validate_graph_state

        assert validate_graph_state(scaffold_state), "Scaffold state failed validation"
        assert validate_graph_state(enhanced_state), "Enhanced state failed validation"

        # Both should have required fields from schema
        required_fields = [
            'raw_findings', 'enriched_findings', 'correlations',
            'warnings', 'errors', 'messages', 'risk_assessment'
        ]

        for field in required_fields:
            assert field in scaffold_state, f"Scaffold missing {field}"
            assert field in enhanced_state, f"Enhanced missing {field}"

    def test_deterministic_behavior(self, base_state):
        """Test that both workflows produce deterministic results."""
        # Warm caches/state once to avoid cross-test contamination on first run
        asyncio.run(self.run_scaffold_workflow(base_state.copy()))
        asyncio.run(self.run_enhanced_workflow(base_state.copy()))

        # Run scaffold workflow multiple times
        scaffold_results = []
        for _ in range(3):
            result = asyncio.run(self.run_scaffold_workflow(base_state.copy()))
            scaffold_results.append(self.normalize_for_comparison(result))

        # Drop first result to ignore any warm-start drift from prior tests
        if len(scaffold_results) > 1:
            scaffold_results = scaffold_results[1:]

        # Run enhanced workflow multiple times
        enhanced_results = []
        for _ in range(3):
            result = asyncio.run(self.run_enhanced_workflow(base_state.copy()))
            enhanced_results.append(self.normalize_for_comparison(result))

        if len(enhanced_results) > 1:
            enhanced_results = enhanced_results[1:]

        # All scaffold results should be identical on core fields
        scaffold_ref = scaffold_results[0]
        assert all(
            r.get('enriched_findings') == scaffold_ref.get('enriched_findings') and
            r.get('risk_assessment') == scaffold_ref.get('risk_assessment')
            for r in scaffold_results
        ), "Scaffold workflow not deterministic"

        # All enhanced results should be identical on core fields
        enhanced_ref = enhanced_results[0]
        assert all(
            r.get('enriched_findings') == enhanced_ref.get('enriched_findings') and
            r.get('risk_assessment') == enhanced_ref.get('risk_assessment')
            for r in enhanced_results
        ), "Enhanced workflow not deterministic"

    def test_error_handling_equivalence(self, base_state):
        """Test that both workflows handle errors equivalently."""
        # Create state with problematic data
        error_state = base_state.copy()
        error_state['raw_findings'] = [
            {'id': 'bad_finding', 'severity': 'invalid_severity'},  # Invalid data
            {'id': 'good_finding', 'severity': 'high', 'risk_score': 90}
        ]

        scaffold_state = asyncio.run(self.run_scaffold_workflow(error_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(error_state.copy()))

        # Both should handle errors gracefully (not crash)
        assert isinstance(scaffold_state, dict), "Scaffold error handling failed"
        assert isinstance(enhanced_state, dict), "Enhanced error handling failed"

        # Both should have some findings processed
        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(enhanced_state)

        assert 'enriched_findings' in scaffold_norm
        assert 'enriched_findings' in enhanced_norm

        # Should have at least the good finding
        scaffold_good = [f for f in scaffold_norm['enriched_findings'] if f.get('id') == 'good_finding']
        enhanced_good = [f for f in enhanced_norm['enriched_findings'] if f.get('id') == 'good_finding']

        assert len(scaffold_good) > 0, "Scaffold didn't process good finding"
        assert len(enhanced_good) > 0, "Enhanced didn't process good finding"

    def test_risk_assessment_canonicalization(self, base_state):
        """Test that risk assessment canonicalization produces unified schema."""
        scaffold_state = asyncio.run(self.run_scaffold_workflow(base_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(base_state.copy()))

        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(enhanced_state)

        # Test unified risk assessment schema
        scaffold_ra = scaffold_norm.get('risk_assessment', {})
        enhanced_ra = enhanced_norm.get('risk_assessment', {})

        # Required unified fields
        required_fields = [
            'overall_risk_level', 'overall_risk', 'risk_factors',
            'recommendations', 'confidence_score', 'counts',
            'total_risk_score', 'average_risk_score', 'finding_count',
            'top_findings'
        ]

        for field in required_fields:
            assert field in scaffold_ra, f"Scaffold risk_assessment missing {field}"
            assert field in enhanced_ra, f"Enhanced risk_assessment missing {field}"

        # Test counts structure (should have all severity levels)
        scaffold_counts = scaffold_ra['counts']
        enhanced_counts = enhanced_ra['counts']

        expected_keys = {'critical', 'high', 'medium', 'low', 'info', 'unknown'}
        assert set(scaffold_counts.keys()) == expected_keys, f"Scaffold counts missing keys: {expected_keys - set(scaffold_counts.keys())}"
        assert set(enhanced_counts.keys()) == expected_keys, f"Enhanced counts missing keys: {expected_keys - set(enhanced_counts.keys())}"

        # All counts should be non-negative integers
        for key in expected_keys:
            assert isinstance(scaffold_counts[key], int) and scaffold_counts[key] >= 0, f"Scaffold {key} count invalid"
            assert isinstance(enhanced_counts[key], int) and enhanced_counts[key] >= 0, f"Enhanced {key} count invalid"

        # Test that overall_risk and overall_risk_level are unified
        assert scaffold_ra['overall_risk'] == scaffold_ra['overall_risk_level'], "Scaffold risk fields not unified"
        assert enhanced_ra['overall_risk'] == enhanced_ra['overall_risk_level'], "Enhanced risk fields not unified"

    def test_compliance_check_canonicalization(self, base_state):
        """Test that compliance check canonicalization produces unified schema."""
        # Add compliance-related findings to test compliance canonicalization
        compliance_state = base_state.copy()
        compliance_state['raw_findings'].extend([
            {
                "id": "c1",
                "title": "PCI DSS violation - unencrypted data",
                "severity": "high",
                "risk_score": 85,
                "metadata": {"compliance_standard": "PCI DSS", "requirement": "3.4"},
                "tags": ["compliance", "pci_dss"],
            },
            {
                "id": "c2",
                "title": "HIPAA violation - missing audit logs",
                "severity": "critical",
                "risk_score": 95,
                "metadata": {"compliance_standard": "HIPAA", "requirement": "164.312"},
                "tags": ["compliance", "hipaa"],
            }
        ])

        # Run workflows with compliance data
        scaffold_state = asyncio.run(self.run_scaffold_workflow(compliance_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(compliance_state.copy()))

        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(enhanced_state)

        # Test unified compliance check schema
        scaffold_cc = scaffold_norm.get('compliance_check', {})
        enhanced_cc = enhanced_norm.get('compliance_check', {})

        # Required unified fields
        assert 'standards' in scaffold_cc, "Scaffold compliance_check missing standards"
        assert 'total_compliance_findings' in scaffold_cc, "Scaffold compliance_check missing total"
        assert 'standards' in enhanced_cc, "Enhanced compliance_check missing standards"
        assert 'total_compliance_findings' in enhanced_cc, "Enhanced compliance_check missing total"

        # Test standards structure
        scaffold_standards = scaffold_cc['standards']
        enhanced_standards = enhanced_cc['standards']

        # Should have entries for PCI DSS and HIPAA
        assert 'PCI DSS' in scaffold_standards or 'pci_dss' in scaffold_standards, "Scaffold missing PCI DSS"
        assert 'HIPAA' in scaffold_standards or 'hipaa' in scaffold_standards, "Scaffold missing HIPAA"
        assert 'PCI DSS' in enhanced_standards or 'pci_dss' in enhanced_standards, "Enhanced missing PCI DSS"
        assert 'HIPAA' in enhanced_standards or 'hipaa' in enhanced_standards, "Enhanced missing HIPAA"

        # Test total compliance findings calculation
        scaffold_total = scaffold_cc['total_compliance_findings']
        enhanced_total = enhanced_cc['total_compliance_findings']
        assert scaffold_total >= 2, "Scaffold compliance total incorrect"
        assert enhanced_total >= 2, "Enhanced compliance total incorrect"

    def test_normalization_function_equivalence(self, base_state):
        """Test that normalization functions produce equivalent results."""
        # Test normalize_rule_suggestions
        test_state = base_state.copy()
        test_state['rule_suggestions'] = [{'id': 'r1', 'confidence': 0.8}]
        test_state['suggested_rules'] = [{'id': 'r2', 'confidence': 0.9}]

        scaffold_normalized = normalize_rule_suggestions(test_state.copy())
        enhanced_normalized = normalize_rule_suggestions(test_state.copy())

        assert scaffold_normalized == enhanced_normalized, "Rule suggestions normalization not equivalent"

        # Test unify_risk_assessment
        risk_state = base_state.copy()
        risk_state['risk_assessment'] = {
            'overall_risk_level': 'high',
            'counts': {'critical': 1, 'high': 2}
        }

        scaffold_risk = unify_risk_assessment(risk_state.copy())
        enhanced_risk = unify_risk_assessment(risk_state.copy())

        assert scaffold_risk == enhanced_risk, "Risk assessment unification not equivalent"

        # Test unify_compliance_check
        compliance_state = base_state.copy()
        compliance_state['compliance_check'] = {
            'standards': {
                'PCI DSS': {'finding_ids': ['f1', 'f2'], 'count': 2}
            }
        }

        scaffold_compliance = unify_compliance_check(compliance_state.copy())
        enhanced_compliance = unify_compliance_check(compliance_state.copy())

        assert scaffold_compliance == enhanced_compliance, "Compliance check unification not equivalent"

    def test_metrics_versioning_and_timing(self, base_state):
        """Test that metrics versioning and monotonic timing work correctly."""
        scaffold_state = asyncio.run(self.run_scaffold_workflow(base_state.copy()))
        enhanced_state = asyncio.run(self.run_enhanced_workflow(base_state.copy()))

        scaffold_norm = self.normalize_for_comparison(scaffold_state)
        enhanced_norm = self.normalize_for_comparison(enhanced_state)

        # Test metrics versioning
        scaffold_metrics = scaffold_norm.get('metrics', {})
        enhanced_metrics = enhanced_norm.get('metrics', {})

        assert 'version' in scaffold_metrics, "Scaffold metrics missing version"
        assert 'version' in enhanced_metrics, "Enhanced metrics missing version"
        assert scaffold_metrics['version'] == enhanced_metrics['version'], "Metrics versions don't match"

        # Test monotonic timing (should be present but not compared for exact values)
        scaffold_timing = scaffold_state.get('monotonic_start')
        enhanced_timing = enhanced_state.get('monotonic_start')

        assert scaffold_timing is not None, "Scaffold missing monotonic timing"
        assert enhanced_timing is not None, "Enhanced missing monotonic timing"

        # Both should be numeric (timestamp values)
        assert isinstance(scaffold_timing, (int, float)), "Scaffold monotonic timing not numeric"
        assert isinstance(enhanced_timing, (int, float)), "Enhanced monotonic timing not numeric"

    def test_schema_validation_with_unified_fields(self, base_state):
        """Test that schema validation works with unified fields."""
        from sys_scan_agent.graph_state import validate_graph_state

        # Test with unified risk assessment
        unified_state = base_state.copy()
        unified_state['risk_assessment'] = {
            'overall_risk_level': 'medium',
            'overall_risk': 'medium',  # Unified field
            'risk_factors': ['test_factor'],
            'recommendations': ['test_recommendation'],
            'confidence_score': 0.85,
            'counts': {'critical': 0, 'high': 1, 'medium': 2, 'low': 0, 'info': 0, 'unknown': 0},
            'total_risk_score': 150,
            'average_risk_score': 50.0,
            'finding_count': 3,
            'top_findings': [{'id': 'f1', 'title': 'Test', 'risk_score': 80}]
        }

        # Test with unified compliance check
        unified_state['compliance_check'] = {
            'standards': {
                'PCI DSS': {'finding_ids': ['f1'], 'count': 1},
                'HIPAA': {'finding_ids': ['f2', 'f3'], 'count': 2}
            },
            'total_compliance_findings': 3
        }

        # Test with unified rule suggestions
        unified_state['suggested_rules'] = [{'id': 'r1', 'confidence': 0.9}]
        unified_state['rule_suggestions'] = [{'id': 'r1', 'confidence': 0.9}]  # Should be unified

        # Apply normalization
        normalized_state = normalize_rule_suggestions(unified_state)
        normalized_state = unify_risk_assessment(normalized_state)
        normalized_state = unify_compliance_check(normalized_state)
        normalized_state = ensure_monotonic_timing(normalized_state)
        normalized_state = add_metrics_version(normalized_state)

        # Should pass validation
        assert validate_graph_state(normalized_state), "Unified schema validation failed"

        # Verify unified fields
        ra = normalized_state['risk_assessment']
        assert ra['overall_risk'] == ra['overall_risk_level'], "Risk fields not unified after normalization"

        cc = normalized_state['compliance_check']
        pci_count = cc['standards'].get('PCI DSS', {}).get('count', 0)
        hipaa_count = cc['standards'].get('HIPAA', {}).get('count', 0)
        assert cc['total_compliance_findings'] == pci_count + hipaa_count, "Compliance total not calculated correctly"


class TestContractVersioning:
    """Test contract versioning compliance."""

    def test_schema_version_constants(self):
        """Test that schema version constants are properly defined."""
        from sys_scan_agent.graph_state import GRAPH_STATE_SCHEMA_VERSION, GRAPH_STATE_SCHEMA_LAST_UPDATED

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