"""Unit tests for GraphState normalization functionality.

This module tests the normalize_graph_state function to ensure:
- Mandatory keys are initialized with proper defaults
- Existing values are preserved
- Type safety is maintained
- Deterministic behavior across all node functions
"""

import pytest
from typing import Dict, Any, List
from datetime import datetime

from sys_scan_agent.graph_state import normalize_graph_state, GraphStateSchema


class TestGraphStateNormalization:
    """Test cases for GraphState normalization."""

    def test_normalize_empty_state(self):
        """Test normalization of completely empty state."""
        empty_state: Dict[str, Any] = {}

        normalized = normalize_graph_state(empty_state)

        # Check mandatory keys are initialized
        assert normalized['raw_findings'] == []
        assert normalized['enriched_findings'] == []
        assert normalized['correlations'] == []
        assert normalized['metrics'] == {}
        assert normalized['iteration_count'] == 0
        assert normalized['baseline_cycle_done'] is False
        assert normalized['cache_keys'] == []
        assert normalized['start_time'] is None

    def test_normalize_partial_state(self):
        """Test normalization preserves existing values and adds missing ones."""
        partial_state = {
            'raw_findings': [{'id': 'test1', 'title': 'Test Finding'}],
            'enriched_findings': [{'id': 'test1', 'severity': 'high'}],
            'metrics': {'duration': 1.5}
        }

        normalized = normalize_graph_state(partial_state)

        # Check existing values preserved
        assert normalized['raw_findings'] == [{'id': 'test1', 'title': 'Test Finding'}]
        assert normalized['enriched_findings'] == [{'id': 'test1', 'severity': 'high'}]
        assert normalized['metrics'] == {'duration': 1.5}

        # Check missing keys added with defaults
        assert normalized['correlations'] == []
        assert normalized['iteration_count'] == 0
        assert normalized['baseline_cycle_done'] is False
        assert normalized['cache_keys'] == []
        assert normalized['start_time'] is None

    def test_normalize_with_none_values(self):
        """Test normalization handles None values properly."""
        state_with_nones = {
            'raw_findings': None,
            'enriched_findings': None,
            'correlations': None,
            'metrics': None,
            'iteration_count': None,
            'baseline_cycle_done': None,
            'cache_keys': None,
            'start_time': None
        }

        normalized = normalize_graph_state(state_with_nones)

        # All None values should be replaced with proper defaults
        assert normalized['raw_findings'] == []
        assert normalized['enriched_findings'] == []
        assert normalized['correlations'] == []
        assert normalized['metrics'] == {}
        assert normalized['iteration_count'] == 0
        assert normalized['baseline_cycle_done'] is False
        assert normalized['cache_keys'] == []
        assert normalized['start_time'] is None

    def test_normalize_preserves_optional_fields(self):
        """Test that optional fields are preserved if present."""
        state_with_optionals = {
            'raw_findings': [{'id': 'test'}],
            'summary': {'total_findings': 1},
            'warnings': [{'message': 'test warning'}],
            'errors': [{'error': 'test error'}],
            'session_id': 'test-session-123',
            'current_stage': 'enrich'
        }

        normalized = normalize_graph_state(state_with_optionals)

        # Optional fields should be preserved
        assert normalized['summary'] == {'total_findings': 1}
        assert normalized['warnings'] == [{'message': 'test warning'}]
        assert normalized['errors'] == [{'error': 'test error'}]
        assert normalized['session_id'] == 'test-session-123'
        assert normalized['current_stage'] == 'enrich'

        # Mandatory fields should still be added
        assert normalized['enriched_findings'] == []
        assert normalized['correlations'] == []
        assert normalized['metrics'] == {}
        assert normalized['iteration_count'] == 0
        assert normalized['baseline_cycle_done'] is False

    def test_normalize_with_datetime_start_time(self):
        """Test normalization with datetime start_time."""
        start_time = datetime.now().isoformat()
        state_with_time = {
            'start_time': start_time,
            'raw_findings': [{'id': 'test'}]
        }

        normalized = normalize_graph_state(state_with_time)

        assert normalized['start_time'] == start_time
        assert normalized['raw_findings'] == [{'id': 'test'}]

    def test_normalize_complex_findings(self):
        """Test normalization with complex finding structures."""
        complex_state = {
            'raw_findings': [
                {
                    'id': 'finding1',
                    'title': 'Complex Finding',
                    'severity': 'high',
                    'metadata': {'source': 'test', 'tags': ['tag1', 'tag2']},
                    'risk_score': 85
                }
            ],
            'enriched_findings': [
                {
                    'id': 'finding1',
                    'correlations': ['corr1', 'corr2'],
                    'baseline_status': 'new'
                }
            ],
            'correlations': [
                {
                    'id': 'corr1',
                    'type': 'similarity',
                    'confidence': 0.95
                }
            ]
        }

        normalized = normalize_graph_state(complex_state)

        # Complex structures should be preserved
        assert len(normalized['raw_findings']) == 1
        assert normalized['raw_findings'][0]['id'] == 'finding1'
        assert len(normalized['enriched_findings']) == 1
        assert len(normalized['correlations']) == 1

        # Defaults should still be applied for missing mandatory fields
        assert normalized['iteration_count'] == 0
        assert normalized['baseline_cycle_done'] is False

    def test_normalize_iteration_count_increment(self):
        """Test that iteration_count can be incremented after normalization."""
        state = {'iteration_count': 5}

        normalized = normalize_graph_state(state)
        assert normalized['iteration_count'] == 5

        # Simulate incrementing iteration count
        normalized['iteration_count'] += 1
        assert normalized['iteration_count'] == 6

    def test_normalize_baseline_cycle_done_toggle(self):
        """Test that baseline_cycle_done can be toggled after normalization."""
        state = {'baseline_cycle_done': True}

        normalized = normalize_graph_state(state)
        assert normalized['baseline_cycle_done'] is True

        # Simulate toggling baseline cycle done
        normalized['baseline_cycle_done'] = False
        assert normalized['baseline_cycle_done'] is False

    def test_normalize_cache_keys_management(self):
        """Test cache_keys list management after normalization."""
        state = {'cache_keys': ['key1', 'key2']}

        normalized = normalize_graph_state(state)
        assert normalized['cache_keys'] == ['key1', 'key2']

        # Simulate adding cache keys
        normalized['cache_keys'].append('key3')
        assert 'key3' in normalized['cache_keys']
        assert len(normalized['cache_keys']) == 3

    def test_normalize_metrics_accumulation(self):
        """Test metrics dict accumulation after normalization."""
        state = {
            'metrics': {
                'enrich_duration': 1.2,
                'findings_count': 10
            }
        }

        normalized = normalize_graph_state(state)
        assert normalized['metrics']['enrich_duration'] == 1.2
        assert normalized['metrics']['findings_count'] == 10

        # Simulate adding more metrics
        normalized['metrics']['summarize_duration'] = 2.5
        assert normalized['metrics']['summarize_duration'] == 2.5
        assert len(normalized['metrics']) == 3


class TestGraphStateSchema:
    """Test cases for GraphStateSchema Pydantic model."""

    def test_schema_creation_empty(self):
        """Test creating schema from empty dict."""
        schema = GraphStateSchema()

        assert schema.raw_findings == []
        assert schema.enriched_findings == []
        assert schema.correlations == []
        assert schema.metrics == {}
        assert schema.iteration_count == 0
        assert schema.baseline_cycle_done is False
        assert schema.cache_keys == []
        assert schema.start_time is None

    def test_schema_creation_with_data(self):
        """Test creating schema with data."""
        data = {
            'raw_findings': [{'id': 'test'}],
            'enriched_findings': [{'id': 'test', 'severity': 'high'}],
            'correlations': [{'id': 'corr1'}],
            'metrics': {'duration': 1.5},
            'iteration_count': 3,
            'baseline_cycle_done': True,
            'cache_keys': ['key1'],
            'start_time': '2024-01-01T00:00:00'
        }

        schema = GraphStateSchema(**data)

        assert schema.raw_findings == [{'id': 'test'}]
        assert schema.enriched_findings == [{'id': 'test', 'severity': 'high'}]
        assert schema.correlations == [{'id': 'corr1'}]
        assert schema.metrics == {'duration': 1.5}
        assert schema.iteration_count == 3
        assert schema.baseline_cycle_done is True
        assert schema.cache_keys == ['key1']
        assert schema.start_time == '2024-01-01T00:00:00'

    def test_schema_validation(self):
        """Test schema validation with invalid data."""
        # Test with wrong types
        with pytest.raises(Exception):  # Pydantic validation error
            GraphStateSchema(raw_findings="not_a_list")

        with pytest.raises(Exception):
            GraphStateSchema(iteration_count="not_an_int")

        with pytest.raises(Exception):
            GraphStateSchema(baseline_cycle_done="not_a_bool")

    def test_schema_to_dict(self):
        """Test converting schema back to dict."""
        data = {
            'raw_findings': [{'id': 'test'}],
            'metrics': {'duration': 1.5},
            'iteration_count': 2
        }

        schema = GraphStateSchema(**data)
        dict_result = schema.model_dump()

        assert dict_result['raw_findings'] == [{'id': 'test'}]
        assert dict_result['metrics'] == {'duration': 1.5}
        assert dict_result['iteration_count'] == 2
        # Check defaults are included
        assert dict_result['enriched_findings'] == []
        assert dict_result['baseline_cycle_done'] is False


class TestNormalizationIntegration:
    """Integration tests for normalization in real scenarios."""

    def test_normalize_router_state(self):
        """Test normalization for router node state."""
        router_state = {
            'enriched_findings': [
                {'id': 'f1', 'severity': 'high', 'category': 'security'},
                {'id': 'f2', 'severity': 'low', 'category': 'compliance'}
            ],
            'correlations': [{'id': 'c1', 'type': 'similarity'}],
            'iteration_count': 2
        }

        normalized = normalize_graph_state(router_state)

        # Router-specific fields should be preserved
        assert len(normalized['enriched_findings']) == 2
        assert len(normalized['correlations']) == 1
        assert normalized['iteration_count'] == 2

        # Defaults should be applied
        assert normalized['raw_findings'] == []
        assert normalized['baseline_cycle_done'] is False

    def test_normalize_baseline_state(self):
        """Test normalization for baseline cycle state."""
        baseline_state = {
            'raw_findings': [{'id': 'f1'}, {'id': 'f2'}],
            'baseline_results': {'f1': 'known', 'f2': 'new'},
            'baseline_cycle_done': True,
            'cache_keys': ['baseline_123']
        }

        normalized = normalize_graph_state(baseline_state)

        # Baseline-specific fields should be preserved
        assert len(normalized['raw_findings']) == 2
        assert normalized['baseline_cycle_done'] is True
        assert normalized['cache_keys'] == ['baseline_123']

        # Defaults should be applied
        assert normalized['enriched_findings'] == []
        assert normalized['iteration_count'] == 0

    def test_normalize_error_recovery_state(self):
        """Test normalization for error recovery scenarios."""
        error_state = {
            'errors': [
                {'error': 'timeout', 'stage': 'summarize'},
                {'error': 'iteration_limit', 'stage': 'enrich'}
            ],
            'warnings': [
                {'message': 'LLM rate limit', 'stage': 'summarize'}
            ],
            'iteration_count': 5
        }

        normalized = normalize_graph_state(error_state)

        # Error handling fields should be preserved
        assert len(normalized['errors']) == 2
        assert len(normalized['warnings']) == 1
        assert normalized['iteration_count'] == 5

        # Defaults should be applied
        assert normalized['raw_findings'] == []
        assert normalized['baseline_cycle_done'] is False


if __name__ == '__main__':
    pytest.main([__file__])