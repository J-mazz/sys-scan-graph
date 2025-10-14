"""
Tests for graph/utils.py utilities.
"""

from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock
import time
import os

from sys_scan_agent.graph import utils
from sys_scan_agent import models


class TestEnvironmentVariableCaching:
    """Test _get_env_var function."""

    def test_get_env_var_cached(self):
        """Test that environment variables are cached."""
        with patch.dict(os.environ, {'TEST_VAR': 'test_value'}):
            # First call should cache
            result1 = utils._get_env_var('TEST_VAR')
            assert result1 == 'test_value'

            # Second call should use cache
            result2 = utils._get_env_var('TEST_VAR')
            assert result2 == 'test_value'

            # Verify it's the same object (cached)
            assert result1 is result2

    def test_get_env_var_default(self):
        """Test default value when env var not set."""
        result = utils._get_env_var('NONEXISTENT_VAR', 'default')
        assert result == 'default'

    def test_get_env_var_none_default(self):
        """Test None default when env var not set."""
        # Clear cache for this test
        utils._ENV_CACHE.clear()
        result = utils._get_env_var('NONEXISTENT_VAR')
        assert result is None


class TestComplianceStandardNormalization:
    """Test _normalize_compliance_standard function."""

    def test_normalize_compliance_standard_pci(self):
        """Test PCI DSS normalization."""
        assert utils._normalize_compliance_standard('pci') == 'PCI DSS'
        assert utils._normalize_compliance_standard('pcidss') == 'PCI DSS'
        assert utils._normalize_compliance_standard('PCI DSS') == 'PCI DSS'

    def test_normalize_compliance_standard_hipaa(self):
        """Test HIPAA normalization."""
        assert utils._normalize_compliance_standard('hipaa') == 'HIPAA'

    def test_normalize_compliance_standard_iso(self):
        """Test ISO 27001 normalization."""
        assert utils._normalize_compliance_standard('iso27001') == 'ISO 27001'

    def test_normalize_compliance_standard_unknown(self):
        """Test unknown standard returns None."""
        assert utils._normalize_compliance_standard('unknown') is None

    def test_normalize_compliance_standard_none(self):
        """Test None input."""
        assert utils._normalize_compliance_standard(None) is None

    def test_normalize_compliance_standard_empty(self):
        """Test empty string input."""
        assert utils._normalize_compliance_standard('') is None


class TestFindingModelConstruction:
    """Test _build_finding_models function."""

    def test_build_finding_models_valid(self):
        """Test building models from valid finding dicts."""
        finding_dicts = [
            {
                'id': 'test1',
                'title': 'Test Finding 1',
                'severity': 'high',
                'risk_score': 75,
                'metadata': {'key': 'value'}
            },
            {
                'id': 'test2',
                'title': 'Test Finding 2',
                'severity': 'medium',
                'risk_score': 45,
                'metadata': {}
            }
        ]

        models_list = utils._build_finding_models(finding_dicts)

        assert len(models_list) == 2
        assert models_list[0].id == 'test1'
        assert models_list[0].title == 'Test Finding 1'
        assert models_list[0].severity == 'high'
        assert models_list[0].risk_score == 75

    def test_build_finding_models_invalid_fields(self):
        """Test building models with invalid fields (should be filtered)."""
        finding_dicts = [
            {
                'id': 'test1',
                'title': 'Test Finding',
                'severity': 'high',
                'risk_score': 75,
                'metadata': {},
                'invalid_field': 'should_be_ignored',
                'another_invalid': 123
            }
        ]

        models_list = utils._build_finding_models(finding_dicts)

        assert len(models_list) == 1
        assert models_list[0].id == 'test1'
        assert models_list[0].title == 'Test Finding'
        assert models_list[0].severity == 'high'
        assert models_list[0].risk_score == 75

    def test_build_finding_models_validation_error(self):
        """Test handling of validation errors."""
        finding_dicts = [
            {
                'id': 'test1',
                'title': 'Test Finding',
                # Missing required fields that would cause validation error
            }
        ]

        # Should not crash, should skip invalid findings
        models_list = utils._build_finding_models(finding_dicts)
        assert len(models_list) == 0  # Invalid finding should be skipped


class TestAgentStateConstruction:
    """Test _build_agent_state function."""

    def test_build_agent_state_basic(self):
        """Test basic AgentState construction."""
        findings = [
            models.Finding(
                id='test1',
                title='Test Finding',
                severity='high',
                risk_score=75,
                metadata={}
            )
        ]

        state = utils._build_agent_state(findings, 'test_scanner')

        assert isinstance(state, models.AgentState)
        assert state.report is not None
        assert len(state.report.results) == 1
        assert state.report.results[0].scanner == 'test_scanner'
        assert state.report.results[0].finding_count == 1
        assert len(state.report.results[0].findings) == 1

    def test_build_agent_state_empty_findings(self):
        """Test AgentState construction with empty findings."""
        findings = []
        state = utils._build_agent_state(findings, 'test_scanner')

        assert isinstance(state, models.AgentState)
        assert state.report.results[0].finding_count == 0
        assert len(state.report.results[0].findings) == 0


class TestStateExtraction:
    """Test state extraction utilities."""

    def test_extract_findings_from_state_raw_findings(self):
        """Test extraction from raw_findings key."""
        state = {'raw_findings': [{'id': 'test1'}, {'id': 'test2'}]}
        result = utils._extract_findings_from_state(state, 'raw_findings')
        assert result == [{'id': 'test1'}, {'id': 'test2'}]

    def test_extract_findings_from_state_correlated(self):
        """Test fallback to correlated_findings."""
        state = {'correlated_findings': [{'id': 'test1'}]}
        result = utils._extract_findings_from_state(state, 'raw_findings')
        assert result == [{'id': 'test1'}]

    def test_extract_findings_from_state_enriched(self):
        """Test fallback to enriched_findings."""
        state = {'enriched_findings': [{'id': 'test1'}]}
        result = utils._extract_findings_from_state(state, 'raw_findings')
        assert result == [{'id': 'test1'}]

    def test_extract_findings_from_state_empty(self):
        """Test empty state returns empty list."""
        state = {}
        result = utils._extract_findings_from_state(state, 'raw_findings')
        assert result == []


class TestStateInitialization:
    """Test _initialize_state_fields function."""

    def test_initialize_state_fields_warnings(self):
        """Test warnings field initialization."""
        state = {}
        utils._initialize_state_fields(state, 'warnings')
        assert state['warnings'] == []

    def test_initialize_state_fields_metrics(self):
        """Test metrics field initialization."""
        state = {}
        utils._initialize_state_fields(state, 'metrics')
        assert state['metrics'] == {}

    def test_initialize_state_fields_cache(self):
        """Test cache field initialization."""
        state = {}
        utils._initialize_state_fields(state, 'cache')
        assert state['cache'] == {}

    def test_initialize_state_fields_enrich_cache(self):
        """Test enrich_cache field initialization."""
        state = {}
        utils._initialize_state_fields(state, 'enrich_cache')
        assert state['enrich_cache'] == {}

    def test_initialize_state_fields_other(self):
        """Test other field initialization."""
        state = {}
        utils._initialize_state_fields(state, 'other_field')
        assert state['other_field'] == []

    def test_initialize_state_fields_existing(self):
        """Test that existing fields are not overwritten."""
        state = {'warnings': ['existing']}
        utils._initialize_state_fields(state, 'warnings')
        assert state['warnings'] == ['existing']


class TestMetricsUpdates:
    """Test metrics update functions."""

    def test_update_metrics_duration(self):
        """Test duration metrics update."""
        state = {}
        start_time = time.monotonic() - 1.5  # 1.5 seconds ago

        utils._update_metrics_duration(state, 'test_duration', start_time)

        assert 'metrics' in state
        assert 'test_duration' in state['metrics']
        assert abs(state['metrics']['test_duration'] - 1.5) < 0.1  # Allow small timing variance

    def test_update_metrics_counter(self):
        """Test counter metrics update."""
        state = {}
        utils._update_metrics_counter(state, 'test_counter')
        assert state['metrics']['test_counter'] == 1

        utils._update_metrics_counter(state, 'test_counter')
        assert state['metrics']['test_counter'] == 2

    def test_update_metrics_counter_increment(self):
        """Test counter with custom increment."""
        state = {}
        utils._update_metrics_counter(state, 'test_counter', 5)
        assert state['metrics']['test_counter'] == 5


class TestWarningManagement:
    """Test _append_warning function."""

    def test_append_warning_basic(self):
        """Test basic warning append."""
        state = {}
        warning_info = utils.WarningInfo(
            module='test_module',
            stage='test_stage',
            error='test error',
            hint='test hint'
        )

        utils._append_warning(state, warning_info)

        assert 'warnings' in state
        assert len(state['warnings']) == 1
        warning = state['warnings'][0]
        assert warning['module'] == 'test_module'
        assert warning['stage'] == 'test_stage'
        assert warning['error'] == 'test error'
        assert warning['hint'] == 'test hint'

    def test_append_warning_no_hint(self):
        """Test warning append without hint."""
        state = {}
        warning_info = utils.WarningInfo(
            module='test_module',
            stage='test_stage',
            error='test error'
        )

        utils._append_warning(state, warning_info)

        warning = state['warnings'][0]
        assert warning['hint'] is None


class TestFindingExtraction:
    """Test _findings_from_graph function."""

    def test_findings_from_graph_valid(self):
        """Test finding extraction with valid data."""
        state = {
            'raw_findings': [
                {
                    'id': 'test1',
                    'title': 'Test Finding',
                    'severity': 'high',
                    'risk_score': 75,
                    'metadata': {'key': 'value'}
                }
            ]
        }

        findings = utils._findings_from_graph(state)

        assert len(findings) == 1
        assert findings[0].id == 'test1'
        assert findings[0].title == 'Test Finding'
        assert findings[0].severity == 'high'
        assert findings[0].risk_score == 75

    def test_findings_from_graph_defaults(self):
        """Test finding extraction with missing fields (should use defaults)."""
        state = {
            'raw_findings': [
                {
                    'id': 'test1'
                    # Missing title, severity, risk_score
                }
            ]
        }

        findings = utils._findings_from_graph(state)

        assert len(findings) == 1
        assert findings[0].id == 'test1'
        assert findings[0].title == '(no title)'
        assert findings[0].severity == 'info'
        assert findings[0].risk_score == 0

    def test_findings_from_graph_risk_total_fallback(self):
        """Test risk_score fallback to risk_total."""
        state = {
            'raw_findings': [
                {
                    'id': 'test1',
                    'title': 'Test Finding',
                    'severity': 'high',
                    'risk_total': 80  # No risk_score, use risk_total
                }
            ]
        }

        findings = utils._findings_from_graph(state)

        assert findings[0].risk_score == 80

    def test_findings_from_graph_invalid_risk_score(self):
        """Test handling of invalid risk_score."""
        state = {
            'raw_findings': [
                {
                    'id': 'test1',
                    'title': 'Test Finding',
                    'severity': 'high',
                    'risk_score': 'invalid'  # Invalid type
                }
            ]
        }

        findings = utils._findings_from_graph(state)

        assert len(findings) == 1
        assert findings[0].risk_score == 0  # Should default to 0

    def test_findings_from_graph_empty_state(self):
        """Test finding extraction from empty state."""
        state = {}
        findings = utils._findings_from_graph(state)
        assert findings == []

    def test_findings_from_graph_exception_handling(self):
        """Test exception handling in finding extraction."""
        state = {
            'raw_findings': [
                {
                    'id': 'test1',
                    # Missing required fields - should still create with defaults
                }
            ]
        }

        # Should not crash, should create finding with defaults
        findings = utils._findings_from_graph(state)
        assert len(findings) == 1  # Should create finding with defaults
        assert findings[0].id == 'test1'
        assert findings[0].title == '(no title)'
        assert findings[0].severity == 'info'
        assert findings[0].risk_score == 0


class TestBatchProcessing:
    """Test batch processing utilities."""

    def test_batch_extract_finding_fields(self):
        """Test batch field extraction from findings."""
        findings = [
            {
                'id': 'test1',
                'title': 'Finding One',
                'severity': 'high',
                'tags': ['tag1', 'tag2'],
                'category': 'security',
                'metadata': {'key': 'value'},
                'risk_score': 75
            },
            {
                'id': 'test2',
                'title': 'Finding Two',
                'severity': 'medium',
                'tags': ['tag3'],
                'category': 'compliance',
                'metadata': {},
                'risk_score': 45
            }
        ]

        fields = utils._batch_extract_finding_fields(findings)

        assert fields['ids'] == ['test1', 'test2']
        assert fields['titles'] == ['Finding One', 'Finding Two']
        assert fields['severities'] == ['high', 'medium']
        assert fields['tags_list'] == [['tag1', 'tag2'], ['tag3']]
        assert fields['categories'] == ['security', 'compliance']
        assert fields['metadata_list'] == [{'key': 'value'}, {}]
        assert fields['risk_scores'] == [75, 45]

    def test_batch_extract_finding_fields_defaults(self):
        """Test batch extraction with missing fields."""
        findings = [
            {
                'id': 'test1'
                # Missing other fields
            }
        ]

        fields = utils._batch_extract_finding_fields(findings)

        assert fields['ids'] == ['test1']
        assert fields['titles'] == ['']
        assert fields['severities'] == ['unknown']
        assert fields['tags_list'] == [[]]
        assert fields['categories'] == ['']

    def test_batch_filter_findings_by_severity(self):
        """Test batch severity filtering."""
        fields = {
            'severities': ['high', 'medium', 'low', 'high', 'info']
        }
        severity_levels = {'high', 'critical'}

        indices = utils._batch_filter_findings_by_severity(fields, severity_levels)

        assert indices == [0, 3]  # Indices of 'high' findings


class TestComplianceChecking:
    """Test compliance-related functions."""

    def test_is_compliance_related_tags(self):
        """Test compliance detection via tags."""
        assert utils._is_compliance_related(['compliance', 'pci'], 'security', {}) is True
        assert utils._is_compliance_related(['pci'], 'security', {}) is False

    def test_is_compliance_related_category(self):
        """Test compliance detection via category."""
        assert utils._is_compliance_related([], 'compliance', {}) is True
        assert utils._is_compliance_related([], 'security', {}) is False

    def test_is_compliance_related_metadata(self):
        """Test compliance detection via metadata."""
        assert utils._is_compliance_related([], 'security', {'compliance_standard': 'PCI DSS'}) is True
        assert utils._is_compliance_related([], 'security', {}) is False

    def test_is_compliance_related_normalized_category(self):
        """Test compliance detection with normalized category."""
        assert utils._is_compliance_related([], 'pci', {}) is True

    def test_batch_check_compliance_indicators(self):
        """Test batch compliance checking."""
        fields = {
            'tags_list': [['compliance'], ['pci'], ['normal']],
            'categories': ['security', 'compliance', 'normal'],
            'metadata_list': [{}, {}, {'compliance_standard': 'HIPAA'}]
        }

        indices = utils._batch_check_compliance_indicators(fields)

        assert set(indices) == {0, 1, 2}  # All three should be compliance-related


class TestExternalDataRequirements:
    """Test external data requirement functions."""

    def test_requires_external_data_tags(self):
        """Test external data requirement detection via tags."""
        assert utils._requires_external_data(['external_required'], {}) is True
        assert utils._requires_external_data(['normal'], {}) is False

    def test_requires_external_data_metadata(self):
        """Test external data requirement detection via metadata."""
        assert utils._requires_external_data([], {'requires_external': True}) is True
        assert utils._requires_external_data([], {'threat_feed_lookup': True}) is True
        assert utils._requires_external_data([], {}) is False

    def test_batch_check_external_requirements(self):
        """Test batch external requirement checking."""
        fields = {
            'tags_list': [['external_required'], ['normal'], ['normal']],
            'metadata_list': [{}, {'requires_external': True}, {'threat_feed_lookup': True}]
        }

        indices = utils._batch_check_external_requirements(fields)

        assert set(indices) == {0, 1, 2}  # All three should require external data


class TestBaselineStatusChecking:
    """Test baseline status checking."""

    def test_batch_check_baseline_status_missing(self):
        """Test detection of missing baseline status."""
        findings = [
            {'id': 'test1'},  # No baseline_status field
            {'id': 'test2', 'baseline_status': None},  # None value
            {'id': 'test3', 'baseline_status': 'present'}  # Has status
        ]

        indices = utils._batch_check_baseline_status(findings)

        assert indices == [0, 1]  # First two should be missing baseline status


class TestStandardExtractionAndMapping:
    """Test compliance standard extraction and mapping."""

    def test_extract_metadata_standards(self):
        """Test metadata standard extraction."""
        metadata = {'compliance_standard': 'PCI DSS'}
        standards = utils._extract_metadata_standards(metadata)
        assert standards == {'PCI DSS'}

    def test_extract_metadata_standards_case_insensitive(self):
        """Test case-insensitive metadata standard extraction."""
        metadata = {'compliance_standard': 'pci dss'}
        standards = utils._extract_metadata_standards(metadata)
        assert standards == {'PCI DSS'}  # Should normalize to canonical form

    def test_extract_tag_standards(self):
        """Test tag standard extraction."""
        tags = ['pci', 'hipaa', 'normal']
        standards = utils._extract_tag_standards(tags)
        assert standards == {'PCI DSS', 'HIPAA'}

    def test_map_findings_to_standards(self):
        """Test mapping findings to standards."""
        std_map = {}
        utils._map_findings_to_standards({'PCI DSS', 'HIPAA'}, std_map, 0)
        utils._map_findings_to_standards({'PCI DSS'}, std_map, 1)

        assert std_map == {'PCI DSS': [0, 1], 'HIPAA': [0]}

    def test_batch_normalize_compliance_standards(self):
        """Test batch compliance standard normalization."""
        fields = {
            'metadata_list': [
                {'compliance_standard': 'pci'},
                {'compliance_standard': 'hipaa'},
                {}
            ],
            'tags_list': [
                ['pci'],
                ['normal'],
                ['iso27001']
            ]
        }

        std_map = utils._batch_normalize_compliance_standards(fields)

        expected = {
            'PCI DSS': [0],     # pci from metadata and tags (same index)
            'HIPAA': [1],       # hipaa from metadata
            'ISO 27001': [2]    # iso27001 from tags
        }
        assert std_map == expected


class TestRiskCalculation:
    """Test risk calculation utilities."""

    def test_count_severities(self):
        """Test severity counting."""
        severities = ['high', 'medium', 'high', 'low', 'unknown', 'info']
        counts = utils._count_severities(severities)

        expected = {
            'critical': 0,
            'high': 2,
            'medium': 1,
            'low': 1,
            'info': 1,
            'unknown': 1
        }
        assert counts == expected

    def test_calculate_risk_totals(self):
        """Test risk total calculation."""
        risk_scores = [10, 20, 30]
        total, avg, scores = utils._calculate_risk_totals(risk_scores)

        assert total == 60
        assert avg == 20.0
        assert scores == [10, 20, 30]

    def test_calculate_risk_totals_empty(self):
        """Test risk calculation with empty list."""
        total, avg, scores = utils._calculate_risk_totals([])
        assert total == 0
        assert avg == 0.0
        assert scores == []

    def test_determine_qualitative_risk_critical(self):
        """Test qualitative risk determination with critical findings."""
        sev_counters = {'critical': 1, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        risk = utils._determine_qualitative_risk(sev_counters)
        assert risk == 'critical'

    def test_determine_qualitative_risk_high(self):
        """Test qualitative risk determination with high findings."""
        sev_counters = {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'info': 0}
        risk = utils._determine_qualitative_risk(sev_counters)
        assert risk == 'high'

    def test_determine_qualitative_risk_info(self):
        """Test qualitative risk determination with only info findings."""
        sev_counters = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 1}
        risk = utils._determine_qualitative_risk(sev_counters)
        assert risk == 'info'

    def test_batch_calculate_risk_metrics(self):
        """Test batch risk metrics calculation."""
        fields = {
            'severities': ['high', 'medium', 'low'],
            'risk_scores': [75, 45, 25]
        }

        metrics = utils._batch_calculate_risk_metrics(fields)

        assert metrics['total_risk'] == 145
        assert metrics['avg_risk'] == 48.333333333333336
        assert metrics['qualitative_risk'] == 'high'
        assert metrics['sev_counters']['high'] == 1
        assert metrics['sev_counters']['medium'] == 1
        assert metrics['sev_counters']['low'] == 1

    def test_batch_get_top_findings_by_risk(self):
        """Test getting top findings by risk score."""
        fields = {
            'ids': ['test1', 'test2', 'test3'],
            'titles': ['High Risk', 'Medium Risk', 'Low Risk'],
            'risk_scores': [75, 45, 25],
            'severities': ['high', 'medium', 'low']
        }

        top_findings = utils._batch_get_top_findings_by_risk(fields, 2)

        assert len(top_findings) == 2
        assert top_findings[0]['id'] == 'test1'
        assert top_findings[0]['risk_score'] == 75
        assert top_findings[1]['id'] == 'test2'
        assert top_findings[1]['risk_score'] == 45

    def test_batch_get_top_findings_by_risk_more_than_available(self):
        """Test getting top findings when requesting more than available."""
        fields = {
            'ids': ['test1', 'test2'],
            'titles': ['Finding 1', 'Finding 2'],
            'risk_scores': [75, 45],
            'severities': ['high', 'medium']
        }

        top_findings = utils._batch_get_top_findings_by_risk(fields, 5)

        assert len(top_findings) == 2  # Should return all available


class TestStateNormalization:
    """Test _normalize_state function."""

    @patch('sys_scan_agent.graph.utils.graph_state.normalize_graph_state')
    def test_normalize_state(self, mock_normalize):
        """Test state normalization delegates to graph_state."""
        mock_normalize.return_value = {'normalized': True}

        state = {'raw': 'data'}
        result = utils._normalize_state(state)

        mock_normalize.assert_called_once_with(state)
        assert result == {'normalized': True}