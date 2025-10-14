"""Tests for correlator.py module."""

import pytest
from unittest.mock import MagicMock, patch, call
from sys_scan_agent.correlator import (
    _enrich_knowledge_before_correlation,
    _collect_findings_for_correlation,
    _load_correlation_config_and_rules,
    _merge_correlation_rules,
    _apply_correlation_rules_and_metrics,
    _build_correlation_reference_map,
    _assign_correlation_refs_to_findings,
    correlate,
    _flatten_findings,
    _collect_suid_indices,
    _collect_ip_forward_indices,
    _check_sequence_trigger,
    _build_related_finding_ids,
    _create_sequence_correlation,
    _add_correlation_refs,
    sequence_correlation,
)


class TestEnrichKnowledgeBeforeCorrelation:
    """Test _enrich_knowledge_before_correlation function."""

    def test_enrich_knowledge_success(self):
        """Test successful knowledge enrichment."""
        state = MagicMock()

        with patch('sys_scan_agent.metrics.get_metrics_collector') as mock_mc, \
             patch('sys_scan_agent.knowledge.apply_external_knowledge') as mock_apply:

            mock_mc_instance = MagicMock()
            mock_mc.return_value = mock_mc_instance

            _enrich_knowledge_before_correlation(state)

            mock_mc.assert_called_once()
            mock_mc_instance.time_stage.assert_called_once_with('knowledge.enrichment')
            mock_apply.assert_called_once_with(state)

    def test_enrich_knowledge_import_error(self):
        """Test graceful handling when knowledge module not available."""
        state = MagicMock()

        with patch('sys_scan_agent.metrics.get_metrics_collector', side_effect=ImportError):
            # Should not raise exception
            _enrich_knowledge_before_correlation(state)


class TestCollectFindingsForCorrelation:
    """Test _collect_findings_for_correlation function."""

    def test_collect_findings_basic(self):
        """Test collecting findings from report."""
        finding1 = MagicMock()
        finding2 = MagicMock()

        scanner_result1 = MagicMock()
        scanner_result1.findings = [finding1]

        scanner_result2 = MagicMock()
        scanner_result2.findings = [finding2]

        state = MagicMock()
        state.report.results = [scanner_result1, scanner_result2]

        result = _collect_findings_for_correlation(state)

        assert result == [finding1, finding2]

    def test_collect_findings_no_report(self):
        """Test collecting findings when no report."""
        state = MagicMock()
        state.report = None

        result = _collect_findings_for_correlation(state)

        assert result == []

    def test_collect_findings_empty_results(self):
        """Test collecting findings when results is empty."""
        state = MagicMock()
        state.report.results = []

        result = _collect_findings_for_correlation(state)

        assert result == []


class TestLoadCorrelationConfigAndRules:
    """Test _load_correlation_config_and_rules function."""

    def test_load_config_and_rules_success(self):
        """Test successful loading of config and rules."""
        mock_cfg = MagicMock()
        mock_cfg.paths.rule_dirs = ['/rules/dir1', '/rules/dir2']
        mock_merged = [{'id': 'rule1'}, {'id': 'rule2'}]

        with patch('sys_scan_agent.config.load_config', return_value=mock_cfg), \
             patch('sys_scan_agent.correlator._merge_correlation_rules', return_value=mock_merged):

            cfg, merged = _load_correlation_config_and_rules()

            assert cfg == mock_cfg
            assert merged == mock_merged

    def test_load_config_and_rules_import_error(self):
        """Test handling when config/rules modules not available."""
        with patch('sys_scan_agent.config.load_config', side_effect=ImportError):
            cfg, merged = _load_correlation_config_and_rules()

            assert cfg is None
            assert merged == []


class TestMergeCorrelationRules:
    """Test _merge_correlation_rules function."""

    def test_merge_rules_basic(self):
        """Test merging rules from config and defaults."""
        mock_cfg = MagicMock()
        mock_cfg.paths.rule_dirs = ['/rules/dir1']

        rule1 = {'id': 'rule1', 'name': 'Rule 1'}
        rule2 = {'id': 'rule2', 'name': 'Rule 2'}
        default_rule = {'id': 'default1', 'name': 'Default Rule'}

        with patch('sys_scan_agent.rules.load_rules_dir', return_value=[rule1, rule2]), \
             patch('sys_scan_agent.rules.DEFAULT_RULES', [default_rule]):

            result = _merge_correlation_rules(mock_cfg)

            assert len(result) == 3
            assert result[0]['id'] == 'rule1'
            assert result[1]['id'] == 'rule2'
            assert result[2]['id'] == 'default1'

    def test_merge_rules_deduplication(self):
        """Test deduplication of rules with same ID."""
        mock_cfg = MagicMock()
        mock_cfg.paths.rule_dirs = ['/rules/dir1']

        rule1 = {'id': 'rule1', 'name': 'Rule 1'}
        duplicate_rule = {'id': 'rule1', 'name': 'Duplicate Rule'}
        default_rule = {'id': 'default1', 'name': 'Default Rule'}

        with patch('sys_scan_agent.rules.load_rules_dir', return_value=[rule1, duplicate_rule]), \
             patch('sys_scan_agent.rules.DEFAULT_RULES', [default_rule]):

            result = _merge_correlation_rules(mock_cfg)

            assert len(result) == 2
            assert result[0]['id'] == 'rule1'
            assert result[1]['id'] == 'default1'

    def test_merge_rules_import_error(self):
        """Test handling when rules module not available."""
        mock_cfg = MagicMock()
        mock_cfg.paths.rule_dirs = ['/rules/dir1']

        with patch('sys_scan_agent.rules.load_rules_dir', side_effect=ImportError):
            result = _merge_correlation_rules(mock_cfg)

            assert result == []


class TestApplyCorrelationRulesAndMetrics:
    """Test _apply_correlation_rules_and_metrics function."""

    def test_apply_rules_success(self):
        """Test successful application of correlation rules."""
        all_findings = [MagicMock(), MagicMock()]
        merged = [{'id': 'rule1'}, {'id': 'rule2'}]
        mc = MagicMock()

        mock_correlations = [MagicMock(), MagicMock()]

        with patch('sys_scan_agent.rules.Correlator') as mock_correlator_class:
            mock_correlator_instance = MagicMock()
            mock_correlator_instance.apply.return_value = mock_correlations
            mock_correlator_class.return_value = mock_correlator_instance

            result = _apply_correlation_rules_and_metrics(all_findings, merged, mc)

            assert result == mock_correlations
            mock_correlator_class.assert_called_once_with(merged)
            mock_correlator_instance.apply.assert_called_once_with(all_findings)
            mc.time_stage.assert_called_once_with('correlate.apply_rules')
            mc.incr.assert_has_calls([
                call('correlate.rules_loaded', 2),
                call('correlate.correlations', 2)
            ])

    def test_apply_rules_import_error(self):
        """Test handling when Correlator not available."""
        all_findings = [MagicMock()]
        merged = [{'id': 'rule1'}]
        mc = MagicMock()

        with patch('sys_scan_agent.correlator.Correlator', side_effect=ImportError):
            result = _apply_correlation_rules_and_metrics(all_findings, merged, mc)

            assert result == []


class TestBuildCorrelationReferenceMap:
    """Test _build_correlation_reference_map function."""

    def test_build_reference_map(self):
        """Test building correlation reference map."""
        corr1 = MagicMock()
        corr1.id = 'corr1'
        corr1.related_finding_ids = ['finding1', 'finding2']

        corr2 = MagicMock()
        corr2.id = 'corr2'
        corr2.related_finding_ids = ['finding2', 'finding3']

        correlations = [corr1, corr2]

        result = _build_correlation_reference_map(correlations)

        expected = {
            'finding1': ['corr1'],
            'finding2': ['corr1', 'corr2'],
            'finding3': ['corr2']
        }
        assert result == expected

    def test_build_reference_map_empty(self):
        """Test building reference map with empty correlations."""
        result = _build_correlation_reference_map([])

        assert result == {}


class TestAssignCorrelationRefsToFindings:
    """Test _assign_correlation_refs_to_findings function."""

    def test_assign_refs(self):
        """Test assigning correlation references to findings."""
        finding1 = MagicMock()
        finding1.id = 'finding1'
        finding1.correlation_refs = None

        finding2 = MagicMock()
        finding2.id = 'finding2'
        finding2.correlation_refs = ['existing_corr']

        finding3 = MagicMock()
        finding3.id = 'finding3'
        finding3.correlation_refs = None

        all_findings = [finding1, finding2, finding3]
        corr_map = {
            'finding1': ['corr1'],
            'finding2': ['corr2'],
            'finding3': ['corr3']
        }

        _assign_correlation_refs_to_findings(all_findings, corr_map)

        assert finding1.correlation_refs == ['corr1']
        assert finding2.correlation_refs == ['corr2']  # Overwrites existing
        assert finding3.correlation_refs == ['corr3']


class TestCorrelate:
    """Test correlate function."""

    def test_correlate_full_flow(self):
        """Test full correlation flow."""
        finding1 = MagicMock()
        finding2 = MagicMock()

        scanner_result = MagicMock()
        scanner_result.findings = [finding1, finding2]

        state = MagicMock()
        state.report.results = [scanner_result]
        state.correlations = []

        mock_cfg = MagicMock()
        mock_cfg.paths.rule_dirs = []
        mock_merged = [{'id': 'rule1'}]
        mock_correlations = [MagicMock()]

        with patch('sys_scan_agent.correlator._enrich_knowledge_before_correlation') as mock_enrich, \
             patch('sys_scan_agent.correlator._load_correlation_config_and_rules', return_value=(mock_cfg, mock_merged)) as mock_load, \
             patch('sys_scan_agent.metrics.get_metrics_collector') as mock_mc, \
             patch('sys_scan_agent.correlator._apply_correlation_rules_and_metrics', return_value=mock_correlations) as mock_apply, \
             patch('sys_scan_agent.correlator._build_correlation_reference_map') as mock_build_map, \
             patch('sys_scan_agent.correlator._assign_correlation_refs_to_findings') as mock_assign:

            correlate(state)

            mock_enrich.assert_called_once_with(state)
            mock_load.assert_called_once()
            mock_apply.assert_called_once_with([finding1, finding2], mock_merged, mock_mc.return_value)
            mock_build_map.assert_called_once_with(mock_correlations)
            mock_assign.assert_called_once_with([finding1, finding2], mock_build_map.return_value)
            assert state.correlations == mock_correlations

    def test_correlate_no_findings(self):
        """Test correlation with no findings."""
        state = MagicMock()
        state.report.results = []

        with patch('sys_scan_agent.correlator._enrich_knowledge_before_correlation') as mock_enrich:
            correlate(state)

            mock_enrich.assert_called_once_with(state)
            # Should not proceed further


class TestFlattenFindings:
    """Test _flatten_findings function."""

    def test_flatten_findings(self):
        """Test flattening findings from report results."""
        finding1 = MagicMock()
        finding2 = MagicMock()
        finding3 = MagicMock()

        scanner_result1 = MagicMock()
        scanner_result1.findings = [finding1]

        scanner_result2 = MagicMock()
        scanner_result2.findings = [finding2, finding3]

        state = MagicMock()
        state.report.results = [scanner_result1, scanner_result2]

        result = _flatten_findings(state)

        assert result == [finding1, finding2, finding3]

    def test_flatten_findings_no_report(self):
        """Test flattening with no report."""
        state = MagicMock()
        state.report = None

        result = _flatten_findings(state)

        assert result == []


class TestCollectSuidIndices:
    """Test _collect_suid_indices function."""

    def test_collect_suid_indices(self):
        """Test collecting SUID finding indices."""
        finding1 = MagicMock()
        finding1.tags = ['suid', 'baseline:new']

        finding2 = MagicMock()
        finding2.tags = ['suid']  # Missing baseline:new

        finding3 = MagicMock()
        finding3.tags = ['baseline:new']  # Missing suid

        ordered = [finding1, finding2, finding3]

        result = _collect_suid_indices(ordered)

        assert result == [(0, finding1)]

    def test_collect_suid_indices_empty(self):
        """Test collecting SUID indices with no matches."""
        finding1 = MagicMock()
        finding1.tags = ['other']

        ordered = [finding1]

        result = _collect_suid_indices(ordered)

        assert result == []


class TestCollectIpForwardIndices:
    """Test _collect_ip_forward_indices function."""

    def test_collect_ip_forward_indices(self):
        """Test collecting IP forwarding finding indices."""
        finding1 = MagicMock()
        finding1.category = 'kernel_param'
        finding1.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'}

        finding2 = MagicMock()
        finding2.category = 'kernel_param'
        finding2.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'value': '0'}

        finding3 = MagicMock()
        finding3.category = 'other'
        finding3.metadata = {}

        ordered = [finding1, finding2, finding3]

        result = _collect_ip_forward_indices(ordered)

        assert result == [(0, finding1)]

    def test_collect_ip_forward_indices_different_keys(self):
        """Test collecting with different metadata keys."""
        finding1 = MagicMock()
        finding1.category = 'kernel_param'
        finding1.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'desired': 'true'}

        finding2 = MagicMock()
        finding2.category = 'kernel_param'
        finding2.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'current': 'enabled'}

        ordered = [finding1, finding2]

        result = _collect_ip_forward_indices(ordered)

        assert len(result) == 2
        assert result[0] == (0, finding1)
        assert result[1] == (1, finding2)


class TestCheckSequenceTrigger:
    """Test _check_sequence_trigger function."""

    def test_check_sequence_trigger_true(self):
        """Test sequence trigger detection when SUID precedes IP forward."""
        suid_indices = [(0, MagicMock()), (2, MagicMock())]
        ip_forward_indices = [(1, MagicMock()), (3, MagicMock())]

        result = _check_sequence_trigger(suid_indices, ip_forward_indices)

        assert result is True

    def test_check_sequence_trigger_false(self):
        """Test sequence trigger detection when IP forward precedes SUID."""
        suid_indices = [(1, MagicMock())]
        ip_forward_indices = [(0, MagicMock())]

        result = _check_sequence_trigger(suid_indices, ip_forward_indices)

        assert result is False

    def test_check_sequence_trigger_empty(self):
        """Test sequence trigger with empty lists."""
        result = _check_sequence_trigger([], [])

        assert result is False


class TestBuildRelatedFindingIds:
    """Test _build_related_finding_ids function."""

    def test_build_related_ids(self):
        """Test building related finding IDs."""
        suid_finding1 = MagicMock()
        suid_finding1.id = 'suid1'

        suid_finding2 = MagicMock()
        suid_finding2.id = 'suid2'

        suid_finding3 = MagicMock()
        suid_finding3.id = 'suid3'

        ip_finding1 = MagicMock()
        ip_finding1.id = 'ip1'

        ip_finding2 = MagicMock()
        ip_finding2.id = 'ip2'

        suid_indices = [(0, suid_finding1), (1, suid_finding2), (2, suid_finding3), (3, MagicMock())]  # 4th ignored
        ip_forward_indices = [(4, ip_finding1), (5, ip_finding2), (6, MagicMock())]  # 3rd ignored

        result = _build_related_finding_ids(suid_indices, ip_forward_indices)

        assert result == ['suid1', 'suid2', 'suid3', 'ip1', 'ip2']


class TestCreateSequenceCorrelation:
    """Test _create_sequence_correlation function."""

    def test_create_sequence_correlation(self):
        """Test creating sequence correlation."""
        related = ['finding1', 'finding2']
        existing_count = 2

        result = _create_sequence_correlation(related, existing_count)

        assert result.id == 'sequence_anom_3'
        assert result.title == 'Suspicious Sequence: New SUID followed by IP forwarding enabled'
        assert result.related_finding_ids == related
        assert result.risk_score_delta == 8
        assert 'sequence_anomaly' in result.tags
        assert result.severity == 'high'


class TestAddCorrelationRefs:
    """Test _add_correlation_refs function."""

    def test_add_correlation_refs(self):
        """Test adding correlation references to findings."""
        corr = MagicMock()
        corr.id = 'corr1'
        corr.related_finding_ids = ['finding1', 'finding2']

        finding1 = MagicMock()
        finding1.id = 'finding1'
        finding1.correlation_refs = None

        finding2 = MagicMock()
        finding2.id = 'finding2'
        finding2.correlation_refs = ['existing']

        finding3 = MagicMock()
        finding3.id = 'finding3'
        finding3.correlation_refs = None

        ordered = [finding1, finding2, finding3]

        state = MagicMock()

        _add_correlation_refs(state, corr, ordered)

        assert finding1.correlation_refs == ['corr1']
        assert finding2.correlation_refs == ['existing', 'corr1']
        assert finding3.correlation_refs is None


class TestSequenceCorrelation:
    """Test sequence_correlation function."""

    def test_sequence_correlation_triggered(self):
        """Test sequence correlation when trigger conditions met."""
        # Create findings
        suid_finding = MagicMock()
        suid_finding.id = 'suid1'
        suid_finding.tags = ['suid', 'baseline:new']
        suid_finding.correlation_refs = None

        ip_finding = MagicMock()
        ip_finding.id = 'ip1'
        ip_finding.category = 'kernel_param'
        ip_finding.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'}
        ip_finding.correlation_refs = None

        other_finding = MagicMock()
        other_finding.id = 'other1'

        # Set up scanner results
        scanner_result = MagicMock()
        scanner_result.findings = [suid_finding, other_finding, ip_finding]

        # Set up state
        state = MagicMock()
        state.report.results = [scanner_result]
        state.correlations = []

        sequence_correlation(state)

        # Should have created one correlation
        assert len(state.correlations) == 1
        corr = state.correlations[0]
        assert corr.id == 'sequence_anom_1'
        assert corr.related_finding_ids == ['suid1', 'ip1']
        assert 'sequence_anomaly' in corr.tags

        # Check correlation refs were added
        assert suid_finding.correlation_refs == ['sequence_anom_1']
        assert ip_finding.correlation_refs == ['sequence_anom_1']

    def test_sequence_correlation_no_trigger(self):
        """Test sequence correlation when conditions not met."""
        # IP forward before SUID
        ip_finding = MagicMock()
        ip_finding.id = 'ip1'
        ip_finding.category = 'kernel_param'
        ip_finding.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'}

        suid_finding = MagicMock()
        suid_finding.id = 'suid1'
        suid_finding.tags = ['suid', 'baseline:new']

        scanner_result = MagicMock()
        scanner_result.findings = [ip_finding, suid_finding]

        state = MagicMock()
        state.report.results = [scanner_result]
        state.correlations = []

        sequence_correlation(state)

        # Should not have created any correlations
        assert len(state.correlations) == 0

    def test_sequence_correlation_no_report(self):
        """Test sequence correlation with no report."""
        state = MagicMock()
        state.report = None

        sequence_correlation(state)

        # Should not crash