from __future__ import annotations
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from sys_scan_agent.models import AgentState
from sys_scan_agent.pipeline import load_report, augment, correlate, baseline_rarity, process_novelty, sequence_correlation, reduce, summarize
from sys_scan_agent.counterfactual import what_if, apply_ip_forward_disabled, recompute_risk
from sys_scan_agent import models


def build_report():
    findings = []
    # ip_forward enabled
    findings.append({'id':'ipf','title':'Enable IP forwarding','severity':'medium','risk_score':30,'metadata':{'sysctl_key':'net.ipv4.ip_forward','value':'1'},'tags':['kernel_param']})
    # Odd binary path (novelty expected)
    findings.append({'id':'proc1','title':'/tmp/.weird_hidden_binary_xyz','severity':'medium','risk_score':20,'metadata':{'cmdline':'/tmp/.weird_hidden_binary_xyz'},'tags':[]})
    report = {
        'meta': {'hostname':'hostCF'},
        'summary': {'finding_count_total':2,'finding_count_emitted':2,'severity_counts':{'medium':2}},
        'results': [
            {'scanner':'kernel_params','finding_count':1,'findings':[findings[0]]},
            {'scanner':'process','finding_count':1,'findings':[findings[1]]}
        ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score':0}
    }
    return report


def test_counterfactual_and_novelty(tmp_path):
    rpt = build_report()
    p = tmp_path/'r.json'
    p.write_text(json.dumps(rpt))
    st = AgentState()
    st = load_report(st, p)
    st = augment(st)
    st = correlate(st)
    st = baseline_rarity(st, baseline_path=tmp_path/'baseline.db')
    st = process_novelty(st, baseline_path=tmp_path/'novelty.json')
    # Ensure novelty detection fires
    assert st.report and st.report.results
    novel = [f for r in st.report.results for f in r.findings if 'process_novel' in f.tags]
    assert novel, 'Novelty detection did not fire for odd binary path'
    st = sequence_correlation(st)
    st = reduce(st)
    st.actions = []
    st = summarize(st)
    # Serialize enriched output for counterfactual
    assert st.report and st.report.results
    enriched = {
        'correlations': [c.model_dump() for c in st.correlations],
        'reductions': st.reductions,
        'summaries': st.summaries.model_dump() if st.summaries else {},
        'actions': [a.model_dump() for a in st.actions],
        'enriched_findings': [f.model_dump() for r in st.report.results for f in r.findings]
    }
    enriched_path = tmp_path / 'enriched.json'
    enriched_path.write_text(json.dumps(enriched))
    cf = what_if(enriched_path, ip_forward_disabled=True)
    assert cf['scenario']['ip_forward_disabled'] is True
    assert any(d['delta'] <= 0 for d in cf['changed_findings'])
    # ATT&CK coverage should be present (even if subset)
    if cf['technique_coverage']:
        assert 'technique_count' in cf['technique_coverage']


class TestApplyIPForwardDisabled:
    """Test the apply_ip_forward_disabled function."""

    def test_apply_ip_forward_disabled_basic(self):
        """Test basic IP forward disabled counterfactual."""
        # Create an actual Finding object
        finding = models.Finding(
            id="test_ip_forward",
            title="IP Forward Enabled",
            severity="high",
            risk_score=80,
            metadata={'value': '1', 'sysctl_key': 'net.ipv4.ip_forward'},
            risk_subscores={'impact': 8.0, 'exposure': 6.0, 'anomaly': 4.0, 'confidence': 7.0}
        )

        result = apply_ip_forward_disabled(finding)

        # Check that it's a different object (deep copy)
        assert result is not finding
        assert result.id == finding.id

        # Check metadata changes
        assert result.metadata['value'] == '0'
        assert result.metadata['counterfactual_original_value'] == '1'

        # Check risk subscore modifications
        assert result.risk_subscores is not None
        assert result.risk_subscores['impact'] == 3.2  # 8.0 * 0.4
        assert result.risk_subscores['exposure'] == 5.5  # 6.0 - 0.5

    def test_apply_ip_forward_disabled_no_metadata(self):
        """Test with finding that has no metadata."""
        finding = models.Finding(
            id="test_no_metadata",
            title="Test Finding",
            severity="medium",
            risk_score=60,
            risk_subscores={'impact': 5.0, 'exposure': 3.0}
        )

        result = apply_ip_forward_disabled(finding)

        assert result.metadata is not None
        assert result.metadata['value'] == '0'
        assert result.metadata['counterfactual_original_value'] is None

    def test_apply_ip_forward_disabled_different_value_keys(self):
        """Test with different metadata value keys."""
        # Test with 'desired' key
        finding1 = models.Finding(
            id="test_desired",
            title="Test Finding",
            severity="medium",
            risk_score=60,
            metadata={'desired': 'enabled'},
            risk_subscores={'impact': 6.0, 'exposure': 4.0}
        )

        result1 = apply_ip_forward_disabled(finding1)
        assert result1.metadata['counterfactual_original_value'] == 'enabled'

        # Test with 'current' key
        finding2 = models.Finding(
            id="test_current",
            title="Test Finding",
            severity="medium",
            risk_score=60,
            metadata={'current': 'true'},
            risk_subscores={'impact': 7.0, 'exposure': 5.0}
        )

        result2 = apply_ip_forward_disabled(finding2)
        assert result2.metadata['counterfactual_original_value'] == 'true'

    def test_apply_ip_forward_disabled_no_risk_subscores(self):
        """Test with finding that has no risk subscores."""
        finding = models.Finding(
            id="test_no_subscores",
            title="Test Finding",
            severity="medium",
            risk_score=60,
            metadata={'value': '1'}
        )

        result = apply_ip_forward_disabled(finding)

        assert result.metadata['value'] == '0'
        assert result.risk_subscores is None

    def test_apply_ip_forward_disabled_min_values(self):
        """Test that risk subscores don't go below minimum values."""
        finding = models.Finding(
            id="test_min_values",
            title="Test Finding",
            severity="medium",
            risk_score=60,
            metadata={'value': '1'},
            risk_subscores={'impact': 1.0, 'exposure': 0.3}  # Low values
        )

        result = apply_ip_forward_disabled(finding)

        assert result.metadata['value'] == '0'
        # Risk subscores should be modified
        assert result.risk_subscores is not None
        assert result.risk_subscores['impact'] == 0.5  # max(0.5, 1.0 * 0.4)
        assert result.risk_subscores['exposure'] == 0.0  # max(0.0, 0.3 - 0.5)


class TestRecomputeRisk:
    """Test the recompute_risk function."""

    @patch('sys_scan_agent.counterfactual.load_persistent_weights')
    @patch('sys_scan_agent.counterfactual.compute_risk')
    @patch('sys_scan_agent.counterfactual.apply_probability')
    def test_recompute_risk_normal_case(self, mock_apply_prob, mock_compute_risk, mock_load_weights):
        """Test recompute_risk with normal findings that have risk subscores."""
        mock_load_weights.return_value = {'impact': 0.4, 'exposure': 0.3, 'anomaly': 0.2, 'confidence': 0.1}
        mock_compute_risk.return_value = (75.0, 25.0)  # (score, raw_weighted_sum)
        mock_apply_prob.return_value = 0.85

        # Create actual Finding objects instead of MagicMock
        finding1 = models.Finding(
            id='test1',
            title='Test Finding 1',
            severity='high',
            risk_score=80,
            risk_subscores={'impact': 8.0, 'exposure': 6.0, 'anomaly': 4.0, 'confidence': 7.0}
        )
        finding2 = models.Finding(
            id='test2',
            title='Test Finding 2',
            severity='medium',
            risk_score=60,
            risk_subscores={'impact': 5.0, 'exposure': 4.0, 'anomaly': 3.0, 'confidence': 6.0}
        )
        findings = [finding1, finding2]

        recompute_risk(findings)

        # Verify load_persistent_weights was called
        mock_load_weights.assert_called_once()

        # Verify compute_risk was called for each finding
        assert mock_compute_risk.call_count == 2
        # Check that compute_risk was called with the expected subscores and weights
        calls = mock_compute_risk.call_args_list
        assert len(calls) == 2
        # First call should have finding1's subscores
        assert calls[0][0][0]['impact'] == 8.0
        assert calls[0][0][0]['exposure'] == 6.0
        # Second call should have finding2's subscores  
        assert calls[1][0][0]['impact'] == 5.0
        assert calls[1][0][0]['exposure'] == 4.0

        # Verify apply_probability was called
        assert mock_apply_prob.call_count == 2
        mock_apply_prob.assert_called_with(25.0)

        # Verify findings were updated
        assert finding1.risk_score == 75.0
        assert finding1.risk_total == 75.0
        assert finding1.probability_actionable == 0.85
        assert finding1.risk_subscores is not None
        assert finding1.risk_subscores['_raw_weighted_sum'] == 25.0

        assert finding2.risk_score == 75.0
        assert finding2.risk_total == 75.0
        assert finding2.probability_actionable == 0.85
        assert finding2.risk_subscores is not None
        assert finding2.risk_subscores['_raw_weighted_sum'] == 25.0

    @patch('sys_scan_agent.counterfactual.load_persistent_weights')
    def test_recompute_risk_no_subscores(self, mock_load_weights):
        """Test recompute_risk with findings that have no risk subscores."""
        mock_load_weights.return_value = {'impact': 0.4, 'exposure': 0.3}

        finding1 = models.Finding(
            id='test1',
            title='Test Finding 1',
            severity='high',
            risk_score=80
        )
        finding2 = models.Finding(
            id='test2',
            title='Test Finding 2',
            severity='medium',
            risk_score=60,
            risk_subscores={}
        )
        findings = [finding1, finding2]

        recompute_risk(findings)

        # Verify no changes were made to findings without subscores
        assert finding1.risk_subscores is None
        assert finding2.risk_subscores == {}

    @patch('sys_scan_agent.counterfactual.load_persistent_weights')
    def test_recompute_risk_empty_list(self, mock_load_weights):
        """Test recompute_risk with empty findings list."""
        mock_load_weights.return_value = {'impact': 0.4}

        recompute_risk([])

        # Should not crash with empty list
        mock_load_weights.assert_called_once()


class TestWhatIfExtended:
    """Extended tests for the what_if function."""

    def test_what_if_no_ip_forward_change(self, tmp_path):
        """Test what_if with ip_forward_disabled=False."""
        from sys_scan_agent.models import Summaries
        enriched_data = {
            'enriched_findings': [
                {
                    'id': 'ipf1',
                    'title': 'Enable IP forwarding',
                    'severity': 'medium',
                    'category': 'kernel_param',
                    'metadata': {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'},
                    'risk_total': 80.0,
                    'risk_score': 80.0
                }
            ],
            'correlations': [],
            'reductions': {},
            'summaries': Summaries(attack_coverage={'technique_count': 10}).model_dump(),
            'actions': []
        }

        enriched_path = tmp_path / 'enriched.json'
        enriched_path.write_text(json.dumps(enriched_data))

        result = what_if(enriched_path, ip_forward_disabled=False)

        assert result['scenario']['ip_forward_disabled'] is False
        assert result['changed_findings'] == []
        assert len(result['residual_high_risk_ids']) == 1
        assert result['residual_high_risk_ids'] == ['ipf1']

    def test_what_if_no_findings(self, tmp_path):
        """Test what_if with no findings."""
        from sys_scan_agent.models import Summaries
        enriched_data = {
            'enriched_findings': [],
            'correlations': [],
            'reductions': {},
            'summaries': Summaries().model_dump(),
            'actions': []
        }

        enriched_path = tmp_path / 'enriched.json'
        enriched_path.write_text(json.dumps(enriched_data))

        result = what_if(enriched_path, ip_forward_disabled=True)

        assert result['scenario']['ip_forward_disabled'] is True
        assert result['changed_findings'] == []
        assert result['residual_high_risk_ids'] == []
        assert result['original_high_threshold'] == 0

    def test_what_if_multiple_ip_forward_findings(self, tmp_path):
        """Test what_if with multiple IP forward findings."""
        from sys_scan_agent.models import Summaries
        enriched_data = {
            'enriched_findings': [
                {
                    'id': 'ipf1',
                    'title': 'Enable IP forwarding',
                    'severity': 'medium',
                    'category': 'kernel_param',
                    'metadata': {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'},
                    'risk_total': 80.0,
                    'risk_score': 80.0,
                    'risk_subscores': {'impact': 8.0, 'exposure': 6.0}
                },
                {
                    'id': 'ipf2',
                    'title': 'Enable IP forwarding',
                    'severity': 'medium',
                    'category': 'kernel_param',
                    'metadata': {'sysctl_key': 'net.ipv4.ip_forward', 'value': 'true'},
                    'risk_total': 75.0,
                    'risk_score': 75.0,
                    'risk_subscores': {'impact': 7.0, 'exposure': 5.0}
                },
                {
                    'id': 'other',
                    'title': 'Other finding',
                    'severity': 'low',
                    'category': 'other',
                    'metadata': {},
                    'risk_total': 50.0,
                    'risk_score': 50.0
                }
            ],
            'correlations': [],
            'reductions': {},
            'summaries': Summaries().model_dump(),
            'actions': []
        }

        enriched_path = tmp_path / 'enriched.json'
        enriched_path.write_text(json.dumps(enriched_data))

        with patch('sys_scan_agent.counterfactual.recompute_risk') as mock_recompute:
            result = what_if(enriched_path, ip_forward_disabled=True)

        assert len(result['changed_findings']) == 2
        assert result['changed_findings'][0]['id'] == 'ipf1'
        assert result['changed_findings'][1]['id'] == 'ipf2'

        # Verify recompute_risk was called
        mock_recompute.assert_called_once()

    def test_what_if_no_summaries(self, tmp_path):
        """Test what_if when summaries is None (should fallback to empty Summaries)."""
        from sys_scan_agent.models import Summaries
        enriched_data = {
            'enriched_findings': [
                {
                    'id': 'test1',
                    'title': 'Test finding',
                    'severity': 'low',
                    'risk_total': 60.0,
                    'risk_score': 60.0
                }
            ],
            'correlations': [],
            'reductions': {},
            'summaries': Summaries().model_dump(),
            'actions': []
        }

        enriched_path = tmp_path / 'enriched.json'
        enriched_path.write_text(json.dumps(enriched_data))

        result = what_if(enriched_path, ip_forward_disabled=False)

        assert result['technique_coverage'] is None

    def test_what_if_disabled_ip_forward_not_enabled(self, tmp_path):
        """Test what_if when IP forward is already disabled."""
        from sys_scan_agent.models import Summaries
        enriched_data = {
            'enriched_findings': [
                {
                    'id': 'ipf1',
                    'title': 'Enable IP forwarding',
                    'severity': 'medium',
                    'category': 'kernel_param',
                    'metadata': {'sysctl_key': 'net.ipv4.ip_forward', 'value': '0'},
                    'risk_total': 20.0,
                    'risk_score': 20.0
                }
            ],
            'correlations': [],
            'reductions': {},
            'summaries': Summaries().model_dump(),
            'actions': []
        }

        enriched_path = tmp_path / 'enriched.json'
        enriched_path.write_text(json.dumps(enriched_data))

        result = what_if(enriched_path, ip_forward_disabled=True)

        # Should not change since value is not '1', 'true', or 'enabled'
        assert result['changed_findings'] == []
        assert result['residual_high_risk_ids'] == ['ipf1']  # Below threshold, but still present due to threshold logic
