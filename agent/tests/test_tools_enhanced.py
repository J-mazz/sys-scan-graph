"""Tests for enhanced tools module.

This module tests the enhanced security analysis tools including:
- Multi-source baseline querying
- External data integration
- Compliance validation
- Report generation
- Stakeholder notification (air-gapped)
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
import json

from sys_scan_agent import tools_enhanced


class TestQueryBaselineEnhanced:
    """Test enhanced baseline querying functionality."""

    @pytest.mark.asyncio
    async def test_query_baseline_enhanced_success(self):
        """Test successful baseline querying with multiple sources."""
        findings = [
            {'id': 'finding_1', 'title': 'Test finding 1'},
            {'id': 'finding_2', 'title': 'Test finding 2'}
        ]

        with patch('sys_scan_agent.baseline.BaselineStore') as mock_store_class, \
             patch('sys_scan_agent.tools_enhanced._query_external_baseline', new_callable=AsyncMock) as mock_external:

            # Setup mock local baseline
            mock_store = MagicMock()
            mock_store.query.return_value = {
                'status': 'known',
                'last_seen': '2024-01-01T00:00:00',
                'frequency': 5
            }
            mock_store_class.return_value = mock_store

            # Setup mock external baseline
            mock_external.return_value = {
                'external_frequency': 10,
                'external_last_seen': datetime.now().isoformat(),
                'external_risk_level': 'low'
            }

            result = await tools_enhanced.query_baseline_enhanced(findings, 'test_host')

            assert result['query_type'] == 'baseline_enhanced'
            assert 'finding_1' in result['results']
            assert 'finding_2' in result['results']
            assert 'local' in result['sources_used']
            assert 'external' in result['sources_used']
            assert 'timestamp' in result

    @pytest.mark.asyncio
    async def test_query_baseline_enhanced_local_only(self):
        """Test baseline querying with only local source available."""
        findings = [{'id': 'finding_1', 'title': 'Test finding'}]

        with patch('sys_scan_agent.baseline.BaselineStore') as mock_store_class, \
             patch('sys_scan_agent.tools_enhanced._query_external_baseline', new_callable=AsyncMock) as mock_external:

            # Setup mock local baseline
            mock_store = MagicMock()
            mock_store.query.return_value = {
                'status': 'known',
                'last_seen': '2024-01-01T00:00:00',
                'frequency': 3
            }
            mock_store_class.return_value = mock_store

            # External baseline fails
            mock_external.side_effect = Exception("External service unavailable")

            result = await tools_enhanced.query_baseline_enhanced(findings, 'test_host')

            assert result['query_type'] == 'baseline_enhanced'
            assert 'finding_1' in result['results']
            assert result['sources_used'] == ['local']

    @pytest.mark.asyncio
    async def test_query_baseline_enhanced_no_findings(self):
        """Test baseline querying with empty findings list."""
        result = await tools_enhanced.query_baseline_enhanced([], 'test_host')

        assert result['query_type'] == 'baseline_enhanced'
        assert result['results'] == {}
        assert result['sources_used'] == []

    @pytest.mark.asyncio
    async def test_query_baseline_enhanced_missing_finding_id(self):
        """Test baseline querying with findings missing IDs."""
        findings = [{'title': 'Test finding without ID'}]

        result = await tools_enhanced.query_baseline_enhanced(findings, 'test_host')

        assert result['query_type'] == 'baseline_enhanced'
        assert result['results'] == {}
        assert result['sources_used'] == []

    @pytest.mark.asyncio
    async def test_query_baseline_enhanced_all_sources_fail(self):
        """Test baseline querying when all sources fail."""
        findings = [{'id': 'finding_1', 'title': 'Test finding'}]

        with patch('sys_scan_agent.baseline.BaselineStore') as mock_store_class, \
             patch('sys_scan_agent.tools_enhanced._query_external_baseline', new_callable=AsyncMock) as mock_external:

            # Local baseline fails
            mock_store_class.side_effect = Exception("Baseline store unavailable")
            # External baseline fails
            mock_external.side_effect = Exception("External service unavailable")

            result = await tools_enhanced.query_baseline_enhanced(findings, 'test_host')

            assert result['query_type'] == 'baseline_enhanced'
            assert 'finding_1' in result['results']
            assert result['results']['finding_1']['status'] == 'unknown'
            assert result['sources_used'] == []


class TestSearchExternalData:
    """Test external data search functionality."""

    @pytest.mark.asyncio
    async def test_search_external_data_success(self):
        """Test successful external data search."""
        queries = ['vulnerability_1', 'threat_2']

        with patch('sys_scan_agent.tools_enhanced._search_cve_database', new_callable=AsyncMock) as mock_cve, \
             patch('sys_scan_agent.tools_enhanced._search_threat_intelligence', new_callable=AsyncMock) as mock_ti:

            # Setup mock CVE results
            mock_cve.return_value = [
                {
                    'type': 'cve',
                    'id': 'CVE-2024-12345',
                    'description': 'Test vulnerability',
                    'severity': 'high'
                }
            ]

            # Setup mock threat intel results
            mock_ti.return_value = [
                {
                    'type': 'threat_intel',
                    'source': 'threat_feed_1',
                    'indicator': 'threat_2',
                    'confidence': 0.8
                }
            ]

            result = await tools_enhanced.search_external_data(queries)

            assert result['search_type'] == 'external_data'
            assert 'vulnerability_1' in result['results']
            assert 'threat_2' in result['results']
            assert result['results']['vulnerability_1']['total_found'] == 2  # CVE + threat intel
            assert result['results']['threat_2']['total_found'] == 2  # CVE + threat intel
            assert 'timestamp' in result

    @pytest.mark.asyncio
    async def test_search_external_data_empty_queries(self):
        """Test external data search with empty query list."""
        result = await tools_enhanced.search_external_data([])

        assert result['search_type'] == 'external_data'
        assert result['results'] == {}

    @pytest.mark.asyncio
    async def test_search_external_data_cve_failure(self):
        """Test external data search when CVE search fails."""
        queries = ['test_query']

        with patch('sys_scan_agent.tools_enhanced._search_cve_database', new_callable=AsyncMock) as mock_cve, \
             patch('sys_scan_agent.tools_enhanced._search_threat_intelligence', new_callable=AsyncMock) as mock_ti:

            # CVE search fails
            mock_cve.side_effect = Exception("CVE service unavailable")

            # Threat intel succeeds
            mock_ti.return_value = [
                {
                    'type': 'threat_intel',
                    'source': 'threat_feed_1',
                    'indicator': 'test_query',
                    'confidence': 0.9
                }
            ]

            result = await tools_enhanced.search_external_data(queries)

            assert result['search_type'] == 'external_data'
            assert 'test_query' in result['results']
            assert result['results']['test_query']['total_found'] == 1
            assert result['results']['test_query']['sources_searched'] == ['cve', 'threat_intel']

    @pytest.mark.asyncio
    async def test_search_external_data_all_sources_fail(self):
        """Test external data search when all sources fail."""
        queries = ['test_query']

        with patch('sys_scan_agent.tools_enhanced._search_cve_database', new_callable=AsyncMock) as mock_cve, \
             patch('sys_scan_agent.tools_enhanced._search_threat_intelligence', new_callable=AsyncMock) as mock_ti:

            # All sources fail
            mock_cve.side_effect = Exception("CVE service unavailable")
            mock_ti.side_effect = Exception("Threat intel service unavailable")

            result = await tools_enhanced.search_external_data(queries)

            assert result['search_type'] == 'external_data'
            assert 'test_query' in result['results']
            assert result['results']['test_query']['total_found'] == 0
            assert result['results']['test_query']['results'] == []


class TestValidateCompliance:
    """Test compliance validation functionality."""

    @pytest.mark.asyncio
    async def test_validate_compliance_success_compliant(self):
        """Test compliance validation with compliant findings."""
        findings = [
            {'id': 'finding_1', 'category': 'software', 'severity': 'low'},
            {'id': 'finding_2', 'category': 'configuration', 'severity': 'medium'}
        ]
        standards = ['pci_dss', 'hipaa']

        result = await tools_enhanced.validate_compliance(findings, standards)

        assert result['validation_type'] == 'compliance'
        assert result['standards_checked'] == standards
        assert result['overall_compliant'] is True
        assert all(r['compliant'] for r in result['results'].values())

    @pytest.mark.asyncio
    async def test_validate_compliance_with_violations(self):
        """Test compliance validation with violations."""
        findings = [
            {'id': 'finding_1', 'category': 'network', 'severity': 'high'},  # Violates PCI DSS
            {'id': 'finding_2', 'category': 'privacy', 'severity': 'medium'}  # Violates HIPAA
        ]
        standards = ['pci_dss', 'hipaa']

        result = await tools_enhanced.validate_compliance(findings, standards)

        assert result['validation_type'] == 'compliance'
        assert result['overall_compliant'] is False
        assert result['results']['pci_dss']['compliant'] is False
        assert result['results']['hipaa']['compliant'] is False
        assert result['results']['pci_dss']['violation_count'] == 1
        assert result['results']['hipaa']['violation_count'] == 1

    @pytest.mark.asyncio
    async def test_validate_compliance_default_standards(self):
        """Test compliance validation with default standards."""
        findings = []

        result = await tools_enhanced.validate_compliance(findings)

        assert result['validation_type'] == 'compliance'
        assert 'pci_dss' in result['standards_checked']
        assert 'hipaa' in result['standards_checked']
        assert 'nist_csf' in result['standards_checked']
        assert result['overall_compliant'] is True

    @pytest.mark.asyncio
    async def test_validate_compliance_empty_findings(self):
        """Test compliance validation with empty findings."""
        result = await tools_enhanced.validate_compliance([])

        assert result['validation_type'] == 'compliance'
        assert result['overall_compliant'] is True
        assert all(r['compliant'] for r in result['results'].values())


class TestGenerateReport:
    """Test report generation functionality."""

    @pytest.mark.asyncio
    async def test_generate_report_json(self):
        """Test JSON report generation."""
        state = {
            'session_id': 'test_session_123',
            'summary': {'total_findings': 5},
            'enriched_findings': [
                {'id': 'f1', 'title': 'Finding 1', 'severity': 'high'},
                {'id': 'f2', 'title': 'Finding 2', 'severity': 'medium'}
            ],
            'correlations': [{'id': 'c1', 'related': ['f1', 'f2']}],
            'metrics': {'processing_time': 120},
            'warnings': ['Warning 1'],
            'compliance_check': {'compliant': True},
            'risk_assessment': {'overall_risk': 'medium'}
        }

        result = await tools_enhanced.generate_report(state, 'json')

        assert result['generation_type'] == 'report'
        assert result['format'] == 'json'
        assert 'content' in result
        assert result['size_bytes'] > 0

        # Verify JSON content
        content = json.loads(result['content'])
        assert content['session_id'] == 'test_session_123'
        assert len(content['findings']) == 2

    @pytest.mark.asyncio
    async def test_generate_report_html(self):
        """Test HTML report generation."""
        state = {
            'session_id': 'test_session_456',
            'summary': {'total_findings': 3},
            'enriched_findings': [
                {'title': 'HTML Finding', 'severity': 'high'}
            ]
        }

        result = await tools_enhanced.generate_report(state, 'html')

        assert result['generation_type'] == 'report'
        assert result['format'] == 'html'
        assert 'content' in result
        assert '<html>' in result['content']
        assert 'test_session_456' in result['content']

    @pytest.mark.asyncio
    async def test_generate_report_pdf(self):
        """Test PDF report generation (placeholder)."""
        state = {
            'session_id': 'test_session_789',
            'enriched_findings': [{'title': 'PDF Finding'}]
        }

        result = await tools_enhanced.generate_report(state, 'pdf')

        assert result['generation_type'] == 'report'
        assert result['format'] == 'pdf'
        assert 'content' in result
        assert 'PDF Report Placeholder' in result['content']

    @pytest.mark.asyncio
    async def test_generate_report_unknown_format(self):
        """Test report generation with unknown format."""
        state = {'session_id': 'test_session'}

        result = await tools_enhanced.generate_report(state, 'unknown')

        assert result['generation_type'] == 'report'
        assert result['format'] == 'unknown'
        assert 'content' in result

        # Should default to JSON
        content = json.loads(result['content'])
        assert content['session_id'] == 'test_session'

    @pytest.mark.asyncio
    async def test_generate_report_empty_state(self):
        """Test report generation with minimal state."""
        state = {}

        result = await tools_enhanced.generate_report(state, 'json')

        assert result['generation_type'] == 'report'
        assert 'content' in result

        content = json.loads(result['content'])
        assert content['findings'] == []


class TestNotifyStakeholders:
    """Test stakeholder notification functionality."""

    @pytest.mark.asyncio
    async def test_notify_stakeholders_air_gapped(self):
        """Test stakeholder notification in air-gapped environment."""
        state = {'session_id': 'test_session'}
        channels = ['email', 'slack', 'webhook']

        result = await tools_enhanced.notify_stakeholders(state, channels)

        assert result['notification_type'] == 'stakeholder_alert'
        assert result['status'] == 'disabled'
        assert result['reason'] == 'air_gapped_deployment'
        assert 'air-gapped' in result['message']

    @pytest.mark.asyncio
    async def test_notify_stakeholders_default_channels(self):
        """Test stakeholder notification with default channels."""
        state = {'session_id': 'test_session'}

        result = await tools_enhanced.notify_stakeholders(state)

        assert result['notification_type'] == 'stakeholder_alert'
        assert result['status'] == 'disabled'


class TestPrivateFunctions:
    """Test private helper functions."""

    @pytest.mark.asyncio
    async def test_query_external_baseline(self):
        """Test external baseline querying."""
        result = await tools_enhanced._query_external_baseline('test_finding', 'test_host')

        assert result is not None
        assert 'external_frequency' in result
        assert 'external_last_seen' in result
        assert 'external_risk_level' in result

    @pytest.mark.asyncio
    async def test_search_cve_database(self):
        """Test CVE database search."""
        results = await tools_enhanced._search_cve_database('test_query')

        assert len(results) == 1
        assert results[0]['type'] == 'cve'
        assert 'CVE-2024-12345' in results[0]['id']
        assert results[0]['severity'] == 'high'

    @pytest.mark.asyncio
    async def test_search_threat_intelligence(self):
        """Test threat intelligence search."""
        results = await tools_enhanced._search_threat_intelligence('test_query')

        assert len(results) == 1
        assert results[0]['type'] == 'threat_intel'
        assert results[0]['confidence'] == 0.8

    def test_violates_standard_pci_dss(self):
        """Test PCI DSS compliance checking."""
        # Should violate
        high_severity_network = {'category': 'network', 'severity': 'high'}
        assert tools_enhanced._violates_standard(high_severity_network, 'pci_dss')

        # Should not violate
        low_severity_software = {'category': 'software', 'severity': 'low'}
        assert not tools_enhanced._violates_standard(low_severity_software, 'pci_dss')

    def test_violates_standard_hipaa(self):
        """Test HIPAA compliance checking."""
        # Should violate
        privacy_finding = {'category': 'privacy', 'severity': 'low'}
        assert tools_enhanced._violates_standard(privacy_finding, 'hipaa')

        data_finding = {'category': 'data', 'severity': 'medium'}
        assert tools_enhanced._violates_standard(data_finding, 'hipaa')

        # Should not violate
        network_finding = {'category': 'network', 'severity': 'high'}
        assert not tools_enhanced._violates_standard(network_finding, 'hipaa')

    def test_violates_standard_nist_csf(self):
        """Test NIST CSF compliance checking."""
        # Should violate
        critical_finding = {'category': 'any', 'severity': 'critical'}
        assert tools_enhanced._violates_standard(critical_finding, 'nist_csf')

        # Should not violate
        high_finding = {'category': 'any', 'severity': 'high'}
        assert not tools_enhanced._violates_standard(high_finding, 'nist_csf')

    def test_violates_standard_unknown(self):
        """Test compliance checking for unknown standard."""
        finding = {'category': 'any', 'severity': 'critical'}
        assert not tools_enhanced._violates_standard(finding, 'unknown_standard')