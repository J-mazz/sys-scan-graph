"""Tests for rules.py module."""

import pytest
import os
import json
import tempfile
from unittest.mock import MagicMock, patch

from sys_scan_agent import rules, models


class TestCorrelatorApply:
    """Test Correlator.apply method."""

    def test_apply_single_rule_all_logic(self):
        """Test applying rules with 'all' logic."""
        # Create test findings
        finding1 = MagicMock()
        finding1.id = 'f1'
        finding1.title = "IP forward enabled"
        finding1.tags = ['network']
        finding1.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'}

        finding2 = MagicMock()
        finding2.id = 'f2'
        finding2.title = "Other finding"
        finding2.tags = ['other']
        finding2.metadata = {}

        findings = [finding1, finding2]

        # Test rule
        test_rule = {
            'id': 'test_rule',
            'title': 'Test Correlation',
            'rationale': 'Test rationale',
            'conditions': [
                {'metadata_key': 'sysctl_key', 'metadata_contains': 'net.ipv4.ip_forward'}
            ],
            'logic': 'all',
            'risk_score_delta': 5,
            'tags': ['test']
        }

        correlator = rules.Correlator([test_rule])
        correlations = correlator.apply(findings)  # type: ignore

        assert len(correlations) == 1
        corr = correlations[0]
        assert corr.id == 'test_rule'
        assert corr.related_finding_ids == ['f1']
        assert corr.risk_score_delta == 5

    def test_apply_exposure_bonus(self):
        """Test exposure bonus calculation."""
        finding1 = MagicMock()
        finding1.id = 'f1'
        finding1.title = "SUID binary"
        finding1.tags = ['suid', 'listening']  # Two exposure tags
        finding1.metadata = {}

        findings = [finding1]

        test_rule = {
            'id': 'test_rule',
            'title': 'Test Correlation',
            'rationale': 'Test rationale',
            'conditions': [
                {'field': 'tags', 'contains': 'suid'}
            ],
            'logic': 'all',
            'risk_score_delta': 5,
            'tags': ['test']
        }

        correlator = rules.Correlator([test_rule])
        correlations = correlator.apply(findings)  # type: ignore

        assert len(correlations) == 1
        # Base delta 5 + exposure bonus 2 (for suid and listening) = 7
        assert correlations[0].risk_score_delta == 7

    def test_apply_no_matches(self):
        """Test rule with no matching findings."""
        finding1 = MagicMock()
        finding1.id = 'f1'
        finding1.title = "Normal finding"
        finding1.tags = ['normal']
        finding1.metadata = {}

        findings = [finding1]

        test_rule = {
            'id': 'test_rule',
            'title': 'Test Correlation',
            'rationale': 'Test rationale',
            'conditions': [
                {'field': 'tags', 'contains': 'suid'}
            ],
            'logic': 'all',
            'risk_score_delta': 5,
            'tags': ['test']
        }

        correlator = rules.Correlator([test_rule])
        correlations = correlator.apply(findings)  # type: ignore

        assert len(correlations) == 0


class TestMatchCondition:
    """Test match_condition static method."""

    def test_match_condition_field_contains(self):
        """Test field matching with contains condition."""
        finding = MagicMock()
        finding.title = "Test finding with keyword"
        finding.description = "Description"
        finding.tags = ['tag1']
        finding.metadata = {}

        cond = {"field": "title", "contains": "keyword"}
        result = rules.Correlator.match_condition(finding, cond)
        assert result is True

    def test_match_condition_metadata_key(self):
        """Test metadata key matching."""
        finding = MagicMock()
        finding.title = "Test"
        finding.description = "Description"
        finding.tags = ['tag1']
        finding.metadata = {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'}

        cond = {"metadata_key": "sysctl_key", "metadata_contains": "net.ipv4.ip_forward"}
        result = rules.Correlator.match_condition(finding, cond)
        assert result is True

    def test_match_condition_no_match(self):
        """Test condition that doesn't match."""
        finding = MagicMock()
        finding.title = "Test finding"
        finding.description = "Description"
        finding.tags = ['tag1']
        finding.metadata = {}

        cond = {"field": "title", "contains": "nonexistent"}
        result = rules.Correlator.match_condition(finding, cond)
        assert result is False


class TestLoadRulesDir:
    """Test load_rules_dir function."""

    def test_load_rules_dir_valid_json(self):
        """Test loading rules from JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, 'test.json')
            test_rule = {
                'id': 'test_rule',
                'title': 'Test Rule',
                'conditions': [{'field': 'title', 'contains': 'test'}]
            }

            with open(json_file, 'w') as f:
                json.dump(test_rule, f)

            result = rules.load_rules_dir(tmpdir)

            assert len(result) == 1
            assert result[0]['id'] == 'test_rule'

    def test_load_rules_dir_invalid_directory(self):
        """Test loading rules from invalid directory."""
        result = rules.load_rules_dir('/nonexistent/path')
        assert result == []

    def test_load_rules_dir_empty_directory(self):
        """Test loading rules from empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = rules.load_rules_dir(tmpdir)
            assert result == []


class TestCanonicalConditionSignature:
    """Test canonical_condition_signature function."""

    def test_canonical_condition_signature_simple(self):
        """Test signature generation for simple conditions."""
        rule = {
            'conditions': [
                {'field': 'title', 'contains': 'test'}
            ],
            'logic': 'all'
        }

        result = rules.canonical_condition_signature(rule)
        expected = "field:title|contains:test|logic=all"
        assert result == expected


class TestLintRules:
    """Test lint_rules function."""

    def test_lint_rules_no_issues(self):
        """Test linting rules with no issues."""
        test_rules = [
            {
                'id': 'rule1',
                'title': 'Rule 1',
                'conditions': [{'field': 'title', 'contains': 'test'}],
                'tags': ['tag1']
            }
        ]

        result = rules.lint_rules(test_rules)
        assert result == []

    def test_lint_rules_unreachable_rule(self):
        """Test detecting unreachable rules (same signature)."""
        test_rules = [
            {
                'id': 'rule1',
                'title': 'Rule 1',
                'conditions': [{'field': 'title', 'contains': 'test'}],
                'logic': 'all'
            },
            {
                'id': 'rule2',
                'title': 'Rule 2',
                'conditions': [{'field': 'title', 'contains': 'test'}],
                'logic': 'all'
            }
        ]

        result = rules.lint_rules(test_rules)

        assert len(result) == 1
        assert result[0]['code'] == 'unreachable'
        assert 'shadowed_by=rule1' in result[0]['detail']


class TestDryRunApply:
    """Test dry_run_apply function."""

    def test_dry_run_apply_single_rule(self):
        """Test dry run with single rule."""
        finding1 = MagicMock()
        finding1.id = 'f1'
        finding1.title = "Test finding"
        finding1.tags = ['test']
        finding1.metadata = {}

        findings = [finding1]

        test_rules = [
            {
                'id': 'test_rule',
                'conditions': [{'field': 'tags', 'contains': 'test'}],
                'logic': 'all'
            }
        ]

        result = rules.dry_run_apply(test_rules, findings)  # type: ignore

        assert 'test_rule' in result
        assert result['test_rule'] == ['f1']

    def test_dry_run_apply_no_matches(self):
        """Test dry run with no matching findings."""
        finding1 = MagicMock()
        finding1.id = 'f1'
        finding1.title = "Test finding"
        finding1.tags = ['other']
        finding1.metadata = {}

        findings = [finding1]

        test_rules = [
            {
                'id': 'test_rule',
                'conditions': [{'field': 'tags', 'contains': 'test'}],
                'logic': 'all'
            }
        ]

        result = rules.dry_run_apply(test_rules, findings)  # type: ignore

        assert 'test_rule' in result
        assert result['test_rule'] == []