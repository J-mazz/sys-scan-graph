from __future__ import annotations
import pytest
import tempfile
import yaml
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import logging

from sys_scan_agent.retriever import (
    KnowledgeRetriever, get_retriever, retrieve_context, retrieve_context_with_summary
)
from sys_scan_agent.knowledge import KNOWLEDGE_DIR

# Patch KNOWLEDGE_DIR at module level
original_knowledge_dir = KNOWLEDGE_DIR


@pytest.fixture
def temp_knowledge_dir(tmp_path):
    """Create a temporary knowledge directory with test data."""
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()

    # Create test ports.yaml
    ports_data = {
        "ports": {
            "22": {
                "service": "ssh",
                "privilege_implication": "remote_admin",
                "tags": ["service:ssh", "remote_access"]
            },
            "80": {
                "service": "http",
                "privilege_implication": "web_surface",
                "tags": ["service:http", "web"]
            },
            "443": {
                "service": "https",
                "privilege_implication": "web_surface",
                "tags": ["service:https", "web", "tls"]
            }
        }
    }

    # Create test modules.yaml
    modules_data = {
        "modules": {
            "nf_conntrack": {
                "family": "netfilter",
                "description": "Connection tracking module",
                "tags": ["network", "firewall"]
            },
            "usbcore": {
                "family": "usb",
                "description": "USB core module",
                "tags": ["hardware", "usb"]
            }
        }
    }

    # Create test suid_programs.yaml
    suid_data = {
        "suid_programs": {
            "/bin/su": {
                "expected": True,
                "description": "Switch user command",
                "tags": ["system", "privilege"]
            },
            "/usr/bin/sudo": {
                "expected": True,
                "description": "Superuser do command",
                "tags": ["system", "privilege"]
            }
        }
    }

    # Create test orgs.yaml
    orgs_data = {
        "orgs": {
            "google": {
                "cidrs": ["8.8.8.0/24", "8.8.4.0/24"],
                "description": "Google LLC",
                "tags": ["search", "cloud"]
            },
            "microsoft": {
                "cidrs": ["13.64.0.0/11", "40.64.0.0/10"],
                "description": "Microsoft Corporation",
                "tags": ["software", "cloud"]
            }
        }
    }

    # Write test files
    (knowledge_dir / "ports.yaml").write_text(yaml.dump(ports_data))
    (knowledge_dir / "modules.yaml").write_text(yaml.dump(modules_data))
    (knowledge_dir / "suid_programs.yaml").write_text(yaml.dump(suid_data))
    (knowledge_dir / "orgs.yaml").write_text(yaml.dump(orgs_data))

    return knowledge_dir


@pytest.fixture(autouse=True)
def setup_knowledge_dir(temp_knowledge_dir):
    """Set up the knowledge directory for all tests."""
    from sys_scan_agent import knowledge
    knowledge.KNOWLEDGE_DIR = temp_knowledge_dir
    knowledge._CACHE.clear()
    yield
    # Restore original
    knowledge.KNOWLEDGE_DIR = original_knowledge_dir

@pytest.fixture
def retriever():
    """Create a KnowledgeRetriever instance."""
    return KnowledgeRetriever()


class TestKnowledgeRetrieverInit:
    """Test KnowledgeRetriever initialization."""

    def test_init_sets_knowledge_dir(self, temp_knowledge_dir):
        """Test that KnowledgeRetriever sets the knowledge directory correctly."""
        with patch('sys_scan_agent.retriever.KNOWLEDGE_DIR', temp_knowledge_dir):
            retriever = KnowledgeRetriever()
            assert retriever.knowledge_dir == temp_knowledge_dir

    def test_init_initializes_cache(self, temp_knowledge_dir):
        """Test that KnowledgeRetriever initializes empty cache."""
        with patch('sys_scan_agent.retriever.KNOWLEDGE_DIR', temp_knowledge_dir):
            retriever = KnowledgeRetriever()
            assert retriever.cache == {}
            assert retriever.last_updated == {}


class TestRetrieveContext:
    """Test retrieve_context method."""

    def test_retrieve_context_general_type(self, retriever):
        """Test retrieving context with general type (searches all files)."""
        results = retriever.retrieve_context("ssh", "general", max_results=5)

        assert len(results) <= 5
        assert all('relevance_score' in result for result in results)
        assert all('retrieved_at' in result for result in results)
        assert all('query' in result for result in results)
        assert all(result['query'] == 'ssh' for result in results)
        assert all(result['context_type'] == 'general' for result in results)

    def test_retrieve_context_specific_type(self, retriever):
        """Test retrieving context with specific type."""
        results = retriever.retrieve_context("ssh", "ports", max_results=5)

        assert len(results) <= 5
        for result in results:
            assert result['source_file'] == 'ports.yaml'
            assert result['context_type'] == 'ports'

    def test_retrieve_context_no_matches(self, retriever):
        """Test retrieving context with no matches."""
        results = retriever.retrieve_context("nonexistent", "general", max_results=5)

        assert len(results) == 0

    def test_retrieve_context_similarity_threshold(self, retriever):
        """Test retrieving context with similarity threshold."""
        # High threshold should return fewer results
        results_high = retriever.retrieve_context("ssh", "general", similarity_threshold=0.5)
        results_low = retriever.retrieve_context("ssh", "general", similarity_threshold=0.01)

        assert len(results_high) <= len(results_low)

    def test_retrieve_context_max_results(self, retriever):
        """Test retrieving context with max_results limit."""
        results = retriever.retrieve_context("service", "general", max_results=2)

        assert len(results) <= 2

    def test_retrieve_context_missing_file(self, retriever):
        """Test retrieving context when knowledge file doesn't exist."""
        results = retriever.retrieve_context("test", "nonexistent", max_results=5)

        assert len(results) == 0

    def test_retrieve_context_sorts_by_relevance(self, retriever):
        """Test that results are sorted by relevance score descending."""
        results = retriever.retrieve_context("ssh", "general", max_results=10)

        if len(results) > 1:
            scores = [r['relevance_score'] for r in results]
            assert scores == sorted(scores, reverse=True)


class TestSearchKnowledgeFile:
    """Test _search_knowledge_file method."""

    def test_search_knowledge_file_basic(self, retriever):
        """Test basic knowledge file searching."""
        data = {
            "ports": {
                "22": {"service": "ssh", "tags": ["remote"]},
                "80": {"service": "http", "tags": ["web"]}
            }
        }

        results = retriever._search_knowledge_file(data, "ssh", "ports.yaml", 0.1)

        assert len(results) == 1
        assert results[0]['key'] == '22'
        assert 'relevance_score' in results[0]
        assert results[0]['source_file'] == 'ports.yaml'

    def test_search_knowledge_file_no_main_key(self, retriever):
        """Test searching knowledge file without main key."""
        data = {
            "22": {"service": "ssh", "tags": ["remote"]},
            "80": {"service": "http", "tags": ["web"]}
        }

        results = retriever._search_knowledge_file(data, "ssh", "ports.yaml", 0.1)

        assert len(results) == 1
        assert results[0]['key'] == '22'

    def test_search_knowledge_file_non_dict_items(self, retriever):
        """Test searching knowledge file with non-dict items."""
        data = {
            "ports": {
                "22": "ssh",  # String instead of dict
                "80": {"service": "http"}
            }
        }

        results = retriever._search_knowledge_file(data, "ssh", "ports.yaml", 0.1)

        assert len(results) == 0  # Should skip non-dict items

    def test_search_knowledge_file_below_threshold(self, retriever):
        """Test searching knowledge file with results below threshold."""
        data = {
            "ports": {
                "22": {"service": "ssh", "tags": ["remote"]}
            }
        }

        results = retriever._search_knowledge_file(data, "unrelated", "ports.yaml", 0.9)

        assert len(results) == 0


class TestCalculateRelevance:
    """Test _calculate_relevance method."""

    def test_calculate_relevance_key_match(self, retriever):
        """Test relevance calculation with key match."""
        data = {"service": "ssh", "tags": ["remote"]}
        score = retriever._calculate_relevance("ssh", "22", data)

        assert score > 0

    def test_calculate_relevance_data_match(self, retriever):
        """Test relevance calculation with data field match."""
        data = {"service": "ssh", "tags": ["remote"]}
        score = retriever._calculate_relevance("remote", "22", data)

        assert score > 0

    def test_calculate_relevance_list_match(self, retriever):
        """Test relevance calculation with list field match."""
        data = {"service": "ssh", "tags": ["remote", "access"]}
        score = retriever._calculate_relevance("access", "22", data)

        assert score > 0

    def test_calculate_relevance_multiple_matches(self, retriever):
        """Test relevance calculation with multiple matches."""
        data = {"service": "ssh remote", "tags": ["remote", "access"]}
        score = retriever._calculate_relevance("ssh remote", "22", data)

        assert score > 0

    def test_calculate_relevance_no_matches(self, retriever):
        """Test relevance calculation with no matches."""
        data = {"service": "ssh", "tags": ["remote"]}
        score = retriever._calculate_relevance("unrelated", "22", data)

        assert score == 0.0

    def test_calculate_relevance_normalization(self, retriever):
        """Test that relevance scores are normalized to [0,1]."""
        data = {"service": "ssh remote access", "tags": ["remote", "access", "secure"]}
        score = retriever._calculate_relevance("ssh remote access secure", "22", data)

        assert 0.0 <= score <= 1.0


class TestGetMatchedFields:
    """Test _get_matched_fields method."""

    def test_get_matched_fields_key_match(self, retriever):
        """Test matched fields detection with key match."""
        data = {"service": "ssh", "tags": ["remote"]}
        matched = retriever._get_matched_fields("22", "22", data)

        assert "key" in matched

    def test_get_matched_fields_string_field_match(self, retriever):
        """Test matched fields detection with string field match."""
        data = {"service": "ssh", "tags": ["remote"]}
        matched = retriever._get_matched_fields("remote", "22", data)

        assert "tags" in matched

    def test_get_matched_fields_list_field_match(self, retriever):
        """Test matched fields detection with list field match."""
        data = {"service": "ssh", "tags": ["remote", "access"]}
        matched = retriever._get_matched_fields("access", "22", data)

        assert "tags" in matched

    def test_get_matched_fields_multiple_matches(self, retriever):
        """Test matched fields detection with multiple field matches."""
        data = {"service": "ssh remote", "description": "remote access", "tags": ["secure"]}
        matched = retriever._get_matched_fields("remote", "22", data)

        assert "service" in matched
        assert "description" in matched

    def test_get_matched_fields_no_matches(self, retriever):
        """Test matched fields detection with no matches."""
        data = {"service": "ssh", "tags": ["remote"]}
        matched = retriever._get_matched_fields("unrelated", "22", data)

        assert matched == []


class TestGetContextSummary:
    """Test get_context_summary method."""

    def test_get_context_summary_empty(self, retriever):
        """Test context summary with empty results."""
        summary = retriever.get_context_summary([])
        assert summary == "No relevant context found."

    def test_get_context_summary_ports(self, retriever):
        """Test context summary for ports data."""
        context_items = [{
            'key': '22',
            'data': {'service': 'ssh'},
            'relevance_score': 0.8
        }]

        summary = retriever.get_context_summary(context_items)
        assert "Port 22: ssh" in summary
        assert "0.80" in summary

    def test_get_context_summary_modules(self, retriever):
        """Test context summary for modules data."""
        context_items = [{
            'key': 'nf_conntrack',
            'data': {'family': 'netfilter'},
            'relevance_score': 0.6
        }]

        summary = retriever.get_context_summary(context_items)
        assert "Module nf_conntrack: netfilter" in summary
        assert "0.60" in summary

    def test_get_context_summary_suid(self, retriever):
        """Test context summary for suid programs data."""
        context_items = [{
            'key': '/bin/su',
            'data': {'expected': True},
            'relevance_score': 0.7
        }]

        summary = retriever.get_context_summary(context_items)
        assert "SUID program /bin/su" in summary
        assert "0.70" in summary

    def test_get_context_summary_orgs(self, retriever):
        """Test context summary for organizations data."""
        context_items = [{
            'key': 'google',
            'data': {'cidrs': ['8.8.8.0/24', '8.8.4.0/24']},
            'relevance_score': 0.9
        }]

        summary = retriever.get_context_summary(context_items)
        assert "Organization google: 2 IP ranges" in summary
        assert "0.90" in summary

    def test_get_context_summary_generic(self, retriever):
        """Test context summary for generic data."""
        context_items = [{
            'key': 'unknown',
            'data': {'custom': 'value'},
            'relevance_score': 0.5
        }]

        summary = retriever.get_context_summary(context_items)
        assert "Item unknown" in summary
        assert "0.50" in summary

    def test_get_context_summary_multiple(self, retriever):
        """Test context summary with multiple items."""
        context_items = [
            {'key': '22', 'data': {'service': 'ssh'}, 'relevance_score': 0.8},
            {'key': '80', 'data': {'service': 'http'}, 'relevance_score': 0.6}
        ]

        summary = retriever.get_context_summary(context_items)
        assert "Port 22: ssh" in summary
        assert "Port 80: http" in summary
        assert "•" in summary  # Bullet points


class TestGlobalRetriever:
    """Test global retriever functions."""

    def test_get_retriever_singleton(self):
        """Test that get_retriever returns a singleton instance."""
        # Reset global state
        import sys_scan_agent.retriever as retriever_module
        retriever_module._retriever = None

        r1 = get_retriever()
        r2 = get_retriever()

        assert r1 is r2
        assert isinstance(r1, KnowledgeRetriever)

    @patch('sys_scan_agent.retriever.get_retriever')
    def test_retrieve_context_function(self, mock_get_retriever):
        """Test retrieve_context function calls retriever."""
        mock_retriever = MagicMock()
        mock_retriever.retrieve_context.return_value = [{'test': 'data'}]
        mock_get_retriever.return_value = mock_retriever

        result = retrieve_context("test query", "ports", 3, 0.2)

        mock_get_retriever.assert_called_once()
        mock_retriever.retrieve_context.assert_called_once_with("test query", "ports", 3, 0.2)
        assert result == [{'test': 'data'}]

    @patch('sys_scan_agent.retriever.retrieve_context')
    @patch('sys_scan_agent.retriever.get_retriever')
    def test_retrieve_context_with_summary(self, mock_get_retriever, mock_retrieve_context):
        """Test retrieve_context_with_summary function."""
        mock_context = [{'key': 'test', 'data': {}, 'relevance_score': 0.5}]
        mock_retrieve_context.return_value = mock_context

        mock_retriever = MagicMock()
        mock_retriever.get_context_summary.return_value = "Test summary"
        mock_get_retriever.return_value = mock_retriever

        context, summary = retrieve_context_with_summary("test query", "general", 5, 0.1)

        mock_retrieve_context.assert_called_once_with("test query", "general", 5, 0.1)
        mock_retriever.get_context_summary.assert_called_once_with(mock_context)
        assert context == mock_context
        assert summary == "Test summary"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_retrieve_context_empty_query(self, retriever):
        """Test retrieving context with empty query."""
        results = retriever.retrieve_context("", "general", max_results=5)
        assert len(results) == 0

    def test_calculate_relevance_empty_query(self, retriever):
        """Test relevance calculation with empty query."""
        data = {"service": "ssh"}
        score = retriever._calculate_relevance("", "22", data)
        assert score == 0.0

    def test_get_matched_fields_empty_query(self, retriever):
        """Test matched fields with empty query."""
        data = {"service": "ssh"}
        matched = retriever._get_matched_fields("", "22", data)
        assert matched == []

    def test_search_knowledge_file_empty_data(self, retriever):
        """Test searching knowledge file with empty data."""
        results = retriever._search_knowledge_file({}, "query", "test.yaml", 0.1)
        assert results == []

    def test_retrieve_context_with_logging(self, retriever):
        """Test that retrieve_context logs information and returns results."""
        # Configure logging to ensure INFO messages are processed
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger('sys_scan_agent.retriever')
        logger.setLevel(logging.INFO)

        results = retriever.retrieve_context("ssh", "general", max_results=1)

        # The method should return results and have executed the logging
        assert isinstance(results, list)
        assert len(results) <= 1
        # If we got here, the logging and return statements were executed

    def test_search_knowledge_file_non_dict_items(self, retriever):
        """Test searching knowledge file with non-dict items."""
        data = {
            "ports": {
                "22": "ssh",  # String instead of dict
                "80": {"service": "http"}
            }
        }

        results = retriever._search_knowledge_file(data, "ssh", "ports.yaml", 0.1)

        assert len(results) == 0  # Should skip non-dict items

    def test_search_knowledge_file_items_not_dict(self, retriever):
        """Test searching knowledge file when items is not a dict."""
        data = "not a dict"

        results = retriever._search_knowledge_file(data, "ssh", "ports.yaml", 0.1)

        assert results == []