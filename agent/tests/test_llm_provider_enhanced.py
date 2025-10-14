"""Tests for llm_provider_enhanced.py - enhanced LLM provider with local Mistral support."""
from unittest.mock import MagicMock, patch, call
import pytest
import sys

# Mock the problematic imports before importing the module
sys.modules['torch'] = MagicMock()
sys.modules['transformers'] = MagicMock()
sys.modules['peft'] = MagicMock()

from sys_scan_agent import llm_provider_enhanced
from sys_scan_agent.llm_provider import ProviderMetadata, NullLLMProvider
from sys_scan_agent.models import Reductions, Correlation, ActionItem, Summaries


class TestEnhancedLLMProvider:
    """Test enhanced LLM provider with local Mistral model support."""

    def test_initialization_default(self):
        """Test default initialization."""
        provider = llm_provider_enhanced.EnhancedLLMProvider()
        assert provider.local_provider is not None
        assert provider.metrics == {'calls_made': 0, 'errors': 0}

    def test_initialization_with_params(self):
        """Test initialization with custom parameters."""
        provider = llm_provider_enhanced.EnhancedLLMProvider(
            model_path="/custom/path",
            device="cpu"
        )
        assert provider.local_provider is not None
        assert provider.metrics == {'calls_made': 0, 'errors': 0}

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    def test_summarize_success(self, mock_local_provider_class):
        """Test successful summarize operation."""
        # Setup mock local provider
        mock_local_provider = MagicMock()
        mock_result = Summaries(executive_summary="Test summary")
        mock_metadata = ProviderMetadata(
            model_name="mistral-7b",
            provider_name="local-mistral",
            latency_ms=100,
            tokens_prompt=50,
            tokens_completion=25
        )
        mock_local_provider.summarize.return_value = (mock_result, mock_metadata)
        mock_local_provider_class.return_value = mock_local_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        reductions = Reductions()
        correlations = []
        actions = []

        result, metadata = provider.summarize(reductions, correlations, actions)

        assert result == mock_result
        assert metadata == mock_metadata
        assert provider.metrics['calls_made'] == 1
        assert provider.metrics['errors'] == 0
        mock_local_provider.summarize.assert_called_once_with(
            reductions, correlations, actions,
            skip=False, previous=None, skip_reason=None, baseline_context=None
        )

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    def test_summarize_with_parameters(self, mock_local_provider_class):
        """Test summarize with all parameters."""
        mock_local_provider = MagicMock()
        mock_result = Summaries(executive_summary="Test summary")
        mock_metadata = ProviderMetadata(
            model_name="mistral-7b",
            provider_name="local-mistral",
            latency_ms=100,
            tokens_prompt=50,
            tokens_completion=25
        )
        mock_local_provider.summarize.return_value = (mock_result, mock_metadata)
        mock_local_provider_class.return_value = mock_local_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        reductions = Reductions()
        correlations = []
        actions = []
        previous = Summaries()
        baseline_context = {"test": "data"}

        result, metadata = provider.summarize(
            reductions, correlations, actions,
            skip=True, previous=previous, skip_reason="test",
            baseline_context=baseline_context
        )

        assert result == mock_result
        assert metadata == mock_metadata
        mock_local_provider.summarize.assert_called_once_with(
            reductions, correlations, actions,
            skip=True, previous=previous, skip_reason="test",
            baseline_context=baseline_context
        )

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    @patch('sys_scan_agent.llm_provider.NullLLMProvider')
    def test_summarize_fallback_on_error(self, mock_null_provider_class, mock_local_provider_class):
        """Test fallback to null provider when local provider fails."""
        # Setup mock local provider to raise exception
        mock_local_provider = MagicMock()
        mock_local_provider.summarize.side_effect = Exception("Model failed")
        mock_local_provider_class.return_value = mock_local_provider

        # Setup mock null provider
        mock_null_provider = MagicMock()
        mock_null_result = Summaries(executive_summary="Fallback summary")
        mock_null_metadata = ProviderMetadata(
            model_name="null-heuristic",
            provider_name="null",
            latency_ms=0,
            tokens_prompt=0,
            tokens_completion=0
        )
        mock_null_provider.summarize.return_value = (mock_null_result, mock_null_metadata)
        mock_null_provider_class.return_value = mock_null_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        reductions = Reductions()
        correlations = []
        actions = []

        result, metadata = provider.summarize(reductions, correlations, actions)

        assert result == mock_null_result
        assert metadata == mock_null_metadata
        assert provider.metrics['calls_made'] == 0  # Local call failed
        assert provider.metrics['errors'] == 1

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    def test_refine_rules_success(self, mock_local_provider_class):
        """Test successful refine_rules operation."""
        mock_local_provider = MagicMock()
        mock_result = [{"id": "rule1", "conditions": []}]
        mock_metadata = ProviderMetadata(
            model_name="mistral-7b",
            provider_name="local-mistral",
            latency_ms=50,
            tokens_prompt=30,
            tokens_completion=15
        )
        mock_local_provider.refine_rules.return_value = (mock_result, mock_metadata)
        mock_local_provider_class.return_value = mock_local_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        suggestions = [{"id": "rule1"}]
        examples = {"rule1": ["example1"]}

        result, metadata = provider.refine_rules(suggestions, examples)

        assert result == mock_result
        assert metadata == mock_metadata
        assert provider.metrics['calls_made'] == 1
        assert provider.metrics['errors'] == 0
        mock_local_provider.refine_rules.assert_called_once_with(suggestions, examples)

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    @patch('sys_scan_agent.llm_provider.NullLLMProvider')
    def test_refine_rules_fallback_on_error(self, mock_null_provider_class, mock_local_provider_class):
        """Test fallback to null provider when local provider fails."""
        # Setup mock local provider to raise exception
        mock_local_provider = MagicMock()
        mock_local_provider.refine_rules.side_effect = Exception("Model failed")
        mock_local_provider_class.return_value = mock_local_provider

        # Setup mock null provider
        mock_null_provider = MagicMock()
        mock_null_result = [{"id": "test_rule", "conditions": []}]
        mock_null_metadata = ProviderMetadata(
            model_name="null-heuristic",
            provider_name="null",
            latency_ms=0,
            tokens_prompt=0,
            tokens_completion=0
        )
        mock_null_provider.refine_rules.return_value = (mock_null_result, mock_null_metadata)
        mock_null_provider_class.return_value = mock_null_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        suggestions = [{"id": "test_rule", "conditions": []}]
        examples = {"test_rule": ["example1", "example2"]}

        result, metadata = provider.refine_rules(suggestions, examples)

        assert result == mock_null_result
        assert metadata == mock_null_metadata
        assert provider.metrics['calls_made'] == 0  # Local call failed
        assert provider.metrics['errors'] == 1

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    def test_triage_success(self, mock_local_provider_class):
        """Test successful triage operation."""
        mock_local_provider = MagicMock()
        mock_result = {"top_findings": [], "correlation_count": 0}
        mock_metadata = ProviderMetadata(
            model_name="mistral-7b",
            provider_name="local-mistral",
            latency_ms=75,
            tokens_prompt=40,
            tokens_completion=20
        )
        mock_local_provider.triage.return_value = (mock_result, mock_metadata)
        mock_local_provider_class.return_value = mock_local_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        reductions = Reductions()
        correlations = []

        result, metadata = provider.triage(reductions, correlations)

        assert result == mock_result
        assert metadata == mock_metadata
        assert provider.metrics['calls_made'] == 1
        assert provider.metrics['errors'] == 0
        mock_local_provider.triage.assert_called_once_with(reductions, correlations)

    @patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider')
    @patch('sys_scan_agent.llm_provider.NullLLMProvider')
    def test_triage_fallback_on_error(self, mock_null_provider_class, mock_local_provider_class):
        """Test fallback to null provider when triage fails."""
        mock_local_provider = MagicMock()
        mock_local_provider.triage.side_effect = Exception("Triage failed")
        mock_local_provider_class.return_value = mock_local_provider

        mock_null_provider = MagicMock()
        mock_null_result = {"fallback": True}
        mock_null_metadata = ProviderMetadata(
            model_name="null-heuristic",
            provider_name="null",
            latency_ms=0,
            tokens_prompt=0,
            tokens_completion=0
        )
        mock_null_provider.triage.return_value = (mock_null_result, mock_null_metadata)
        mock_null_provider_class.return_value = mock_null_provider

        provider = llm_provider_enhanced.EnhancedLLMProvider()
        reductions = Reductions()
        correlations = []

        result, metadata = provider.triage(reductions, correlations)

        assert result == mock_null_result
        assert metadata == mock_null_metadata
        assert provider.metrics['calls_made'] == 0
        assert provider.metrics['errors'] == 1

    def test_get_metrics(self):
        """Test metrics retrieval."""
        provider = llm_provider_enhanced.EnhancedLLMProvider()
        provider.metrics['calls_made'] = 5
        provider.metrics['errors'] = 2

        metrics = provider.get_metrics()

        assert metrics == {'calls_made': 5, 'errors': 2}
        # Ensure it's a copy, not a reference
        assert metrics is not provider.metrics

    def test_get_enhanced_llm_provider_singleton(self):
        """Test singleton behavior of get_enhanced_llm_provider."""
        # Reset global state
        llm_provider_enhanced._enhanced_provider = None

        provider1 = llm_provider_enhanced.get_enhanced_llm_provider()
        provider2 = llm_provider_enhanced.get_enhanced_llm_provider()

        assert provider1 is provider2
        assert isinstance(provider1, llm_provider_enhanced.EnhancedLLMProvider)

    def test_set_enhanced_llm_provider(self):
        """Test setting custom enhanced provider."""
        # Reset global state
        llm_provider_enhanced._enhanced_provider = None

        custom_provider = llm_provider_enhanced.EnhancedLLMProvider(model_path="/custom")
        llm_provider_enhanced.set_enhanced_llm_provider(custom_provider)

        retrieved = llm_provider_enhanced.get_enhanced_llm_provider()
        assert retrieved is custom_provider

    def test_multiple_operations_metrics(self):
        """Test metrics accumulation across multiple operations."""
        with patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider') as mock_class:
            mock_provider = MagicMock()
            mock_class.return_value = mock_provider

            # Setup successful responses
            mock_provider.summarize.return_value = (Summaries(), ProviderMetadata(
                model_name="test", provider_name="test", latency_ms=0, tokens_prompt=0, tokens_completion=0
            ))
            mock_provider.refine_rules.return_value = ([], ProviderMetadata(
                model_name="test", provider_name="test", latency_ms=0, tokens_prompt=0, tokens_completion=0
            ))
            mock_provider.triage.return_value = ({}, ProviderMetadata(
                model_name="test", provider_name="test", latency_ms=0, tokens_prompt=0, tokens_completion=0
            ))

            provider = llm_provider_enhanced.EnhancedLLMProvider()

            # Perform multiple operations
            provider.summarize(Reductions(), [], [])
            provider.refine_rules([])
            provider.triage(Reductions(), [])

            assert provider.metrics['calls_made'] == 3
            assert provider.metrics['errors'] == 0

    def test_error_handling_with_multiple_failures(self):
        """Test error handling with multiple consecutive failures."""
        with patch('sys_scan_agent.llm_provider_enhanced.LocalMistralLLMProvider') as mock_class:
            mock_provider = MagicMock()
            mock_provider.summarize.side_effect = Exception("Persistent failure")
            mock_class.return_value = mock_provider

            with patch('sys_scan_agent.llm_provider.NullLLMProvider') as mock_null_class:
                mock_null = MagicMock()
                mock_null.summarize.return_value = (Summaries(), ProviderMetadata(
                    model_name="null", provider_name="null", latency_ms=0, tokens_prompt=0, tokens_completion=0
                ))
                mock_null_class.return_value = mock_null

                provider = llm_provider_enhanced.EnhancedLLMProvider()

                # Multiple failures
                provider.summarize(Reductions(), [], [])
                provider.summarize(Reductions(), [], [])

                assert provider.metrics['calls_made'] == 0
                assert provider.metrics['errors'] == 2
                assert mock_null.summarize.call_count == 2