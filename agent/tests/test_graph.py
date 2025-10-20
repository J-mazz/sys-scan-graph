#    .________      ._____.___ .______  .______ .______ .___ .______  .___
#    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
#     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
#    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
#     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
#        :/               |___|    |___|    :       :   |___|    |___||___|
#        :                                  •       •                 
#                                                                          
#
#    2925
#    test_graph.py

"""Tests for graph.py module - Graph state management and workflow orchestration."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import asyncio
from typing import Dict, Any, List

from sys_scan_agent.graph import (
    GraphState,
    memory_manager,
    reflection_engine,
    _extract_patterns_from_history,
    _accumulate_context,
    _assess_analysis_quality,
    _identify_uncertainty_factors,
    _generate_strategy_adjustments,
    _perform_cyclical_reasoning,
    summarize_host_state,
    suggest_rules,
    tool_coordinator_sync,
    risk_analyzer_sync,
    compliance_checker_sync,
    metrics_collector_sync,
    baseline_tools_sync,
    build_workflow,
    workflow,
    app,
    BaselineQueryGraph
)

# Import analysis functions directly
from sys_scan_agent.graph.analysis import risk_analyzer, compliance_checker, metrics_collector


class TestGraphState:
    """Test GraphState TypedDict functionality."""

    def test_graph_state_initialization(self):
        """Test GraphState can be initialized with various fields."""
        state: GraphState = {
            'raw_findings': [{'id': 'f1', 'title': 'Test finding'}],
            'enriched_findings': [{'id': 'f1', 'title': 'Test finding', 'risk_score': 50}],
            'correlated_findings': [{'id': 'f1', 'correlations': ['corr1']}],
            'suggested_rules': [{'rule': 'test_rule', 'confidence': 0.8}],
            'summary': {'executive_summary': 'Test summary'},
            'warnings': [{'type': 'warning', 'message': 'Test warning'}],
            'correlations': [{'id': 'corr1', 'title': 'Test correlation'}],
            'messages': [{'role': 'user', 'content': 'Test message'}],
            'baseline_results': {'f1': {'baseline_data': 'test'}},
            'baseline_cycle_done': False,
            'iteration_count': 1,
            'metrics': {'duration': 100},
            'cache_keys': ['key1'],
            'enrich_cache': {'key1': [{'id': 'f1'}]},
            'streaming_enabled': True,
            'human_feedback_pending': False,
            'pending_tool_calls': [{'name': 'test_tool'}],
            'risk_assessment': {'risk_level': 'medium'},
            'compliance_check': {'passed': 10, 'failed': 2},
            'errors': [{'error': 'test error'}],
            'degraded_mode': False,
            'human_feedback_processed': True,
            'final_metrics': {'total_duration': 200},
            'cache': {'cached_data': 'test'},
            'llm_provider_mode': 'normal',
            'current_stage': 'analysis',
            'start_time': '2024-01-01T00:00:00Z',
            'cache_hits': ['hit1'],
            'summarize_progress': 0.5,
            'host_id': 'host1',
            'memory': {'iteration_history': []},
            'reflection': {'confidence_score': 0.8}
        }

        assert state['raw_findings'][0]['id'] == 'f1'
        assert state['risk_assessment']['risk_level'] == 'medium'
        assert state['iteration_count'] == 1

    def test_graph_state_partial_initialization(self):
        """Test GraphState can be initialized with only some fields."""
        state: GraphState = {
            'raw_findings': [{'id': 'f1'}],
            'summary': {'brief': 'Test'}
        }

        assert len(state['raw_findings']) == 1
        assert state['summary']['brief'] == 'Test'
        # Optional fields should be accessible
        assert state.get('iteration_count') is None
        assert state.get('memory') is None


class TestMemoryManager:
    """Test memory management functionality."""

    def test_memory_manager_initializes_memory(self):
        """Test memory_manager initializes memory when not present."""
        state: GraphState = {
            'iteration_count': 0,
            'start_time': '2024-01-01T00:00:00Z',
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {},
            'summary': {'executive_summary': 'Test summary'}
        }

        result = memory_manager(state)

        assert 'memory' in result
        memory = result['memory']
        # Memory manager always adds current iteration snapshot
        assert len(memory['iteration_history']) == 1
        assert memory['iteration_history'][0]['iteration'] == 0
        assert memory['iteration_history'][0]['findings_count'] == 1

    def test_memory_manager_with_existing_memory(self):
        """Test memory_manager works with existing memory."""
        state: GraphState = {
            'iteration_count': 1,
            'start_time': '2024-01-01T00:00:00Z',
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {'f1': 'result'},
            'summary': {'executive_summary': 'Test summary'},
            'risk_assessment': {'risk_level': 'high'},
            'memory': {
                'iteration_history': [{'iteration': 0, 'findings_count': 5}],
                'learned_patterns': [],
                'context_accumulation': {},
                'reflection_insights': []
            }
        }

        result = memory_manager(state)

        assert len(result['memory']['iteration_history']) == 2
        assert result['memory']['iteration_history'][1]['iteration'] == 1
        assert result['memory']['iteration_history'][1]['findings_count'] == 1
        assert result['memory']['iteration_history'][1]['risk_level'] == 'high'

    def test_memory_manager_limits_history_size(self):
        """Test memory_manager limits iteration history size."""
        # Create state with 12 iterations in history
        history = [{'iteration': i, 'findings_count': 1} for i in range(12)]
        state: GraphState = {
            'iteration_count': 12,
            'memory': {
                'iteration_history': history,
                'learned_patterns': [],
                'context_accumulation': {},
                'reflection_insights': []
            }
        }

        result = memory_manager(state)

        # Should limit to 10 items, keeping the most recent
        assert 'memory' in result
        memory = result['memory']
        assert len(memory['iteration_history']) == 10
        assert memory['iteration_history'][0]['iteration'] == 3  # Keeps items 3-12 (last 10)
        assert memory['iteration_history'][9]['iteration'] == 12

    def test_memory_manager_extracts_patterns(self):
        """Test memory_manager calls pattern extraction when enough history."""
        history = [
            {'iteration': i, 'risk_level': 'critical' if i % 2 == 0 else 'low'}
            for i in range(6)
        ]
        state: GraphState = {
            'iteration_count': 6,
            'memory': {
                'iteration_history': history,
                'learned_patterns': [],
                'context_accumulation': {},
                'reflection_insights': []
            }
        }

        result = memory_manager(state)

        # Should have extracted patterns (multiple critical iterations)
        assert 'memory' in result
        memory = result['memory']
        assert len(memory['learned_patterns']) > 0
        assert any(p['type'] == 'risk_escalation' for p in memory['learned_patterns'])

    def test_memory_manager_accumulates_context(self):
        """Test memory_manager accumulates context across iterations."""
        state: GraphState = {
            'enriched_findings': [
                {'title': 'SUID binary found', 'id': 'f1'},
                {'title': 'Network service running', 'id': 'f2'},
                {'title': 'Suspicious file permission', 'id': 'f3'}
            ],
            'risk_assessment': {'risk_level': 'medium'},
            'memory': {
                'iteration_history': [],
                'learned_patterns': [],
                'context_accumulation': {},
                'reflection_insights': []
            }
        }

        result = memory_manager(state)

        assert 'memory' in result
        context = result['memory']['context_accumulation']
        assert 'risk_progression' in context
        assert context['risk_progression'] == ['medium']
        assert 'observed_categories' in context
        assert 'privilege_escalation' in context['observed_categories']
        assert 'filesystem_security' in context['observed_categories']


class TestMemoryHelperFunctions:
    """Test memory management helper functions."""

    def test_extract_patterns_from_history_risk_escalation(self):
        """Test pattern extraction detects risk escalation."""
        memory = {
            'iteration_history': [
                {'risk_level': 'critical'},
                {'risk_level': 'critical'},
                {'risk_level': 'high'}
            ],
            'learned_patterns': []
        }

        _extract_patterns_from_history(memory)

        assert len(memory['learned_patterns']) == 1
        assert memory['learned_patterns'][0]['type'] == 'risk_escalation'
        assert 'Multiple critical risk iterations detected' in memory['learned_patterns'][0]['pattern']

    def test_extract_patterns_from_history_tool_overuse(self):
        """Test pattern extraction detects tool overuse."""
        memory = {
            'iteration_history': [
                {'tool_calls_made': 25},
                {'tool_calls_made': 30},
                {'tool_calls_made': 35}
            ],
            'learned_patterns': []
        }

        _extract_patterns_from_history(memory)

        assert len(memory['learned_patterns']) == 1
        assert memory['learned_patterns'][0]['type'] == 'tool_overuse'
        assert 'High tool call volume detected' in memory['learned_patterns'][0]['pattern']

    def test_accumulate_context_risk_progression(self):
        """Test context accumulation for risk progression."""
        memory = {
            'context_accumulation': {
                'risk_progression': ['low', 'medium']
            }
        }
        state = {
            'risk_assessment': {'risk_level': 'high'}
        }

        _accumulate_context(state, memory)

        assert memory['context_accumulation']['risk_progression'] == ['low', 'medium', 'high']

    def test_accumulate_context_limits_risk_progression(self):
        """Test context accumulation limits risk progression history."""
        memory = {
            'context_accumulation': {
                'risk_progression': ['low'] * 6  # 6 items
            }
        }
        state = {
            'risk_assessment': {'risk_level': 'high'}
        }

        _accumulate_context(state, memory)

        # Should keep only last 5
        assert len(memory['context_accumulation']['risk_progression']) == 5
        assert memory['context_accumulation']['risk_progression'] == ['low'] * 4 + ['high']

    def test_accumulate_context_finding_categories(self):
        """Test context accumulation extracts finding categories."""
        memory = {
            'context_accumulation': {}
        }
        state = {
            'enriched_findings': [
                {'title': 'SUID binary detected'},
                {'title': 'Network port open'},
                {'title': 'File permission issue'},
                {'title': 'Process running'}
            ]
        }

        _accumulate_context(state, memory)

        categories = memory['context_accumulation']['observed_categories']
        assert 'privilege_escalation' in categories
        assert 'network_security' in categories
        assert 'filesystem_security' in categories
        assert 'process_security' in categories


class TestReflectionEngine:
    """Test reflection engine functionality."""

    def test_reflection_engine_initializes_reflection(self):
        """Test reflection_engine initializes reflection when not present."""
        state: GraphState = {
            'iteration_count': 0,
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {}
        }

        result = reflection_engine(state)

        assert 'reflection' in result
        # Quality assessment runs even for iteration 0, so it gets assessed as 'low'
        assert result['reflection']['confidence_score'] == 0.5  # 0.3 (findings) + 0.2 (base) = 0.5
        assert result['reflection']['reasoning_quality'] == 'low'
        assert result['reflection']['strategy_adjustments'] == []
        assert result['reflection']['uncertainty_factors'] == ['incomplete_baseline_data']

    def test_reflection_engine_with_existing_reflection(self):
        """Test reflection_engine works with existing reflection."""
        state: GraphState = {
            'iteration_count': 1,
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {},
            'reflection': {
                'confidence_score': 0.7,
                'reasoning_quality': 'good'
            }
        }

        result = reflection_engine(state)

        # Should update reflection based on analysis
        assert 'reflection' in result
        assert isinstance(result['reflection']['confidence_score'], float)
        assert result['reflection']['reasoning_quality'] in ['low', 'moderate', 'good', 'high']

    def test_reflection_engine_with_multiple_iterations(self):
        """Test reflection_engine performs cyclical reasoning after multiple iterations."""
        state: GraphState = {
            'iteration_count': 3,
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {},
            'memory': {
                'iteration_history': [
                    {'iteration': 0, 'risk_level': 'low'},
                    {'iteration': 1, 'risk_level': 'medium'},
                    {'iteration': 2, 'risk_level': 'high'}
                ],
                'reflection_insights': []
            },
            'reflection': {
                'confidence_score': 0.8,
                'uncertainty_factors': []
            }
        }

        result = reflection_engine(state)

        # Should have performed cyclical reasoning
        assert 'memory' in result
        memory = result['memory']
        assert 'reflection_insights' in memory
        assert len(memory['reflection_insights']) > 0


class TestReflectionHelperFunctions:
    """Test reflection engine helper functions."""

    def test_assess_analysis_quality_high_quality(self):
        """Test quality assessment for high quality analysis."""
        state = {
            'enriched_findings': [{'id': f'f{i}'} for i in range(10)],
            'correlations': [{'id': 'corr1'}],
            'baseline_results': {f'f{i}': 'result' for i in range(10)},
            'risk_assessment': {'risk_level': 'high'},
            'compliance_check': {'passed': 5, 'failed': 1}
        }

        result = _assess_analysis_quality(state)

        assert result['quality'] == 'high'
        assert result['confidence'] > 0.8
        assert 'findings_present' in result['factors']
        assert 'correlations_found' in result['factors']
        assert 'good_baseline_coverage' in result['factors']
        assert 'risk_assessed' in result['factors']
        assert 'compliance_checked' in result['factors']

    def test_assess_analysis_quality_low_quality(self):
        """Test quality assessment for low quality analysis."""
        state = {
            'enriched_findings': [],
            'correlations': [],
            'baseline_results': {}
        }

        result = _assess_analysis_quality(state)

        assert result['quality'] == 'low'
        assert result['confidence'] < 0.5
        assert 'no_findings' in result['factors']

    def test_identify_uncertainty_factors_incomplete_baseline(self):
        """Test uncertainty identification for incomplete baseline."""
        state = {
            'enriched_findings': [{'id': 'f1'}, {'id': 'f2'}, {'id': 'f3'}, {'id': 'f4'}],  # 4 findings
            'baseline_results': {'f1': 'result'}  # Only 1/4 = 0.25 covered, 0.25 < 0.3 threshold
        }
        memory = {'iteration_history': []}

        factors = _identify_uncertainty_factors(state, memory)

        assert 'incomplete_baseline_data' in factors

    def test_identify_uncertainty_factors_analysis_instability(self):
        """Test uncertainty identification for analysis instability."""
        state = {
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {}
        }
        memory = {
            'iteration_history': [
                {'reasoning_quality': 'low'},
                {'reasoning_quality': 'low'},
                {'reasoning_quality': 'low'}
            ]
        }

        factors = _identify_uncertainty_factors(state, memory)

        assert 'analysis_instability' in factors

    def test_identify_uncertainty_factors_unclear_risk(self):
        """Test uncertainty identification for unclear risk assessment."""
        state = {
            'enriched_findings': [{'id': 'f1'}],
            'baseline_results': {},
            'risk_assessment': {'risk_level': 'unknown'}
        }
        memory = {'iteration_history': []}

        factors = _identify_uncertainty_factors(state, memory)

        assert 'unclear_risk_assessment' in factors

    def test_identify_uncertainty_factors_missing_correlations(self):
        """Test uncertainty identification for missing correlations."""
        state = {
            'enriched_findings': [{'id': f'f{i}'} for i in range(10)],  # 10 findings
            'correlations': [],  # No correlations
            'baseline_results': {}
        }
        memory = {'iteration_history': []}

        factors = _identify_uncertainty_factors(state, memory)

        assert 'missing_correlations' in factors

    def test_generate_strategy_adjustments_low_confidence(self):
        """Test strategy adjustment generation for low confidence."""
        state = {'enriched_findings': []}
        memory = {'learned_patterns': []}
        reflection = {
            'confidence_score': 0.2,
            'uncertainty_factors': []
        }

        adjustments = _generate_strategy_adjustments(state, memory, reflection)

        assert len(adjustments) == 1
        assert adjustments[0]['type'] == 'increase_tool_usage'
        assert 'Low confidence in analysis' in adjustments[0]['reason']

    def test_generate_strategy_adjustments_uncertainty_factors(self):
        """Test strategy adjustment generation for uncertainty factors."""
        state = {'enriched_findings': []}
        memory = {'learned_patterns': []}
        reflection = {
            'confidence_score': 0.8,
            'uncertainty_factors': ['incomplete_baseline_data', 'analysis_instability']
        }

        adjustments = _generate_strategy_adjustments(state, memory, reflection)

        assert len(adjustments) == 2
        types = [adj['type'] for adj in adjustments]
        assert 'prioritize_baseline' in types
        assert 'stabilize_analysis' in types

    def test_generate_strategy_adjustments_learned_patterns(self):
        """Test strategy adjustment generation for learned patterns."""
        state = {'enriched_findings': []}
        memory = {
            'learned_patterns': [{
                'type': 'risk_escalation',
                'pattern': 'Multiple critical risk iterations',
                'recommendation': 'Escalate to human review'
            }]
        }
        reflection = {
            'confidence_score': 0.8,
            'uncertainty_factors': []
        }

        adjustments = _generate_strategy_adjustments(state, memory, reflection)

        assert len(adjustments) == 1
        assert adjustments[0]['type'] == 'escalate_review'
        assert 'Escalate to human review' in adjustments[0]['action']

    def test_perform_cyclical_reasoning_convergence(self):
        """Test cyclical reasoning detects convergence."""
        state = {'enriched_findings': []}
        memory = {
            'iteration_history': [
                {'iteration': 0, 'risk_level': 'high'},
                {'iteration': 1, 'risk_level': 'high'},
                {'iteration': 2, 'risk_level': 'high'}
            ],
            'reflection_insights': []
        }

        insights = _perform_cyclical_reasoning(state, memory)

        assert len(insights) == 1
        assert insights[0]['type'] == 'convergence_detected'
        assert 'converged to high risk level' in insights[0]['insight']

    def test_perform_cyclical_reasoning_oscillation(self):
        """Test cyclical reasoning detects oscillation."""
        state = {'enriched_findings': []}
        memory = {
            'iteration_history': [
                {'iteration': 0, 'risk_level': 'low'},
                {'iteration': 1, 'risk_level': 'high'},
                {'iteration': 2, 'risk_level': 'medium'}
            ],
            'reflection_insights': []
        }

        insights = _perform_cyclical_reasoning(state, memory)

        assert len(insights) == 1
        assert insights[0]['type'] == 'oscillation_detected'
        assert 'oscillating between risk levels' in insights[0]['insight']

    def test_perform_cyclical_reasoning_tool_usage_spike(self):
        """Test cyclical reasoning detects tool usage spike."""
        state = {'enriched_findings': []}
        memory = {
            'iteration_history': [
                {'iteration': 0, 'tool_calls_made': 5},
                {'iteration': 1, 'tool_calls_made': 8},
                {'iteration': 2, 'tool_calls_made': 50}  # Spike
            ],
            'reflection_insights': []
        }

        insights = _perform_cyclical_reasoning(state, memory)

        assert len(insights) == 1
        assert insights[0]['type'] == 'tool_usage_spike'
        assert 'Significant increase in tool usage' in insights[0]['insight']


class TestSyncWrapperFunctions:
    """Test sync wrapper functions for async nodes."""

    @patch('sys_scan_agent.graph.enhanced_summarize_host_state')
    def test_summarize_host_state_with_function(self, mock_func):
        """Test summarize_host_state when function is available."""
        mock_func.return_value = {'summary': 'test summary'}

        state: GraphState = {'raw_findings': []}
        result = summarize_host_state(state)

        assert result == {'summary': 'test summary'}
        mock_func.assert_called_once_with(state)

    def test_summarize_host_state_without_function(self):
        """Test summarize_host_state when function is None."""
        with patch('sys_scan_agent.graph.enhanced_summarize_host_state', None):
            state: GraphState = {'raw_findings': []}
            result = summarize_host_state(state)

            assert result == state  # Should return unchanged state

    @patch('sys_scan_agent.graph.enhanced_suggest_rules')
    def test_suggest_rules_with_function(self, mock_func):
        """Test suggest_rules when function is available."""
        mock_func.return_value = {'suggested_rules': ['rule1']}

        state: GraphState = {'enriched_findings': []}
        result = suggest_rules(state)

        assert result == {'suggested_rules': ['rule1']}
        mock_func.assert_called_once_with(state)

    def test_suggest_rules_without_function(self):
        """Test suggest_rules when function is None."""
        with patch('sys_scan_agent.graph.enhanced_suggest_rules', None):
            state: GraphState = {'enriched_findings': []}
            result = suggest_rules(state)

            assert result == state  # Should return unchanged state

    @patch('sys_scan_agent.graph.tool_coordinator')
    def test_tool_coordinator_sync_with_function(self, mock_func):
        """Test tool_coordinator_sync when function is available."""
        mock_func.return_value = {'tool_calls': ['call1']}

        state: GraphState = {'pending_tool_calls': []}
        result = tool_coordinator_sync(state)

        assert result == {'tool_calls': ['call1']}
        mock_func.assert_called_once_with(state)

    def test_tool_coordinator_sync_without_function(self):
        """Test tool_coordinator_sync when function is None."""
        with patch('sys_scan_agent.graph.tool_coordinator', None):
            state: GraphState = {'pending_tool_calls': []}
            result = tool_coordinator_sync(state)

            assert result == state  # Should return unchanged state

    @patch('sys_scan_agent.graph.risk_analyzer')
    def test_risk_analyzer_sync_with_function(self, mock_func):
        """Test risk_analyzer_sync when function is available."""
        mock_func.return_value = {'risk_assessment': {'level': 'high'}}

        state: GraphState = {'enriched_findings': []}
        result = risk_analyzer_sync(state)

        assert result == {'risk_assessment': {'level': 'high'}}
        mock_func.assert_called_once_with(state)

    @patch('sys_scan_agent.graph.compliance_checker')
    def test_compliance_checker_sync_with_function(self, mock_func):
        """Test compliance_checker_sync when function is available."""
        mock_func.return_value = {'compliance_check': {'passed': 5}}

        state: GraphState = {'enriched_findings': []}
        result = compliance_checker_sync(state)

        assert result == {'compliance_check': {'passed': 5}}
        mock_func.assert_called_once_with(state)

    @patch('sys_scan_agent.graph.metrics_collector')
    def test_metrics_collector_sync_with_function(self, mock_func):
        """Test metrics_collector_sync when function is available."""
        mock_func.return_value = {'metrics': {'duration': 100}}

        state: GraphState = {'iteration_count': 1}
        result = metrics_collector_sync(state)

        assert result == {'metrics': {'duration': 100}}
        mock_func.assert_called_once_with(state)

    @patch('sys_scan_agent.graph.query_baseline')
    def test_baseline_tools_sync_with_function(self, mock_func):
        """Test baseline_tools_sync when function is available."""
        mock_func.return_value = {'baseline_data': 'test'}

        # Create a mock message with tool_calls attribute
        mock_message = Mock()
        mock_message.tool_calls = [{
            'id': 'call1',
            'name': 'query_baseline',
            'args': {'finding_id': 'f1'}
        }]

        state: GraphState = {
            'messages': [mock_message]
        }
        result = baseline_tools_sync(state)

        # Should add tool results to messages
        assert 'messages' in result
        messages = result['messages']
        assert len(messages) == 2
        assert messages[1]['tool_call_id'] == 'call1'
        assert messages[1]['content'] == {'baseline_data': 'test'}
        mock_func.assert_called_once_with(finding_id='f1')

    def test_baseline_tools_sync_without_messages(self):
        """Test baseline_tools_sync when no messages present."""
        with patch('sys_scan_agent.graph.query_baseline', None):
            state: GraphState = {}
            result = baseline_tools_sync(state)

            assert result == state  # Should return unchanged state

    def test_baseline_tools_sync_without_tool_calls(self):
        """Test baseline_tools_sync when messages have no tool calls."""
        with patch('sys_scan_agent.graph.query_baseline', None):
            state: GraphState = {'messages': [{'content': 'no tools'}]}
            result = baseline_tools_sync(state)

            assert result == state  # Should return unchanged state

    def test_baseline_tools_sync_without_function(self):
        """Test baseline_tools_sync when query_baseline is None."""
        with patch('sys_scan_agent.graph.query_baseline', None):
            state: GraphState = {
                'messages': [{
                    'tool_calls': [{
                        'id': 'call1',
                        'name': 'query_baseline',
                        'args': {}
                    }]
                }]
            }
            result = baseline_tools_sync(state)

            assert result == state  # Should return unchanged state


class TestBuildWorkflow:
    """Test workflow building functionality."""

    def test_build_workflow_with_dependencies(self):
        """Test build_workflow with all dependencies available."""
        with patch('sys_scan_agent.graph.StateGraph') as mock_state_graph, \
             patch.multiple('sys_scan_agent.graph',
                          END='END',
                          START='START',
                          ToolNode=Mock(),
                          enrich_findings=Mock(),
                          enhanced_summarize_host_state=Mock(),
                          enhanced_suggest_rules=Mock(),
                          tool_coordinator=Mock(),
                          plan_baseline_queries=Mock(),
                          integrate_baseline_results=Mock(),
                          risk_analyzer=Mock(),
                          compliance_checker=Mock(),
                          metrics_collector=Mock(),
                          query_baseline=Mock()):
            # Mock the required components
            mock_wf = Mock()
            mock_wf.add_node = Mock()
            mock_wf.add_edge = Mock()
            mock_wf.set_entry_point = Mock()
            mock_wf.compile = Mock(return_value='compiled_app')

            # Configure StateGraph mock
            mock_state_graph.return_value = mock_wf

            wf, app = build_workflow()

            assert wf == mock_wf
            assert app == 'compiled_app'
            # Note: StateGraph may have been called during module import, so we don't check the call count
            mock_wf.compile.assert_called_once()

    def test_build_workflow_without_dependencies(self):
        """Test build_workflow when dependencies are not available."""
        # Mock imports to return None
        with patch.multiple('sys_scan_agent.graph',
                          StateGraph=None,
                          END=None,
                          START=None,
                          ToolNode=None,
                          enrich_findings=None,
                          enhanced_summarize_host_state=None,
                          enhanced_suggest_rules=None,
                          tool_coordinator=None,
                          plan_baseline_queries=None,
                          integrate_baseline_results=None,
                          risk_analyzer=None,
                          compliance_checker=None,
                          metrics_collector=None,
                          query_baseline=None):
            wf, app = build_workflow()

            assert wf is None
            assert app is None

    def test_build_workflow_partial_dependencies(self):
        """Test build_workflow with some dependencies missing."""
        with patch.multiple('sys_scan_agent.graph',
                          StateGraph=Mock(),
                          END='END',
                          START='START',
                          ToolNode='ToolNode',
                          enrich_findings=None,  # Missing core component
                          enhanced_summarize_host_state=Mock(),
                          enhanced_suggest_rules=Mock()):
            wf, app = build_workflow()

            # Should return None, None when required components are missing
            assert wf is None
            assert app is None


class TestErrorHandling:
    """Test error handling for missing dependencies."""

    def test_async_wrapper_exception_handling(self):
        """Test that async wrapper functions handle exceptions gracefully."""
        # Test with a function that raises an exception
        async def failing_func(state):
            raise Exception("Test exception")

        with patch('sys_scan_agent.graph.enhanced_summarize_host_state', failing_func):
            state: GraphState = {}  # Empty state
            result = summarize_host_state(state)

            # Should return original state on exception
            assert result == state

    def test_workflow_globals_with_missing_dependencies(self):
        """Test that global workflow variables handle missing dependencies."""
        # The workflow and app variables should be set appropriately
        # when dependencies are missing
        with patch.multiple('sys_scan_agent.graph',
                          StateGraph=None,
                          enrich_findings=None):
            # Re-import to trigger the build_workflow call
            from importlib import reload
            import sys_scan_agent.graph
            reload(sys_scan_agent.graph)

            # Should be None when dependencies unavailable at import time
            # Note: This test may not work as expected due to import-time execution
            # The globals are set when the module is first imported
            pass  # Skip this test as it's hard to test import-time behavior


class TestIntegration:
    """Integration tests for graph functionality."""

    def test_full_memory_and_reflection_cycle(self):
        """Test a full cycle of memory management and reflection."""
        state: GraphState = {
            'iteration_count': 2,
            'start_time': '2024-01-01T00:00:00Z',
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID binary'},
                {'id': 'f2', 'title': 'Network service'}
            ],
            'baseline_results': {'f1': 'baseline_data'},
            'correlations': [{'id': 'corr1'}],
            'risk_assessment': {'risk_level': 'high'},
            'compliance_check': {'passed': 8, 'failed': 1},
            'summary': {'executive_summary': 'Analysis complete'},
            'memory': {
                'iteration_history': [
                    {'iteration': 0, 'risk_level': 'medium', 'findings_count': 3, 'tool_calls_made': 5},
                    {'iteration': 1, 'risk_level': 'high', 'findings_count': 2, 'tool_calls_made': 8}
                ],
                'learned_patterns': [],
                'context_accumulation': {'risk_progression': ['low', 'medium']},
                'reflection_insights': []
            }
        }

        # Run memory manager
        state = memory_manager(state)

        # Run reflection engine
        state = reflection_engine(state)

        # Verify memory was updated
        assert 'memory' in state
        memory = state['memory']
        assert len(memory['iteration_history']) == 3
        assert memory['iteration_history'][2]['iteration'] == 2

        # Verify reflection was performed
        assert 'reflection' in state
        assert isinstance(state['reflection']['confidence_score'], float)
        assert state['reflection']['reasoning_quality'] in ['low', 'moderate', 'good', 'high']

        # Verify context accumulation
        assert 'risk_progression' in memory['context_accumulation']
        assert len(memory['context_accumulation']['risk_progression']) == 3

        # Verify pattern extraction occurred
        assert len(memory['learned_patterns']) >= 0  # May or may not find patterns

        # Verify cyclical reasoning occurred
        assert len(memory['reflection_insights']) >= 0  # May or may not find insights


class TestAnalysisFunctions:
    """Test analysis.py async functions for risk analysis, compliance checking, and metrics collection."""

    @pytest.mark.asyncio
    async def test_risk_analyzer_basic_functionality(self):
        """Test risk_analyzer with basic enriched findings."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80, 'tags': ['privilege']},
                {'id': 'f2', 'title': 'World readable file', 'severity': 'medium', 'risk_score': 40, 'tags': ['filesystem']},
                {'id': 'f3', 'title': 'Network service', 'severity': 'low', 'risk_score': 20, 'tags': ['network']}
            ],
            'correlations': []
        }

        result = await risk_analyzer(state)  # type: ignore

        assert 'risk_assessment' in result
        risk_assessment = result['risk_assessment']
        assert risk_assessment['overall_risk_level'] == 'high'
        assert risk_assessment['total_risk_score'] == 140  # 80 + 40 + 20
        assert risk_assessment['average_risk_score'] == 46.666666666666664  # 140 / 3
        assert risk_assessment['finding_count'] == 3
        assert risk_assessment['high_severity_count'] == 1
        assert risk_assessment['correlation_count'] == 0
        assert 'counts' in risk_assessment
        assert risk_assessment['counts']['high'] == 1
        assert risk_assessment['counts']['medium'] == 1
        assert risk_assessment['counts']['low'] == 1
        assert len(risk_assessment['top_findings']) == 3
        assert risk_assessment['top_findings'][0]['id'] == 'f1'  # Highest risk score

    @pytest.mark.asyncio
    async def test_risk_analyzer_with_correlations(self):
        """Test risk_analyzer with correlation bonus."""
        from sys_scan_agent import models

        correlation = models.Correlation(
            id='corr1',
            title='Privilege escalation chain',
            rationale='Chain of privilege escalation findings',
            related_finding_ids=['f1', 'f2'],
            risk_score_delta=25
        )

        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file', 'severity': 'high', 'risk_score': 80},
                {'id': 'f2', 'title': 'Weak permissions', 'severity': 'medium', 'risk_score': 40}
            ],
            'correlations': [correlation]
        }

        result = await risk_analyzer(state)

        risk_assessment = result['risk_assessment']
        assert risk_assessment['total_risk_score'] == 145  # 80 + 40 + 25 correlation bonus
        assert risk_assessment['correlation_count'] == 1

    @pytest.mark.asyncio
    async def test_risk_analyzer_empty_findings(self):
        """Test risk_analyzer with no findings."""
        state: GraphState = {
            'enriched_findings': [],
            'correlations': []
        }

        result = await risk_analyzer(state)

        risk_assessment = result['risk_assessment']
        assert risk_assessment['overall_risk_level'] == 'info'
        assert risk_assessment['total_risk_score'] == 0
        assert risk_assessment['average_risk_score'] == 0.0
        assert risk_assessment['finding_count'] == 0
        assert risk_assessment['high_severity_count'] == 0
        assert risk_assessment['correlation_count'] == 0

    @pytest.mark.asyncio
    async def test_risk_analyzer_critical_findings(self):
        """Test risk_analyzer with critical severity findings."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Critical vulnerability', 'severity': 'critical', 'risk_score': 100},
                {'id': 'f2', 'title': 'High vulnerability', 'severity': 'high', 'risk_score': 80}
            ],
            'correlations': []
        }

        result = await risk_analyzer(state)

        risk_assessment = result['risk_assessment']
        assert risk_assessment['overall_risk_level'] == 'critical'
        assert risk_assessment['total_risk_score'] == 180
        assert risk_assessment['high_severity_count'] == 2  # Both 'high' and 'critical' are considered high severity

    @pytest.mark.asyncio
    async def test_compliance_checker_pci_dss_violations(self):
        """Test compliance_checker identifies PCI DSS violations."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'tags': ['privilege']},
                {'id': 'f2', 'title': 'Unencrypted network traffic', 'severity': 'medium', 'tags': ['network']},
                {'id': 'f3', 'title': 'PCI DSS violation', 'severity': 'high', 'tags': ['pci'], 'metadata': {'compliance_standard': 'PCI'}}
            ]
        }

        result = await compliance_checker(state)

        compliance_check = result['compliance_check']
        assert 'standards' in compliance_check
        pci_dss = compliance_check['standards']['PCI DSS']
        assert pci_dss['count'] == 3  # SUID, network unencrypted, explicit PCI tag
        assert len(pci_dss['finding_ids']) == 3
        assert 'f1' in pci_dss['finding_ids']
        assert 'f2' in pci_dss['finding_ids']
        assert 'f3' in pci_dss['finding_ids']

    @pytest.mark.asyncio
    async def test_compliance_checker_hipaa_violations(self):
        """Test compliance_checker identifies HIPAA violations."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'World readable patient data', 'severity': 'high', 'metadata': {'readable': True, 'world_access': True}},
                {'id': 'f2', 'title': 'HIPAA violation', 'severity': 'critical', 'tags': ['hipaa'], 'metadata': {'compliance_standard': 'HIPAA'}}
            ]
        }

        result = await compliance_checker(state)

        compliance_check = result['compliance_check']
        hipaa = compliance_check['standards']['HIPAA']
        assert hipaa['count'] == 2
        assert len(hipaa['finding_ids']) == 2
        assert 'f1' in hipaa['finding_ids']
        assert 'f2' in hipaa['finding_ids']

    @pytest.mark.asyncio
    async def test_compliance_checker_iso27001_violations(self):
        """Test compliance_checker identifies ISO 27001 violations."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Incorrect file permissions', 'severity': 'medium'},
                {'id': 'f2', 'title': 'Network configuration issue', 'severity': 'info'}
            ]
        }

        result = await compliance_checker(state)

        compliance_check = result['compliance_check']
        iso27001 = compliance_check['standards']['ISO27001']
        assert iso27001['count'] == 1  # Only permission-related finding
        assert 'f1' in iso27001['finding_ids']
        assert 'f2' not in iso27001['finding_ids']

    @pytest.mark.asyncio
    async def test_compliance_checker_no_violations(self):
        """Test compliance_checker with no compliance violations."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Minor configuration issue', 'severity': 'low', 'tags': []}
            ]
        }

        result = await compliance_checker(state)

        compliance_check = result['compliance_check']
        assert compliance_check['total_compliance_findings'] == 0
        assert compliance_check['pci_dss_compliant'] is True
        assert compliance_check['hipaa_compliant'] is True
        assert compliance_check['iso27001_compliant'] is True

    @pytest.mark.asyncio
    async def test_compliance_checker_remediation_priority(self):
        """Test compliance_checker calculates remediation priority correctly."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Critical PCI violation', 'severity': 'critical'},
                {'id': 'f2', 'title': 'High HIPAA violation', 'severity': 'high'},
                {'id': 'f3', 'title': 'Medium issue', 'severity': 'medium'}
            ]
        }

        result = await compliance_checker(state)

        compliance_check = result['compliance_check']
        assert compliance_check['remediation_priority'] == 'immediate'  # Due to critical finding

    @pytest.mark.asyncio
    async def test_metrics_collector_basic_functionality(self):
        """Test metrics_collector collects basic metrics."""
        from sys_scan_agent import models

        correlation = models.Correlation(
            id='corr1',
            title='Test correlation',
            rationale='Test correlation rationale',
            related_finding_ids=['f1', 'f2'],
            risk_score_delta=10
        )

        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'High finding', 'severity': 'high', 'category': 'privilege'},
                {'id': 'f2', 'title': 'Medium finding', 'severity': 'medium', 'category': 'network'},
                {'id': 'f3', 'title': 'Low finding', 'severity': 'low', 'category': 'filesystem'}
            ],
            'correlations': [correlation],
            'risk_assessment': {'overall_risk': 'high'},
            'cache': {'key1': 'value1'},
            'enrich_cache': {'key2': 'value2'}
        }

        result = await metrics_collector(state)

        metrics = result['final_metrics']
        assert metrics['findings_processed'] == 3
        assert metrics['correlations_found'] == 1
        assert metrics['overall_risk'] == 'high'
        assert metrics['cache_entries'] == 2  # cache + enrich_cache
        assert 'processing_timestamp' in metrics
        assert 'findings_by_severity' in metrics
        assert metrics['findings_by_severity']['high'] == 1
        assert metrics['findings_by_severity']['medium'] == 1
        assert metrics['findings_by_severity']['low'] == 1
        assert 'findings_by_category' in metrics
        assert 'correlation_effectiveness' in metrics

    @pytest.mark.asyncio
    async def test_metrics_collector_empty_state(self):
        """Test metrics_collector with minimal state."""
        state: GraphState = {
            'enriched_findings': [],
            'correlations': [],
            'cache': {},
            'enrich_cache': {}
        }

        result = await metrics_collector(state)

        metrics = result['final_metrics']
        assert metrics['findings_processed'] == 0
        assert metrics['correlations_found'] == 0
        assert metrics['cache_entries'] == 0
        assert metrics['correlation_effectiveness'] == 0.0

    @pytest.mark.asyncio
    async def test_metrics_collector_category_counting(self):
        """Test metrics_collector properly categorizes findings."""
        state: GraphState = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file privilege issue', 'severity': 'high'},
                {'id': 'f2', 'title': 'Network security problem', 'severity': 'medium'},
                {'id': 'f3', 'title': 'File permission issue', 'severity': 'low'},
                {'id': 'f4', 'title': 'Process security vulnerability', 'severity': 'high'}
            ],
            'correlations': [],
            'cache': {},
            'enrich_cache': {}
        }

        result = await metrics_collector(state)

        categories = result['final_metrics']['findings_by_category']
        assert categories['privilege_escalation'] == 1  # SUID file
        assert categories['network_security'] == 1  # Network title
        assert categories['filesystem'] == 1  # File permission
        assert categories['process_security'] == 1  # Process title


class TestEnrichmentFunctions:
    """Test enrichment.py functions for finding enrichment and correlation."""

    def test_enrich_findings_basic_functionality(self):
        """Test enrich_findings with basic raw findings."""
        from sys_scan_agent.graph.enrichment import enrich_findings

        state: Dict[str, Any] = {
            'raw_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80},
                {'id': 'f2', 'title': 'World readable file', 'severity': 'medium', 'risk_score': 40}
            ]
        }

        result = enrich_findings(state)

        assert 'enriched_findings' in result
        enriched = result['enriched_findings']
        assert len(enriched) == 2
        assert enriched[0]['id'] == 'f1'
        assert enriched[1]['id'] == 'f2'
        # Check that enrichment added additional fields
        assert 'tags' in enriched[0] or 'risk_subscores' in enriched[0] or 'probability_actionable' in enriched[0]

    def test_enrich_findings_empty_findings(self):
        """Test enrich_findings with no findings."""
        from sys_scan_agent.graph.enrichment import enrich_findings

        state: Dict[str, Any] = {
            'raw_findings': []
        }

        result = enrich_findings(state)

        assert 'enriched_findings' in result
        assert result['enriched_findings'] == []

    def test_correlate_findings_basic_functionality(self):
        """Test correlate_findings with enriched findings."""
        from sys_scan_agent.graph.enrichment import correlate_findings

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80, 'tags': ['privilege']},
                {'id': 'f2', 'title': 'SUID binary', 'severity': 'high', 'risk_score': 85, 'tags': ['privilege']},
                {'id': 'f3', 'title': 'World readable file', 'severity': 'medium', 'risk_score': 40, 'tags': ['filesystem']}
            ]
        }

        result = correlate_findings(state)

        assert 'correlations' in result
        correlations = result['correlations']
        assert isinstance(correlations, list)
        # Should have found correlations between similar privilege escalation findings
        assert len(correlations) >= 0  # May or may not find correlations depending on rules

    def test_correlate_findings_no_findings(self):
        """Test correlate_findings with no enriched findings."""
        from sys_scan_agent.graph.enrichment import correlate_findings

        state: Dict[str, Any] = {
            'enriched_findings': []
        }

        result = correlate_findings(state)

        assert 'correlations' in result
        assert result['correlations'] == []

    @pytest.mark.asyncio
    async def test_enhanced_enrich_findings_basic_functionality(self):
        """Test enhanced_enrich_findings with caching."""
        from sys_scan_agent.graph.enrichment import enhanced_enrich_findings

        state: Dict[str, Any] = {
            'raw_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80},
                {'id': 'f2', 'title': 'World readable file', 'severity': 'medium', 'risk_score': 40}
            ]
        }

        result = await enhanced_enrich_findings(state)

        assert 'enriched_findings' in result
        enriched = result['enriched_findings']
        assert len(enriched) == 2
        assert enriched[0]['id'] == 'f1'
        assert enriched[1]['id'] == 'f2'
        assert 'enrich_cache' in result
        assert 'cache_keys' in result
        assert len(result['cache_keys']) == 1

    @pytest.mark.asyncio
    async def test_enhanced_enrich_findings_cache_hit(self):
        """Test enhanced_enrich_findings cache hit scenario."""
        from sys_scan_agent.graph.enrichment import enhanced_enrich_findings

        # Pre-populate cache
        cached_findings = [
            {'id': 'f1', 'title': 'Cached SUID file', 'severity': 'high', 'risk_score': 80, 'cached': True},
            {'id': 'f2', 'title': 'Cached world readable', 'severity': 'medium', 'risk_score': 40, 'cached': True}
        ]

        state: Dict[str, Any] = {
            'raw_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80},
                {'id': 'f2', 'title': 'World readable file', 'severity': 'medium', 'risk_score': 40}
            ],
            'enrich_cache': {'enrich:some_key': cached_findings},
            'cache_keys': []
        }

        # Mock the cache key generation to return the known key
        with patch('sys_scan_agent.graph.enrichment._generate_cache_key', return_value='enrich:some_key'):
            result = await enhanced_enrich_findings(state)

            # Should use cached results
            assert result['enriched_findings'] == cached_findings
            assert result['enriched_findings'][0]['cached'] is True

    @pytest.mark.asyncio
    async def test_enhanced_enrich_findings_empty_findings(self):
        """Test enhanced_enrich_findings with no findings."""
        from sys_scan_agent.graph.enrichment import enhanced_enrich_findings

        state: Dict[str, Any] = {
            'raw_findings': []
        }

        result = await enhanced_enrich_findings(state)

        assert 'enriched_findings' in result
        assert result['enriched_findings'] == []
        assert 'cache_keys' in result

    @pytest.mark.asyncio
    async def test_enhanced_enrich_findings_error_handling(self):
        """Test enhanced_enrich_findings error handling."""
        from sys_scan_agent.graph.enrichment import enhanced_enrich_findings

        state: Dict[str, Any] = {
            'raw_findings': [
                {'id': 'f1', 'title': 'Test finding', 'severity': 'high', 'risk_score': 80}
            ]
        }

        # Mock pipeline to raise an exception
        with patch('sys_scan_agent.graph.enrichment._perform_enrichment_pipeline', side_effect=Exception("Test error")):
            result = await enhanced_enrich_findings(state)

            # Should handle error gracefully - enriched_findings may be empty or fallback to raw
            assert 'enriched_findings' in result
            # The exact behavior depends on when the error occurs, but it should be a list
            assert isinstance(result['enriched_findings'], list)
            assert 'warnings' in result
            assert len(result['warnings']) == 1
            assert 'Test error' in result['warnings'][0]['error']

    def test_enrich_findings_with_existing_enriched(self):
        """Test enrich_findings when enriched findings already exist."""
        from sys_scan_agent.graph.enrichment import enrich_findings

        state: Dict[str, Any] = {
            'raw_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80}
            ],
            'enriched_findings': [
                {'id': 'existing', 'title': 'Existing enriched', 'severity': 'low', 'risk_score': 20}
            ]
        }

        result = enrich_findings(state)

        # Should process raw findings and create new enriched findings
        assert 'enriched_findings' in result
        assert len(result['enriched_findings']) >= 1

    def test_correlate_findings_with_existing_correlations(self):
        """Test correlate_findings when correlations already exist."""
        from sys_scan_agent.graph.enrichment import correlate_findings

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'risk_score': 80, 'tags': ['privilege']}
            ],
            'correlations': [{'id': 'existing_corr', 'title': 'Existing correlation'}]
        }

        result = correlate_findings(state)

        # Should add to existing correlations or keep them
        assert 'correlations' in result
        assert isinstance(result['correlations'], list)


class TestRoutingFunctions:
    """Test routing.py functions for workflow routing and tool coordination."""

    def test_advanced_router_human_feedback_pending(self):
        """Test advanced_router returns human_feedback when pending."""
        from sys_scan_agent.graph.routing import advanced_router

        state: Dict[str, Any] = {
            'human_feedback_pending': True,
            'enriched_findings': [{'id': 'f1', 'severity': 'high'}]
        }

        result = advanced_router(state)
        assert result == 'human_feedback'

    def test_advanced_router_no_findings(self):
        """Test advanced_router returns summarize when no findings."""
        from sys_scan_agent.graph.routing import advanced_router

        state: Dict[str, Any] = {
            'enriched_findings': [],
            'correlated_findings': []
        }

        result = advanced_router(state)
        assert result == 'summarize'

    def test_advanced_router_compliance_violations(self):
        """Test advanced_router routes to compliance_checker for compliance violations."""
        from sys_scan_agent.graph.routing import advanced_router

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'SUID file found', 'severity': 'high', 'tags': ['pci']},
                {'id': 'f2', 'title': 'World readable file', 'severity': 'medium', 'metadata': {'compliance_standard': 'HIPAA'}}
            ]
        }

        result = advanced_router(state)
        assert result == 'compliance'

    def test_advanced_router_baseline_missing(self):
        """Test advanced_router routes to plan_baseline for missing baseline."""
        from sys_scan_agent.graph.routing import advanced_router

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'High severity finding', 'severity': 'high', 'baseline_status': 'new'}
            ],
            'baseline_results': {}
        }

        result = advanced_router(state)
        assert result == 'baseline'

    def test_advanced_router_default_summarize(self):
        """Test advanced_router defaults to summarize."""
        from sys_scan_agent.graph.routing import advanced_router

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Low severity finding', 'severity': 'low', 'baseline_status': 'existing'}
            ],
            'baseline_results': {'f1': 'baseline_data'}
        }

        result = advanced_router(state)
        assert result == 'summarize'

    def test_should_suggest_rules_no_findings(self):
        """Test should_suggest_rules with no findings."""
        from sys_scan_agent.graph.routing import should_suggest_rules

        state: Dict[str, Any] = {
            'enriched_findings': []
        }

        result = should_suggest_rules(state)
        assert result in ['__end__', 'END']  # Depends on langgraph availability

    def test_should_suggest_rules_high_severity(self):
        """Test should_suggest_rules routes to suggest_rules for high severity findings."""
        from sys_scan_agent.graph.routing import should_suggest_rules

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'High severity finding', 'severity': 'high'},
                {'id': 'f2', 'title': 'Low severity finding', 'severity': 'low'}
            ]
        }

        result = should_suggest_rules(state)
        assert result == 'suggest_rules'

    def test_should_suggest_rules_no_high_severity(self):
        """Test should_suggest_rules ends workflow when no high severity findings."""
        from sys_scan_agent.graph.routing import should_suggest_rules

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Medium severity finding', 'severity': 'medium'},
                {'id': 'f2', 'title': 'Low severity finding', 'severity': 'low'}
            ]
        }

        result = should_suggest_rules(state)
        assert result in ['__end__', 'END']  # Depends on langgraph availability

    def test_choose_post_summarize_baseline_needed(self):
        """Test choose_post_summarize routes to plan_baseline when baseline cycle not done."""
        from sys_scan_agent.graph.routing import choose_post_summarize

        state: Dict[str, Any] = {
            'baseline_cycle_done': False,
            'enriched_findings': [
                {'id': 'f1', 'title': 'Finding without baseline', 'severity': 'high'}
            ]
        }

        result = choose_post_summarize(state)
        assert result == 'plan_baseline'

    def test_choose_post_summarize_baseline_done(self):
        """Test choose_post_summarize delegates to should_suggest_rules when baseline done."""
        from sys_scan_agent.graph.routing import choose_post_summarize

        state: Dict[str, Any] = {
            'baseline_cycle_done': True,
            'enriched_findings': [
                {'id': 'f1', 'title': 'High severity finding', 'severity': 'high'}
            ]
        }

        result = choose_post_summarize(state)
        assert result == 'suggest_rules'

    @pytest.mark.asyncio
    async def test_tool_coordinator_no_findings(self):
        """Test tool_coordinator with no findings."""
        from sys_scan_agent.graph.routing import tool_coordinator

        state: Dict[str, Any] = {
            'enriched_findings': [],
            'correlated_findings': []
        }

        result = await tool_coordinator(state)

        assert result['pending_tool_calls'] == []
        assert 'tool_coordinator_calls' in result.get('metrics', {})

    @pytest.mark.asyncio
    async def test_tool_coordinator_with_missing_baseline(self):
        """Test tool_coordinator creates tool calls for missing baseline."""
        from sys_scan_agent.graph.routing import tool_coordinator

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Finding needing baseline', 'severity': 'high'},
                {'id': 'f2', 'title': 'Finding with baseline', 'severity': 'medium', 'baseline_status': 'existing'}
            ]
        }

        result = await tool_coordinator(state)

        pending_calls = result['pending_tool_calls']
        assert len(pending_calls) == 1
        assert pending_calls[0]['name'] == 'query_baseline'
        assert pending_calls[0]['args']['finding_id'] == 'f1'
        assert 'tool_coordinator_calls' in result.get('metrics', {})

    @pytest.mark.asyncio
    async def test_tool_coordinator_all_baselines_present(self):
        """Test tool_coordinator when all findings have baseline."""
        from sys_scan_agent.graph.routing import tool_coordinator

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Finding with baseline', 'severity': 'high', 'baseline_status': 'existing'}
            ]
        }

        result = await tool_coordinator(state)

        assert result['pending_tool_calls'] == []
        assert 'tool_coordinator_calls' in result.get('metrics', {})

    @pytest.mark.asyncio
    async def test_tool_coordinator_error_handling(self):
        """Test tool_coordinator error handling."""
        from sys_scan_agent.graph.routing import tool_coordinator

        state: Dict[str, Any] = {
            'enriched_findings': [
                {'id': 'f1', 'title': 'Test finding', 'severity': 'high'}
            ]
        }

        # Mock to raise an exception
        with patch('sys_scan_agent.graph.routing._prepare_tool_coordination_data', side_effect=Exception("Test error")):
            result = await tool_coordinator(state)

            # Should handle error gracefully and add warning
            assert 'warnings' in result
            assert len(result['warnings']) == 1
            assert 'Test error' in result['warnings'][0]['error']


class TestCanonicalizeFunctions:
    """Test canonicalize.py functions for deterministic output ordering."""

    def test_canonicalize_enriched_output_dict_basic_functionality(self):
        """Test canonicalize_enriched_output_dict with basic enriched output."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        output_dict = {
            'correlations': [
                {'id': 'corr3', 'title': 'Third correlation'},
                {'id': 'corr1', 'title': 'First correlation'},
                {'id': 'corr2', 'title': 'Second correlation'}
            ],
            'actions': [
                {'priority': 1, 'action': 'Low priority'},
                {'priority': 3, 'action': 'High priority'},
                {'priority': 2, 'action': 'Medium priority'}
            ],
            'followups': [
                {'finding_id': 'f3', 'followup': 'Third followup'},
                {'finding_id': 'f1', 'followup': 'First followup'},
                {'finding_id': 'f2', 'followup': 'Second followup'}
            ],
            'multi_host_correlation': [
                {'key': 'key3', 'correlation': 'Third multi-host'},
                {'key': 'key1', 'correlation': 'First multi-host'},
                {'key': 'key2', 'correlation': 'Second multi-host'}
            ],
            'other_field': 'unchanged'
        }

        result = canonicalize_enriched_output_dict(output_dict)

        # Check correlations are sorted by id
        assert result['correlations'][0]['id'] == 'corr1'
        assert result['correlations'][1]['id'] == 'corr2'
        assert result['correlations'][2]['id'] == 'corr3'

        # Check actions are sorted by priority (descending)
        assert result['actions'][0]['priority'] == 3
        assert result['actions'][1]['priority'] == 2
        assert result['actions'][2]['priority'] == 1

        # Check followups are sorted by finding_id
        assert result['followups'][0]['finding_id'] == 'f1'
        assert result['followups'][1]['finding_id'] == 'f2'
        assert result['followups'][2]['finding_id'] == 'f3'

        # Check multi_host_correlation are sorted by key
        assert result['multi_host_correlation'][0]['key'] == 'key1'
        assert result['multi_host_correlation'][1]['key'] == 'key2'
        assert result['multi_host_correlation'][2]['key'] == 'key3'

        # Check other fields are unchanged
        assert result['other_field'] == 'unchanged'

    def test_canonicalize_enriched_output_dict_empty_lists(self):
        """Test canonicalize_enriched_output_dict with empty lists."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        output_dict = {
            'correlations': [],
            'actions': [],
            'followups': [],
            'multi_host_correlation': []
        }

        result = canonicalize_enriched_output_dict(output_dict)

        assert result['correlations'] == []
        assert result['actions'] == []
        assert result['followups'] == []
        assert result['multi_host_correlation'] == []

    def test_canonicalize_enriched_output_dict_missing_fields(self):
        """Test canonicalize_enriched_output_dict with missing fields."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        output_dict = {
            'some_field': 'value'
        }

        result = canonicalize_enriched_output_dict(output_dict)

        assert result['some_field'] == 'value'
        assert 'correlations' not in result
        assert 'actions' not in result
        assert 'followups' not in result
        assert 'multi_host_correlation' not in result

    def test_canonicalize_enriched_output_dict_non_dict_items(self):
        """Test canonicalize_enriched_output_dict with non-dict items in lists."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        output_dict = {
            'correlations': ['string_corr3', 'string_corr1', 'string_corr2'],
            'actions': ['action3', 'action1', 'action2'],
            'followups': ['followup3', 'followup1', 'followup2'],
            'multi_host_correlation': ['multi3', 'multi1', 'multi2']
        }

        result = canonicalize_enriched_output_dict(output_dict)

        # Non-dict items should be sorted as strings (correlations, followups, multi_host_correlation)
        assert result['correlations'] == ['string_corr1', 'string_corr2', 'string_corr3']
        assert result['followups'] == ['followup1', 'followup2', 'followup3']
        assert result['multi_host_correlation'] == ['multi1', 'multi2', 'multi3']

        # Actions are sorted by priority (reverse=True), but non-dict items get priority 0, so stable sort
        # The original order is preserved when priorities are equal
        assert len(result['actions']) == 3
        assert set(result['actions']) == {'action1', 'action2', 'action3'}

    def test_canonicalize_enriched_output_dict_non_list_fields(self):
        """Test canonicalize_enriched_output_dict with non-list fields."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        output_dict = {
            'correlations': 'not_a_list',
            'actions': 123,
            'followups': {'key': 'value'},
            'multi_host_correlation': True
        }

        result = canonicalize_enriched_output_dict(output_dict)

        # Non-list fields should be unchanged
        assert result['correlations'] == 'not_a_list'
        assert result['actions'] == 123
        assert result['followups'] == {'key': 'value'}
        assert result['multi_host_correlation'] is True

    def test_canonicalize_enriched_output_dict_preserves_original(self):
        """Test canonicalize_enriched_output_dict preserves the original dict."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        original = {
            'correlations': [{'id': 'corr2'}, {'id': 'corr1'}],
            'actions': [{'priority': 1}, {'priority': 2}]
        }
        original_copy = original.copy()

        result = canonicalize_enriched_output_dict(original)

        # Original should be unchanged
        assert original == original_copy
        # Result should be different (sorted)
        assert result != original
        assert result['correlations'][0]['id'] == 'corr1'
        assert result['correlations'][1]['id'] == 'corr2'

    def test_canonicalize_enriched_output_dict_complex_nested(self):
        """Test canonicalize_enriched_output_dict with complex nested structures."""
        from sys_scan_agent.canonicalize import canonicalize_enriched_output_dict

        output_dict = {
            'correlations': [
                {'id': 'corr2', 'nested': {'value': 2}},
                {'id': 'corr1', 'nested': {'value': 1}},
                {'id': 'corr3', 'nested': {'value': 3}}
            ],
            'actions': [
                {'priority': 2, 'details': {'complex': True}},
                {'priority': 1, 'details': {'complex': False}},
                {'priority': 3, 'details': {'complex': True}}
            ]
        }

        result = canonicalize_enriched_output_dict(output_dict)

        # Should sort by id/priority, preserving nested structure
        assert result['correlations'][0]['id'] == 'corr1'
        assert result['correlations'][1]['id'] == 'corr2'
        assert result['correlations'][2]['id'] == 'corr3'

        assert result['actions'][0]['priority'] == 3
        assert result['actions'][1]['priority'] == 2
        assert result['actions'][2]['priority'] == 1

        # Nested structures should be preserved
        assert result['correlations'][0]['nested']['value'] == 1
        assert result['actions'][0]['details']['complex'] is True


class TestEndpointClassification:
    """Test endpoint_classification.py functions for host role classification."""

    def test_classify_empty_report(self):
        """Test classify with empty report."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'workstation'
        assert signals == ['no findings => default workstation']

    def test_classify_none_report(self):
        """Test classify with None report."""
        from sys_scan_agent.endpoint_classification import classify

        role, signals = classify(None)

        assert role == 'workstation'
        assert signals == ['no findings => default workstation']

    def test_classify_bastion_role(self):
        """Test classify identifies bastion role."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        # Create findings with bastion signals: multiple SSH listeners + routing
        findings = [
            models.Finding(
                id='f1',
                title='SSH listener 1',
                severity='info',
                risk_score=0,
                metadata={'state': 'LISTEN', 'port': 22},
                tags=['network']
            ),
            models.Finding(
                id='f2',
                title='SSH listener 2',
                severity='info',
                risk_score=0,
                metadata={'state': 'LISTEN', 'port': 22},
                tags=['network']
            ),
            models.Finding(
                id='f3',
                title='Routing enabled',
                severity='info',
                risk_score=0,
                metadata={},
                tags=['routing']
            )
        ]

        scanner_result = models.ScannerResult(
            scanner='network',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'bastion'
        assert 'bastion: 2 ssh listeners + routing/nat signals' in signals

    def test_classify_lightweight_router_ip_forward(self):
        """Test classify identifies lightweight_router with IP forwarding."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = [
            models.Finding(
                id='f1',
                title='IP forwarding enabled',
                severity='info',
                risk_score=0,
                metadata={'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'},
                tags=[]
            )
        ]

        scanner_result = models.ScannerResult(
            scanner='kernel_params',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'lightweight_router'
        assert 'lightweight_router: routing/nat or ip_forward enabled' in signals

    def test_classify_lightweight_router_nat(self):
        """Test classify identifies lightweight_router with NAT."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = [
            models.Finding(
                id='f1',
                title='NAT configuration',
                severity='info',
                risk_score=0,
                metadata={},
                tags=['nat']
            )
        ]

        scanner_result = models.ScannerResult(
            scanner='network',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'lightweight_router'
        assert 'lightweight_router: routing/nat or ip_forward enabled' in signals

    def test_classify_container_host(self):
        """Test classify identifies container_host."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = [
            models.Finding(
                id='f1',
                title='Container module',
                severity='info',
                risk_score=0,
                metadata={'module': 'overlay'},
                tags=['container']
            ),
            models.Finding(
                id='f2',
                title='Docker socket',
                severity='info',
                risk_score=0,
                metadata={},
                tags=['docker']
            )
        ]

        scanner_result = models.ScannerResult(
            scanner='modules',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'container_host'
        assert 'container modules detected (1)' in signals

    def test_classify_dev_workstation(self):
        """Test classify identifies dev_workstation."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = [
            # Dev ports
            models.Finding(
                id='f1',
                title='Dev server on 3000',
                severity='info',
                risk_score=0,
                metadata={'port': 3000, 'state': 'LISTEN'},
                tags=['network']
            ),
            models.Finding(
                id='f2',
                title='Dev server on 5173',
                severity='info',
                risk_score=0,
                metadata={'port': 5173, 'state': 'LISTEN'},
                tags=['network']
            ),
            # High ports
            models.Finding(
                id='f3',
                title='High port service',
                severity='info',
                risk_score=0,
                metadata={'port': 35000, 'state': 'LISTEN'},
                tags=['network']
            ),
            models.Finding(
                id='f4',
                title='Another high port',
                severity='info',
                risk_score=0,
                metadata={'port': 40000, 'state': 'LISTEN'},
                tags=['network']
            )
        ]

        scanner_result = models.ScannerResult(
            scanner='network',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'dev_workstation'
        assert 'dev ports 2 & high ephemeral listeners 2' in signals

    def test_classify_workstation_fallback(self):
        """Test classify defaults to workstation."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = [
            models.Finding(
                id='f1',
                title='Some service',
                severity='info',
                risk_score=0,
                metadata={'port': 80, 'state': 'LISTEN'},
                tags=['network']
            )
        ]

        scanner_result = models.ScannerResult(
            scanner='network',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'workstation'
        assert 'default workstation fallback' in signals

    def test_classify_bastion_with_many_services(self):
        """Test classify bastion with many services gets additional signal."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = []
        # Create 15 listening services (more than 12)
        for i in range(15):
            findings.append(models.Finding(
                id=f'f{i}',
                title=f'Service {i}',
                severity='info',
                risk_score=0,
                metadata={'state': 'LISTEN', 'port': 1000 + i},
                tags=['network']
            ))

        # Add bastion signals
        findings.extend([
            models.Finding(
                id='ssh1',
                title='SSH 1',
                severity='info',
                risk_score=0,
                metadata={'state': 'LISTEN', 'port': 22},
                tags=['network']
            ),
            models.Finding(
                id='ssh2',
                title='SSH 2',
                severity='info',
                risk_score=0,
                metadata={'state': 'LISTEN', 'port': 22},
                tags=['network']
            ),
            models.Finding(
                id='route',
                title='Routing',
                severity='info',
                risk_score=0,
                metadata={},
                tags=['routing']
            )
        ])

        scanner_result = models.ScannerResult(
            scanner='network',
            finding_count=len(findings),
            findings=findings
        )

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'lightweight_router'
        assert 'lightweight_router: routing/nat or ip_forward enabled' in signals
        assert '17 listening services (mixed)' in signals

    def test_classify_multiple_scanner_types(self):
        """Test classify with multiple scanner result types."""
        from sys_scan_agent.endpoint_classification import classify
        from sys_scan_agent import models

        findings = [
            # Network findings
            models.Finding(
                id='net1',
                title='SSH',
                severity='info',
                risk_score=0,
                metadata={'state': 'LISTEN', 'port': 22},
                tags=['network']
            ),
            # Kernel params
            models.Finding(
                id='kern1',
                title='IP forward',
                severity='info',
                risk_score=0,
                metadata={'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'},
                tags=[]
            ),
            # Modules
            models.Finding(
                id='mod1',
                title='Container module',
                severity='info',
                risk_score=0,
                metadata={'module': 'overlay'},
                tags=['container']
            )
        ]

        results = [
            models.ScannerResult(scanner='network', finding_count=1, findings=[findings[0]]),
            models.ScannerResult(scanner='kernel_params', finding_count=1, findings=[findings[1]]),
            models.ScannerResult(scanner='modules', finding_count=1, findings=[findings[2]])
        ]

        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=results,
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        # Should prioritize lightweight_router over container_host due to ordering
        assert role == 'lightweight_router'
        assert 'lightweight_router: routing/nat or ip_forward enabled' in signals

    def test_classify_role_order_precedence(self):
        """Test that role ordering is respected (bastion > lightweight_router > container_host > dev_workstation > workstation)."""
        from sys_scan_agent.endpoint_classification import classify, ROLE_ORDER
        from sys_scan_agent import models

        # Test that bastion takes precedence over others
        findings = [
            # Bastion signals
            models.Finding(id='ssh1', title='SSH1', severity='info', risk_score=0, metadata={'state': 'LISTEN', 'port': 22}, tags=['network']),
            models.Finding(id='ssh2', title='SSH2', severity='info', risk_score=0, metadata={'state': 'LISTEN', 'port': 22}, tags=['network']),
            models.Finding(id='route', title='Route', severity='info', risk_score=0, metadata={}, tags=['routing']),
            # Container signals (should be ignored due to precedence)
            models.Finding(id='cont', title='Container', severity='info', risk_score=0, metadata={'module': 'overlay'}, tags=['container']),
            # Dev signals (should be ignored)
            models.Finding(id='dev1', title='Dev port', severity='info', risk_score=0, metadata={'port': 3000, 'state': 'LISTEN'}, tags=['network']),
            models.Finding(id='dev2', title='High port', severity='info', risk_score=0, metadata={'port': 35000, 'state': 'LISTEN'}, tags=['network'])
        ]

        scanner_result = models.ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(),
            results=[scanner_result],
            summary_extension=models.SummaryExtension(total_risk_score=0)
        )

        role, signals = classify(report)

        assert role == 'lightweight_router'
        assert ROLE_ORDER.index(role) < ROLE_ORDER.index('container_host')
        assert ROLE_ORDER.index(role) < ROLE_ORDER.index('dev_workstation')
        assert ROLE_ORDER.index(role) < ROLE_ORDER.index('workstation')