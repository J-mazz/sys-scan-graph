# Graph nodes package for sys-scan-graph agent
# This package contains modular graph node implementations for various analysis functions

from typing import TypedDict, List, Dict, Any, Optional
import asyncio

# Import shared utilities from base module (single source of truth)
from .base import (
    StateType,
    WarningInfo,
    SummarizationContext,
    get_env_var,
    clear_env_cache,
    normalize_compliance_standard,
    extract_findings_from_state,
    initialize_state_fields,
    normalize_state,
    ensure_monotonic_timing,
    update_metrics_duration,
    update_metrics_counter,
    append_warning,
    build_finding_models,
    build_agent_state,
    findings_from_graph,
    batch_extract_finding_fields,
    batch_filter_findings_by_severity,
    batch_check_baseline_status,
    is_compliance_related,
    batch_check_compliance_indicators,
    count_severities,
    calculate_risk_totals,
    determine_qualitative_risk,
    batch_calculate_risk_metrics,
    batch_get_top_findings_by_risk,
    count_findings_by_severity,
    get_enhanced_llm_provider,
)

# Import GraphState from dedicated state module (single source of truth)
from .state import GraphState

# Import memory and reflection from dedicated modules
from .memory import (
    memory_manager,
    _extract_patterns_from_history,
    _accumulate_context,
)

from .reflection import (
    reflection_engine,
    _assess_analysis_quality,
    _identify_uncertainty_factors,
    _generate_strategy_adjustments,
    _perform_cyclical_reasoning,
)

# Import generic async wrapper utility
from .utils import run_async_node

# Import node functions from submodules
from .enrichment import enrich_findings, correlate_findings, enhanced_enrich_findings
from .summarization import enhanced_summarize_host_state, _generate_executive_summary, _create_reductions, _count_findings_by_severity
from .routing import advanced_router, tool_coordinator, should_suggest_rules, choose_post_summarize
from .baseline import plan_baseline_queries, integrate_baseline_results
from .analysis import risk_analyzer, compliance_checker, metrics_collector
from .cache import cache_manager
from .rules import enhanced_suggest_rules
from .utils import (
    _batch_check_external_requirements,
    _extract_metadata_standards,
    _extract_tag_standards,
    _map_findings_to_standards,
    _batch_normalize_compliance_standards,
)

# Import optional dependencies with fallbacks
try:
    from langgraph.graph import StateGraph, END, START  # type: ignore
    from langgraph.prebuilt import ToolNode  # type: ignore
except ImportError:
    StateGraph = None
    END = None
    START = None
    ToolNode = None

try:
    from ..tools import query_baseline
except ImportError:
    query_baseline = None


# ==============================================================================
# Sync Wrappers - Look up function at call time to support patching in tests
# ==============================================================================

def summarize_host_state(state: GraphState) -> GraphState:
    """Sync wrapper for enhanced_summarize_host_state."""
    func = globals().get('enhanced_summarize_host_state')
    if func is None:
        return state
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(func(state))
        loop.close()
        return result
    except Exception:
        return state


def suggest_rules(state: GraphState) -> GraphState:
    """Sync wrapper for enhanced_suggest_rules."""
    func = globals().get('enhanced_suggest_rules')
    if func is None:
        return state
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(func(state))
        loop.close()
        return result
    except Exception:
        return state


def tool_coordinator_sync(state: GraphState) -> GraphState:
    """Sync wrapper for tool_coordinator."""
    func = globals().get('tool_coordinator')
    if func is None:
        return state
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(func(state))
        loop.close()
        return result
    except Exception:
        return state


def risk_analyzer_sync(state: GraphState) -> GraphState:
    """Sync wrapper for risk_analyzer."""
    func = globals().get('risk_analyzer')
    if func is None:
        return state
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(func(state))
        loop.close()
        return result
    except Exception:
        return state


def compliance_checker_sync(state: GraphState) -> GraphState:
    """Sync wrapper for compliance_checker."""
    func = globals().get('compliance_checker')
    if func is None:
        return state
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(func(state))
        loop.close()
        return result
    except Exception:
        return state


def metrics_collector_sync(state: GraphState) -> GraphState:
    """Sync wrapper for metrics_collector."""
    func = globals().get('metrics_collector')
    if func is None:
        return state
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(func(state))
        loop.close()
        return result
    except Exception:
        return state


def baseline_tools_sync(state: GraphState) -> GraphState:
    """Sync wrapper for ToolNode execution that updates state with tool results."""
    func = globals().get('query_baseline')
    if func is None:
        return state
    
    messages = state.get('messages', [])
    if not messages:
        return state
    
    last_message = messages[-1]
    if not hasattr(last_message, 'tool_calls') or not last_message.tool_calls:
        return state
    
    tool_results = []
    for tool_call in last_message.tool_calls:
        try:
            args = tool_call.get('args', {})
            result = func(**args)
            tool_results.append({
                'type': 'tool',
                'content': result,
                'tool_call_id': tool_call.get('id'),
                'name': tool_call.get('name')
            })
        except Exception as e:
            tool_results.append({
                'type': 'tool',
                'content': {'error': str(e), 'status': 'error'},
                'tool_call_id': tool_call.get('id'),
                'name': tool_call.get('name')
            })
    
    state['messages'] = messages + tool_results
    return state


def build_workflow(enhanced: Optional[bool] = None):
    """Build and compile a robust StateGraph workflow with memory management, tool calling, and reflection.

    Features:
    - Memory management for cross-iteration learning
    - Tool calling integration for baseline queries
    - Reflection engine for cyclical reasoning
    - Risk and compliance analysis

    Returns:
        (workflow, app) tuple – uncompiled workflow object and compiled app.
    """
    current_StateGraph = globals().get('StateGraph')
    current_END = globals().get('END')
    current_query_baseline = globals().get('query_baseline')

    if current_StateGraph is None:
        return None, None

    required_nodes = [
        enrich_findings, summarize_host_state, suggest_rules,
        tool_coordinator_sync, plan_baseline_queries, baseline_tools_sync,
        integrate_baseline_results,
        risk_analyzer_sync, compliance_checker_sync, metrics_collector_sync
    ]

    if any(node is None for node in required_nodes):
        return None, None

    wf = current_StateGraph(GraphState)

    # --- Add Nodes ---
    wf.add_node("enrich", enrich_findings)
    wf.add_node("memory_manager", memory_manager)
    wf.add_node("reflection_engine", reflection_engine)
    wf.add_node("summarize", summarize_host_state)
    wf.add_node("suggest_rules", suggest_rules)
    wf.add_node("tool_coordinator", tool_coordinator_sync)
    wf.add_node("plan_baseline", plan_baseline_queries)
    if current_query_baseline is not None:
        wf.add_node("baseline_tools", baseline_tools_sync)
    wf.add_node("integrate_baseline", integrate_baseline_results)
    wf.add_node("risk_analysis", risk_analyzer_sync)
    wf.add_node("compliance_checker_node", compliance_checker_sync)
    wf.add_node("metrics_collection", metrics_collector_sync)

    # --- Define Edges ---
    wf.set_entry_point("enrich")
    wf.add_edge("enrich", "memory_manager")
    wf.add_edge("memory_manager", "reflection_engine")
    wf.add_edge("reflection_engine", "summarize")
    wf.add_edge("summarize", "suggest_rules")
    wf.add_edge("suggest_rules", "tool_coordinator")
    wf.add_edge("tool_coordinator", "plan_baseline")
    
    if current_query_baseline is not None:
        wf.add_edge("plan_baseline", "baseline_tools")
        wf.add_edge("baseline_tools", "integrate_baseline")
    else:
        wf.add_edge("plan_baseline", "integrate_baseline")
    
    wf.add_edge("integrate_baseline", "risk_analysis")
    wf.add_edge("risk_analysis", "compliance_checker_node")
    wf.add_edge("compliance_checker_node", "metrics_collection")
    wf.add_edge("metrics_collection", current_END)

    try:
        compiled = wf.compile()
        return wf, compiled
    except Exception:
        return wf, None


# Build default workflow at import
workflow, app = build_workflow()

# Backward compatibility alias
BaselineQueryGraph = app

__all__ = [
    # Node functions from submodules
    'enrich_findings', 'correlate_findings', 'enhanced_enrich_findings',
    'enhanced_summarize_host_state', '_generate_executive_summary', '_create_reductions', '_count_findings_by_severity',
    'advanced_router', 'tool_coordinator', 'should_suggest_rules', 'choose_post_summarize',
    'plan_baseline_queries', 'integrate_baseline_results',
    'risk_analyzer', 'compliance_checker', 'metrics_collector',
    'cache_manager', 'enhanced_suggest_rules',
    
    # Shared utilities from base.py
    'GraphState', 'StateType', 'WarningInfo', 'SummarizationContext',
    'get_env_var', 'clear_env_cache', 'normalize_compliance_standard',
    'extract_findings_from_state', 'initialize_state_fields', 'normalize_state',
    'ensure_monotonic_timing', 'update_metrics_duration', 'update_metrics_counter',
    'append_warning', 'build_finding_models', 'build_agent_state', 'findings_from_graph',
    'batch_extract_finding_fields', 'batch_filter_findings_by_severity', 'batch_check_baseline_status',
    'is_compliance_related', 'batch_check_compliance_indicators',
    'count_severities', 'calculate_risk_totals', 'determine_qualitative_risk',
    'batch_calculate_risk_metrics', 'batch_get_top_findings_by_risk', 'count_findings_by_severity',
    'get_enhanced_llm_provider',
    
    # Async wrapper utility
    'run_async_node',
    
    # Utils-specific functions
    '_batch_check_external_requirements', '_extract_metadata_standards',
    '_extract_tag_standards', '_map_findings_to_standards', '_batch_normalize_compliance_standards',
    
    # Memory management and reflection (from dedicated modules)
    'memory_manager', 'reflection_engine',
    '_extract_patterns_from_history', '_accumulate_context', '_assess_analysis_quality',
    '_identify_uncertainty_factors', '_generate_strategy_adjustments', '_perform_cyclical_reasoning',
    
    # Sync wrappers
    'summarize_host_state', 'suggest_rules', 'tool_coordinator_sync',
    'risk_analyzer_sync', 'compliance_checker_sync', 'metrics_collector_sync',
    'baseline_tools_sync', 'build_workflow', 'workflow', 'app', 'BaselineQueryGraph',
    
    # Optional dependencies
    'StateGraph', 'END', 'START', 'ToolNode', 'query_baseline'
]
