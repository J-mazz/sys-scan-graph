#    .________      ._____.___ .______  .______ .______ .___ .______  .___
#    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
#     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
#    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
#     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
#        :/               |___|    |___|    :       :   |___|    |___||___|
#        :                                  •       •                 
#                                                                          
#
#    2925
#    graph.py - Clean Orchestrator Module
#
# ==============================================================================
"""LangGraph workflow orchestrator for the analysis agent.

This module serves as a clean orchestrator that assembles the StateGraph workflow
from specialized submodules. The actual logic has been extracted to:
- graph/state.py: GraphState TypedDict definition
- graph/memory.py: Memory management for cross-iteration learning
- graph/reflection.py: Reflection engine for cyclical reasoning
- graph/utils.py: Generic async wrapper and utility functions
"""
from __future__ import annotations
import asyncio
from typing import Optional, List, Dict, Any

# ==============================================================================
# Import GraphState from dedicated module (single source of truth)
# ==============================================================================
from .graph.state import GraphState

# ==============================================================================
# Import memory and reflection engines from dedicated modules
# Also re-export helper functions for backward compatibility with tests
# ==============================================================================
from .graph.memory import (
    memory_manager,
    _extract_patterns_from_history,
    _accumulate_context,
)

from .graph.reflection import (
    reflection_engine,
    _assess_analysis_quality,
    _identify_uncertainty_factors,
    _generate_strategy_adjustments,
    _perform_cyclical_reasoning,
)

# ==============================================================================
# Runtime graph assembly (enhanced workflow builder)
# ==============================================================================
try:  # Optional dependency guard
    from langgraph.graph import StateGraph, END, START  # type: ignore
    from langgraph.prebuilt import ToolNode  # type: ignore

    # Import scaffold nodes (required for current workflow)
    from .graph.enrichment import enrich_findings, correlate_findings
    from .graph.summarization import enhanced_summarize_host_state
    from .graph.rules import enhanced_suggest_rules
    from .graph.routing import tool_coordinator
    from .graph.baseline import plan_baseline_queries, integrate_baseline_results
    from .graph.analysis import risk_analyzer, compliance_checker, metrics_collector

    from .tools import query_baseline
except Exception:  # pragma: no cover - graph optional
    StateGraph = None  # type: ignore
    END = None  # type: ignore
    START = None  # type: ignore
    ToolNode = None  # type: ignore
    enrich_findings = None  # type: ignore
    correlate_findings = None  # type: ignore
    enhanced_summarize_host_state = None  # type: ignore
    enhanced_suggest_rules = None  # type: ignore
    tool_coordinator = None  # type: ignore
    plan_baseline_queries = None  # type: ignore
    integrate_baseline_results = None  # type: ignore
    risk_analyzer = None  # type: ignore
    compliance_checker = None  # type: ignore
    metrics_collector = None  # type: ignore
    query_baseline = None  # type: ignore


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
    """Execute baseline tool calls and update state with results."""
    func = globals().get('query_baseline')
    if ToolNode is None or func is None:
        return state
    
    messages = state.get('messages', [])
    if not messages:
        return state
    
    last_message = messages[-1]
    if not hasattr(last_message, 'tool_calls') or not last_message.tool_calls:
        return state
    
    tool_results: List[Dict[str, Any]] = []
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


# ==============================================================================
# Workflow Builder
# ==============================================================================

def build_workflow(enhanced: Optional[bool] = None, interactive: bool = False):
    """Build and compile a robust StateGraph workflow.

    Features:
    - Memory management for cross-iteration learning
    - Tool calling integration for baseline queries
    - Reflection engine for cyclical reasoning
    - Risk and compliance analysis

    Returns:
        (workflow, app) tuple – uncompiled workflow object and compiled app.
    """
    if StateGraph is None:
        return None, None

    required_nodes = [
        enrich_findings, summarize_host_state, suggest_rules,
        tool_coordinator_sync, plan_baseline_queries, baseline_tools_sync,
        integrate_baseline_results,
        risk_analyzer_sync, compliance_checker_sync, metrics_collector_sync
    ]

    if any(node is None for node in required_nodes):
        return None, None

    wf = StateGraph(GraphState)

    # --- Add Nodes ---
    wf.add_node("enrich", enrich_findings)
    wf.add_node("memory_manager", memory_manager)
    wf.add_node("reflection_engine", reflection_engine)
    wf.add_node("summarize", summarize_host_state)
    wf.add_node("suggest_rules", suggest_rules)
    wf.add_node("tool_coordinator", tool_coordinator_sync)
    wf.add_node("plan_baseline", plan_baseline_queries)
    wf.add_node("baseline_tools", baseline_tools_sync)
    wf.add_node("integrate_baseline", integrate_baseline_results)
    wf.add_node("risk_analysis", risk_analyzer_sync)
    wf.add_node("compliance_checker_node", compliance_checker_sync)
    wf.add_node("metrics_collection", metrics_collector_sync)

    # --- Define Edges (linear workflow) ---
    wf.set_entry_point("enrich")
    wf.add_edge("enrich", "memory_manager")
    wf.add_edge("memory_manager", "reflection_engine")
    wf.add_edge("reflection_engine", "summarize")
    wf.add_edge("summarize", "suggest_rules")
    wf.add_edge("suggest_rules", "tool_coordinator")
    wf.add_edge("tool_coordinator", "plan_baseline")
    wf.add_edge("plan_baseline", "baseline_tools")
    wf.add_edge("baseline_tools", "integrate_baseline")
    wf.add_edge("integrate_baseline", "risk_analysis")
    wf.add_edge("risk_analysis", "compliance_checker_node")
    wf.add_edge("compliance_checker_node", "metrics_collection")
    # Final edge: either to END (non-interactive) or to Investigation Director when interactive
    if interactive:
        try:
            from .graph_nodes_ui import investigation_director_node
            wf.add_node("investigation_director", investigation_director_node)
            wf.add_edge("metrics_collection", "investigation_director")
            wf.add_edge("investigation_director", END)
        except Exception as e:  # pragma: no cover - optional
            logger.warning(f"Interactive mode requested but could not add Investigation Director: {e}")
            wf.add_edge("metrics_collection", END)
    else:
        wf.add_edge("metrics_collection", END)

    try:
        compiled = wf.compile()
        return wf, compiled
    except Exception:
        return wf, None


# ==============================================================================
# Module Initialization
# ==============================================================================
workflow, app = build_workflow()

# Backward compatibility alias
BaselineQueryGraph = app

__all__ = [
    # Core exports
    "GraphState", "workflow", "app", "build_workflow", "BaselineQueryGraph",
    # Memory management (re-exported for backward compatibility)
    "memory_manager", "_extract_patterns_from_history", "_accumulate_context",
    # Reflection (re-exported for backward compatibility)
    "reflection_engine", "_assess_analysis_quality", "_identify_uncertainty_factors",
    "_generate_strategy_adjustments", "_perform_cyclical_reasoning",
    # Sync wrappers
    "summarize_host_state", "suggest_rules", "tool_coordinator_sync",
    "risk_analyzer_sync", "compliance_checker_sync", "metrics_collector_sync",
    "baseline_tools_sync",
]
