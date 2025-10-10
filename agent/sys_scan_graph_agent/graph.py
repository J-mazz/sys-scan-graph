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
#    graph.py

# ==============================================================================
from __future__ import annotations
"""Graph state schema (INT-FUT-GRAPH-STATE)

Central TypedDict describing the evolving state passed between LangGraph nodes
for the LLM-driven analysis agent. This is a lightweight, JSON-friendly
structure distinct from the richer Pydantic models in models.py to allow
incremental population and external serialization without validation overhead.
"""
from typing import TypedDict, List, Dict, Any, Optional, Callable
import os
import logging


class GraphState(TypedDict, total=False):
    raw_findings: List[Dict[str, Any]]            # Raw scanner findings (pre-enrichment)
    enriched_findings: List[Dict[str, Any]]       # Findings after augmentation / risk recompute
    correlated_findings: List[Dict[str, Any]]     # Findings annotated with correlation references
    suggested_rules: List[Dict[str, Any]]         # Candidate correlation / refinement suggestions
    summary: Dict[str, Any]                       # LLM or heuristic summary artifacts
    warnings: List[Any]                           # Structured warning / error entries
    correlations: List[Dict[str, Any]]            # Correlation objects (optional)
    messages: List[Any]                           # LangChain message list for tool execution
    baseline_results: Dict[str, Any]              # Mapping finding_id -> baseline tool result
    baseline_cycle_done: bool                     # Guard to prevent infinite loop
    iteration_count: int                          # Number of summarize iterations executed
    metrics: Dict[str, Any]                       # Metrics for node durations / counters
    cache_keys: List[str]                         # Cache keys used during processing
    enrich_cache: Dict[str, List[Dict[str, Any]]]  # Mapping cache_key -> enriched findings list
    streaming_enabled: bool                        # Flag to enable streaming summarization
    human_feedback_pending: bool                   # Indicates waiting for human input / approval
    pending_tool_calls: List[Dict[str, Any]]       # Planned tool calls (pre ToolNode execution)
    risk_assessment: Dict[str, Any]                # Aggregated risk metrics / qualitative judgment
    compliance_check: Dict[str, Any]               # Compliance standards evaluation results
    errors: List[Dict[str, Any]]                   # Collected error records (optional, separate from warnings)
    degraded_mode: bool                            # Indicates system is in degraded / fallback mode
    human_feedback_processed: bool                 # Human feedback step completed
    final_metrics: Dict[str, Any]                  # Aggregated final metrics snapshot
    cache: Dict[str, Any]                          # General-purpose cache store (centralized)
    llm_provider_mode: str                         # Active LLM provider mode (normal|fallback|null)
    # Performance optimization fields
    current_stage: str                             # Current processing stage for observability
    start_time: str                                # Processing start timestamp
    cache_hits: List[str]                          # Cache hit tracking
    summarize_progress: float                      # Summarization progress (0.0-1.0)
    host_id: str                                   # Host identifier for baseline queries
    # Memory management fields
    memory: Dict[str, Any]                         # Memory store for cross-iteration learning
    reflection: Dict[str, Any]                     # Reflection and cyclical reasoning results

# Runtime graph assembly (enhanced workflow builder)
try:  # Optional dependency guard
    from langgraph.graph import StateGraph, END, START  # type: ignore
    from langgraph.prebuilt import ToolNode  # type: ignore

    # Import scaffold nodes (required for current workflow)
    from .graph import (
        enrich_findings,
        enhanced_summarize_host_state,
        enhanced_suggest_rules,
        tool_coordinator,
        plan_baseline_queries,
        integrate_baseline_results,
        risk_analyzer,
        compliance_checker,
        metrics_collector,
    )  # type: ignore

    from .tools import query_baseline
except Exception:  # pragma: no cover - graph optional
    StateGraph = None  # type: ignore
    END = None  # type: ignore
    START = None  # type: ignore
    ToolNode = None  # type: ignore
    enrich_findings = None  # type: ignore
    enhanced_summarize_host_state = None  # type: ignore
    enhanced_suggest_rules = None  # type: ignore
    tool_coordinator = None  # type: ignore
    plan_baseline_queries = None  # type: ignore
    integrate_baseline_results = None  # type: ignore
    risk_analyzer = None  # type: ignore
    compliance_checker = None  # type: ignore
    metrics_collector = None  # type: ignore
    query_baseline = None  # type: ignore


# Memory Management Node
def memory_manager(state: GraphState) -> GraphState:
    """Manage conversation memory and context across graph iterations.

    Maintains:
    - Previous analysis results
    - Learning from past iterations
    - Context accumulation for better reasoning
    - Memory cleanup to prevent unbounded growth
    """
    # Initialize memory if not present or None
    if 'memory' not in state or state['memory'] is None:
        state['memory'] = {
            'iteration_history': [],
            'learned_patterns': [],
            'context_accumulation': {},
            'reflection_insights': []
        }

    memory = state['memory']
    current_iteration = state.get('iteration_count', 0)

    # Store current state snapshot in memory
    iteration_snapshot = {
        'iteration': current_iteration,
        'timestamp': state.get('start_time', 'unknown'),
        'findings_count': len(state.get('enriched_findings', [])),
        'summary': state.get('summary', ''),
        'risk_level': (state.get('risk_assessment') or {}).get('risk_level', 'unknown'),
        'tool_calls_made': len((state.get('baseline_results') or {}))
    }

    memory['iteration_history'].append(iteration_snapshot)

    # Limit memory size to prevent unbounded growth
    max_memory_items = 10
    if len(memory['iteration_history']) > max_memory_items:
        memory['iteration_history'] = memory['iteration_history'][-max_memory_items:]

    # Extract patterns from history
    if len(memory['iteration_history']) >= 3:
        _extract_patterns_from_history(memory)

    # Update context accumulation
    _accumulate_context(state, memory)

    state['memory'] = memory
    return state


def _extract_patterns_from_history(memory):
    """Extract learning patterns from iteration history."""
    history = memory['iteration_history']

    # Pattern: Risk level trends
    risk_trends = [h.get('risk_level', 'unknown') for h in history[-5:]]
    if risk_trends.count('critical') >= 2:
        memory['learned_patterns'].append({
            'type': 'risk_escalation',
            'pattern': 'Multiple critical risk iterations detected',
            'recommendation': 'Escalate to human review'
        })

    # Pattern: Tool call effectiveness
    tool_effectiveness = sum(h.get('tool_calls_made', 0) for h in history[-3:])
    if tool_effectiveness > 20:
        memory['learned_patterns'].append({
            'type': 'tool_overuse',
            'pattern': 'High tool call volume detected',
            'recommendation': 'Optimize tool usage patterns'
        })


def _accumulate_context(state, memory):
    """Accumulate context across iterations for better reasoning."""
    context = memory['context_accumulation']

    # Accumulate risk insights
    risk_assessment = state.get('risk_assessment')
    if risk_assessment and isinstance(risk_assessment, dict):
        risk_level = risk_assessment.get('risk_level', 'unknown')
        context['risk_progression'] = context.get('risk_progression', [])
        context['risk_progression'].append(risk_level)

        # Keep only recent risk progression
        if len(context['risk_progression']) > 5:
            context['risk_progression'] = context['risk_progression'][-5:]

    # Accumulate finding categories seen
    if 'enriched_findings' in state:
        categories = set()
        for finding in state['enriched_findings']:
            title = finding.get('title', '').lower()
            if 'suid' in title:
                categories.add('privilege_escalation')
            elif 'network' in title:
                categories.add('network_security')
            elif 'file' in title or 'permission' in title:
                categories.add('filesystem_security')
            elif 'process' in title:
                categories.add('process_security')

        context['observed_categories'] = list(categories)


# Reflection and Cyclical Reasoning Node
def reflection_engine(state: GraphState) -> GraphState:
    """Perform reflection and cyclical reasoning on analysis results.

    Analyzes:
    - Previous iteration outcomes
    - Pattern recognition across cycles
    - Strategy adjustment based on learning
    - Confidence assessment and uncertainty handling
    """
    memory = state.get('memory', {})
    iteration_count = state.get('iteration_count') or 0

    # Initialize reflection if not present or None
    if 'reflection' not in state or state['reflection'] is None:
        state['reflection'] = {
            'confidence_score': 0.5,
            'reasoning_quality': 'initializing',
            'strategy_adjustments': [],
            'uncertainty_factors': []
        }

    reflection = state['reflection']

    # Analyze current analysis quality
    analysis_quality = _assess_analysis_quality(state)
    reflection['reasoning_quality'] = analysis_quality['quality']
    reflection['confidence_score'] = analysis_quality['confidence']

    # Identify uncertainty factors
    uncertainty_factors = _identify_uncertainty_factors(state, memory)
    reflection['uncertainty_factors'] = uncertainty_factors

    # Generate strategy adjustments based on reflection
    if iteration_count > 0:
        adjustments = _generate_strategy_adjustments(state, memory, reflection)
        reflection['strategy_adjustments'] = adjustments

    # Update cyclical reasoning insights
    if iteration_count >= 2:
        cyclical_insights = _perform_cyclical_reasoning(state, memory)
        memory['reflection_insights'] = cyclical_insights

    state['reflection'] = reflection
    state['memory'] = memory

    return state


def _assess_analysis_quality(state):
    """Assess the quality of the current analysis."""
    quality_score = 0
    confidence_factors = []

    # Check for comprehensive findings
    findings_count = len(state.get('enriched_findings', []))
    if findings_count > 0:
        quality_score += 0.3
        confidence_factors.append('findings_present')
    else:
        confidence_factors.append('no_findings')

    # Check for correlations
    correlations = state.get('correlations', []) or []
    correlations_count = len(correlations)
    if correlations_count > 0:
        quality_score += 0.2
        confidence_factors.append('correlations_found')

    # Check for baseline coverage
    baseline_results = state.get('baseline_results') or {}
    baseline_coverage = len(baseline_results) / max(findings_count, 1)
    if baseline_coverage > 0.5:
        quality_score += 0.2
        confidence_factors.append('good_baseline_coverage')
    elif baseline_coverage > 0.2:
        quality_score += 0.1
        confidence_factors.append('moderate_baseline_coverage')

    # Check for risk assessment
    if 'risk_assessment' in state:
        quality_score += 0.2
        confidence_factors.append('risk_assessed')

    # Check for compliance check
    if 'compliance_check' in state:
        quality_score += 0.1
        confidence_factors.append('compliance_checked')

    # Determine quality level
    if quality_score >= 0.8:
        quality = 'high'
    elif quality_score >= 0.6:
        quality = 'good'
    elif quality_score >= 0.4:
        quality = 'moderate'
    else:
        quality = 'low'

    return {
        'quality': quality,
        'confidence': min(quality_score + 0.2, 1.0),  # Add base confidence
        'factors': confidence_factors
    }


def _identify_uncertainty_factors(state, memory):
    """Identify factors that contribute to analysis uncertainty."""
    factors = []

    # Check for incomplete baseline data
    findings_count = len(state.get('enriched_findings', []))
    baseline_results = state.get('baseline_results') or {}
    baseline_count = len(baseline_results)
    if baseline_count < findings_count * 0.3:
        factors.append('incomplete_baseline_data')

    # Check for iteration instability
    history = memory.get('iteration_history', [])
    if len(history) >= 3:
        recent_qualities = [h.get('reasoning_quality', 'unknown') for h in history[-3:]]
        if recent_qualities.count('low') >= 2:
            factors.append('analysis_instability')

    # Check for high uncertainty in risk assessment
    risk_assessment = state.get('risk_assessment')
    if risk_assessment and isinstance(risk_assessment, dict) and risk_assessment.get('risk_level') == 'unknown':
        factors.append('unclear_risk_assessment')

    # Check for missing correlations despite findings
    findings_count = len(state.get('enriched_findings', []))
    correlations = state.get('correlations', []) or []
    correlations_count = len(correlations)
    if findings_count > 5 and correlations_count == 0:
        factors.append('missing_correlations')

    return factors


def _generate_strategy_adjustments(state, memory, reflection):
    """Generate strategy adjustments based on reflection insights."""
    adjustments = []

    # Adjust based on confidence level
    confidence = reflection.get('confidence_score', 0.5)
    if confidence < 0.3:
        adjustments.append({
            'type': 'increase_tool_usage',
            'reason': 'Low confidence in analysis',
            'action': 'Increase baseline queries and external data gathering'
        })

    # Adjust based on uncertainty factors
    uncertainty_factors = reflection.get('uncertainty_factors', [])
    if 'incomplete_baseline_data' in uncertainty_factors:
        adjustments.append({
            'type': 'prioritize_baseline',
            'reason': 'Missing baseline information',
            'action': 'Focus next iteration on baseline data collection'
        })

    if 'analysis_instability' in uncertainty_factors:
        adjustments.append({
            'type': 'stabilize_analysis',
            'reason': 'Unstable analysis results across iterations',
            'action': 'Apply more conservative thresholds and validation'
        })

    # Adjust based on pattern learning
    learned_patterns = memory.get('learned_patterns', [])
    for pattern in learned_patterns:
        if pattern['type'] == 'risk_escalation':
            adjustments.append({
                'type': 'escalate_review',
                'reason': pattern['pattern'],
                'action': pattern['recommendation']
            })

    return adjustments


def _perform_cyclical_reasoning(state, memory):
    """Perform cyclical reasoning across multiple iterations."""
    insights = []

    history = memory.get('iteration_history', [])
    if len(history) < 3:
        return insights

    # Analyze convergence patterns
    recent_iterations = history[-3:]
    risk_levels = [h.get('risk_level', 'unknown') for h in recent_iterations]

    # Check for convergence
    if len(set(risk_levels)) == 1 and risk_levels[0] != 'unknown':
        insights.append({
            'type': 'convergence_detected',
            'insight': f'Analysis converged to {risk_levels[0]} risk level',
            'confidence': 0.8
        })

    # Check for oscillation
    elif len(set(risk_levels)) == len(risk_levels) and len(risk_levels) > 1:
        insights.append({
            'type': 'oscillation_detected',
            'insight': 'Analysis oscillating between risk levels',
            'confidence': 0.7,
            'recommendation': 'Stabilize analysis parameters'
        })

    # Analyze tool effectiveness trends
    tool_calls = [h.get('tool_calls_made', 0) for h in recent_iterations]
    if tool_calls and tool_calls[-1] > sum(tool_calls[:-1]) / max(len(tool_calls[:-1]), 1) * 2:
        insights.append({
            'type': 'tool_usage_spike',
            'insight': 'Significant increase in tool usage',
            'confidence': 0.6,
            'recommendation': 'Review tool call efficiency'
        })

    return insights

# Sync wrapper functions for async nodes
def summarize_host_state(state: GraphState) -> GraphState:
    """Sync wrapper for enhanced_summarize_host_state."""
    if enhanced_summarize_host_state is None:
        return state
    import asyncio
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(enhanced_summarize_host_state(state))  # type: ignore
        loop.close()
        return result  # type: ignore
    except Exception:
        # Fallback: just return state unchanged
        return state

def suggest_rules(state: GraphState) -> GraphState:
    """Sync wrapper for enhanced_suggest_rules."""
    if enhanced_suggest_rules is None:
        return state
    import asyncio
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(enhanced_suggest_rules(state))  # type: ignore
        loop.close()
        return result  # type: ignore
    except Exception:
        # Fallback: just return state unchanged
        return state

def tool_coordinator_sync(state: GraphState) -> GraphState:
    """Sync wrapper for tool_coordinator."""
    if tool_coordinator is None:
        return state
    import asyncio
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(tool_coordinator(state))  # type: ignore
        loop.close()
        return result  # type: ignore
    except Exception:
        # Fallback: just return state unchanged
        return state

def risk_analyzer_sync(state: GraphState) -> GraphState:
    """Sync wrapper for risk_analyzer."""
    if risk_analyzer is None:
        return state
    import asyncio
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(risk_analyzer(state))  # type: ignore
        loop.close()
        return result  # type: ignore
    except Exception:
        # Fallback: just return state unchanged
        return state

def compliance_checker_sync(state: GraphState) -> GraphState:
    """Sync wrapper for compliance_checker."""
    if compliance_checker is None:
        return state
    import asyncio
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(compliance_checker(state))  # type: ignore
        loop.close()
        return result  # type: ignore
    except Exception:
        # Fallback: just return state unchanged
        return state

def metrics_collector_sync(state: GraphState) -> GraphState:
    """Sync wrapper for metrics_collector."""
    if metrics_collector is None:
        return state
    import asyncio
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(metrics_collector(state))  # type: ignore
        loop.close()
        return result  # type: ignore
    except Exception:
        # Fallback: just return state unchanged
        return state

def baseline_tools_sync(state: GraphState) -> GraphState:
    """Sync wrapper for ToolNode execution that updates state with tool results."""
    if ToolNode is None or query_baseline is None:
        return state
    
    # Extract messages from state
    messages = state.get('messages', [])
    if not messages:
        return state
    
    # Get the last message (should be AIMessage with tool_calls)
    last_message = messages[-1]
    if not hasattr(last_message, 'tool_calls') or not last_message.tool_calls:
        return state
    
    # Execute the tools
    tool_results = []
    for tool_call in last_message.tool_calls:
        try:
            # Call the tool function directly
            args = tool_call.get('args', {})
            result = query_baseline(**args)
            
            # Create a ToolMessage
            tool_message = {
                'type': 'tool',
                'content': result,
                'tool_call_id': tool_call.get('id'),
                'name': tool_call.get('name')
            }
            tool_results.append(tool_message)
        except Exception as e:
            # Create error tool message
            tool_message = {
                'type': 'tool',
                'content': {'error': str(e), 'status': 'error'},
                'tool_call_id': tool_call.get('id'),
                'name': tool_call.get('name')
            }
            tool_results.append(tool_message)
    
    # Add tool results to messages
    state['messages'] = messages + tool_results
    return state

def build_workflow(enhanced: Optional[bool] = None):  # type: ignore
    """Build and compile a robust StateGraph workflow with memory management, tool calling, and reflection.

    Features:
    - Memory management for cross-iteration learning
    - Tool calling integration for baseline queries
    - Reflection engine for cyclical reasoning
    - Conditional routing based on analysis quality
    - Risk and compliance analysis

    Returns:
        (workflow, app) tuple – uncompiled workflow object and compiled app.
    """
    if StateGraph is None:
        return None, None

    # Check required components - include tool calling for enhanced mode
    required_nodes = [
        enrich_findings, summarize_host_state, suggest_rules,
        tool_coordinator_sync, plan_baseline_queries, baseline_tools_sync,
        integrate_baseline_results,
        risk_analyzer_sync, compliance_checker_sync, metrics_collector_sync
    ]

    if any(node is None for node in required_nodes):
        return None, None

    # Create workflow
    wf = StateGraph(GraphState)

    # Core analysis nodes
    if enrich_findings is not None:
        wf.add_node("enrich", enrich_findings)

    # Memory and reflection nodes (sync)
    wf.add_node("memory_manager", memory_manager)
    wf.add_node("reflection_engine", reflection_engine)

    # Summarization node
    if summarize_host_state is not None:
        wf.add_node("summarize", summarize_host_state)

    # Rule suggestion node
    if suggest_rules is not None:
        wf.add_node("suggest_rules", suggest_rules)

    # Tool calling nodes - properly integrated for enhanced workflow
    if tool_coordinator_sync is not None:
        wf.add_node("tool_coordinator", tool_coordinator_sync)
    if plan_baseline_queries is not None:
        wf.add_node("plan_baseline", plan_baseline_queries)
    if query_baseline is not None:
        wf.add_node("baseline_tools", baseline_tools_sync)
    if integrate_baseline_results is not None:
        wf.add_node("integrate_baseline", integrate_baseline_results)

    # Analysis nodes
    if risk_analyzer_sync is not None:
        wf.add_node("risk_analysis", risk_analyzer_sync)
    if compliance_checker_sync is not None:
        wf.add_node("compliance_checker_node", compliance_checker_sync)
    if metrics_collector_sync is not None:
        wf.add_node("metrics_collection", metrics_collector_sync)

    # Set entry point
    if enrich_findings is not None:
        wf.set_entry_point("enrich")
    else:
        # Fallback to memory manager if core nodes unavailable
        wf.set_entry_point("memory_manager")

    # Define the workflow - simplified for testing
    if enrich_findings is not None:
        wf.add_edge("enrich", "memory_manager")
    wf.add_edge("memory_manager", "reflection_engine")

    # Add summarization if available
    if summarize_host_state is not None:
        wf.add_edge("reflection_engine", "summarize")

    # Add rule suggestions if available
    if suggest_rules is not None:
        if summarize_host_state is not None:
            wf.add_edge("summarize", "suggest_rules")
        else:
            wf.add_edge("reflection_engine", "suggest_rules")

    # Add tool calling workflow
    if tool_coordinator_sync is not None and suggest_rules is not None:
        wf.add_edge("suggest_rules", "tool_coordinator")
        if plan_baseline_queries is not None:
            wf.add_edge("tool_coordinator", "plan_baseline")
            if query_baseline is not None:
                wf.add_edge("plan_baseline", "baseline_tools")
                if integrate_baseline_results is not None:
                    wf.add_edge("baseline_tools", "integrate_baseline")
                    wf.add_edge("integrate_baseline", "risk_analysis")
                else:
                    wf.add_edge("baseline_tools", "risk_analysis")
            else:
                wf.add_edge("plan_baseline", "risk_analysis")
        else:
            wf.add_edge("tool_coordinator", "risk_analysis")
    elif suggest_rules is not None:
        wf.add_edge("suggest_rules", "risk_analysis")

    # Add analysis nodes
    if risk_analyzer_sync is not None:
        # Risk analysis is already connected above
        pass

    if compliance_checker_sync is not None and risk_analyzer_sync is not None:
        wf.add_edge("risk_analysis", "compliance_checker_node")

    if metrics_collector_sync is not None:
        if compliance_checker_sync is not None:
            wf.add_edge("compliance_checker_node", "metrics_collection")
        elif risk_analyzer_sync is not None:
            wf.add_edge("risk_analysis", "metrics_collection")
        else:
            wf.add_edge("reflection_engine", "metrics_collection")

    # End the workflow
    if metrics_collector_sync is not None and END is not None:
        wf.add_edge("metrics_collection", END)
    elif compliance_checker_sync is not None and END is not None:
        wf.add_edge("compliance_checker_node", END)
    elif risk_analyzer_sync is not None and END is not None:
        wf.add_edge("risk_analysis", END)
    elif suggest_rules is not None and END is not None:
        wf.add_edge("suggest_rules", END)
    elif summarize_host_state is not None and END is not None:
        wf.add_edge("summarize", END)
    elif END is not None:
        wf.add_edge("reflection_engine", END)

    try:
        compiled = wf.compile()
        return wf, compiled
    except Exception:
        return wf, None
# Build default workflow at import using env toggle
workflow, app = build_workflow()

# Alias for backward compatibility
BaselineQueryGraph = app

__all__ = ["GraphState", "workflow", "app", "build_workflow", "BaselineQueryGraph"]