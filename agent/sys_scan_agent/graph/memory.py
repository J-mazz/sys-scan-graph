"""Memory management module for graph nodes.

This module provides long-term memory capabilities for the analysis workflow,
enabling cross-iteration learning, pattern recognition, and context accumulation.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Set

from .state import GraphState

logger = logging.getLogger(__name__)


def memory_manager(state: GraphState) -> GraphState:
    """Manage conversation memory and context across graph iterations.

    Maintains:
    - Previous analysis results
    - Learning from past iterations
    - Context accumulation for better reasoning
    - Memory cleanup to prevent unbounded growth
    
    Args:
        state: Current graph state
        
    Returns:
        Updated state with memory management applied
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


def _extract_patterns_from_history(memory: Dict[str, Any]) -> None:
    """Extract learning patterns from iteration history.
    
    Analyzes iteration history to identify:
    - Risk level trends (e.g., escalation patterns)
    - Tool call effectiveness (e.g., overuse detection)
    
    Args:
        memory: Memory dict to update with learned patterns
    """
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


def _accumulate_context(state: GraphState, memory: Dict[str, Any]) -> None:
    """Accumulate context across iterations for better reasoning.
    
    Builds up contextual knowledge including:
    - Risk progression over time
    - Categories of findings observed
    
    Args:
        state: Current graph state
        memory: Memory dict to update with accumulated context
    """
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
        categories: Set[str] = set()
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


__all__ = [
    'memory_manager',
    '_extract_patterns_from_history',
    '_accumulate_context',
]
