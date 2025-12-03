"""Reflection and metacognition module for graph nodes.

This module provides reflection and cyclical reasoning capabilities,
enabling the analysis workflow to assess its own quality, identify
uncertainties, and adjust strategies based on learning.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List

from .state import GraphState

logger = logging.getLogger(__name__)


def reflection_engine(state: GraphState) -> GraphState:
    """Perform reflection and cyclical reasoning on analysis results.

    Analyzes:
    - Previous iteration outcomes
    - Pattern recognition across cycles
    - Strategy adjustment based on learning
    - Confidence assessment and uncertainty handling
    
    Args:
        state: Current graph state
        
    Returns:
        Updated state with reflection analysis applied
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


def _assess_analysis_quality(state: GraphState) -> Dict[str, Any]:
    """Assess the quality of the current analysis.
    
    Evaluates multiple factors to determine analysis quality:
    - Presence and count of findings
    - Correlation coverage
    - Baseline data coverage
    - Risk assessment completion
    - Compliance check completion
    
    Args:
        state: Current graph state
        
    Returns:
        Dict with 'quality' level, 'confidence' score, and 'factors' list
    """
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


def _identify_uncertainty_factors(state: GraphState, memory: Dict[str, Any]) -> List[str]:
    """Identify factors that contribute to analysis uncertainty.
    
    Checks for:
    - Incomplete baseline data
    - Analysis instability across iterations
    - Unclear risk assessments
    - Missing correlations despite findings
    
    Args:
        state: Current graph state
        memory: Memory dict with iteration history
        
    Returns:
        List of uncertainty factor identifiers
    """
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


def _generate_strategy_adjustments(
    state: GraphState,
    memory: Dict[str, Any],
    reflection: Dict[str, Any]
) -> List[Dict[str, str]]:
    """Generate strategy adjustments based on reflection insights.
    
    Produces actionable strategy adjustments based on:
    - Current confidence level
    - Identified uncertainty factors
    - Learned patterns from memory
    
    Args:
        state: Current graph state
        memory: Memory dict with learned patterns
        reflection: Current reflection state
        
    Returns:
        List of strategy adjustment dicts with type, reason, and action
    """
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


def _perform_cyclical_reasoning(state: GraphState, memory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Perform cyclical reasoning across multiple iterations.
    
    Analyzes patterns across iterations to detect:
    - Convergence (stable results)
    - Oscillation (unstable results)
    - Tool usage spikes
    
    Args:
        state: Current graph state
        memory: Memory dict with iteration history
        
    Returns:
        List of cyclical reasoning insights
    """
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


__all__ = [
    'reflection_engine',
    '_assess_analysis_quality',
    '_identify_uncertainty_factors',
    '_generate_strategy_adjustments',
    '_perform_cyclical_reasoning',
]
