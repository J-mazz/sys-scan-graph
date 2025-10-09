"""
pipeline compatibility module.

This module provides backward compatibility for functions that were previously
in the monolithic pipeline.py file. It imports from the new modular components.
"""

from pathlib import Path
from typing import List
from . import models
from .loader import load_report
from .enricher import augment
from .correlator import correlate as _correlate, sequence_correlation as _sequence_correlation
from .reduction import reduce_all
from .llm import LLMClient
from .utils import _recompute_finding_risk

# Stub functions for compatibility - these were in the original pipeline but not yet modularized
def baseline_rarity(state):
    """Stub function for baseline rarity processing."""
    # TODO: Implement baseline rarity logic if needed
    pass

def process_novelty(state):
    """Stub function for novelty processing."""
    # TODO: Implement novelty processing logic if needed
    pass

def reduce(state):
    """Stub function for counterfactual reduction."""
    # TODO: Implement counterfactual reduction logic if needed
    pass

AgentState = models.AgentState
EnrichedOutput = models.EnrichedOutput
Reductions = models.Reductions
Summaries = models.Summaries
Correlation = models.Correlation
ActionItem = models.ActionItem


def generate_causal_hypotheses(state, max_hypotheses: int = 3) -> list[dict]:
    """Generate speculative causal hypotheses from correlations & findings.
    Heuristics only (deterministic):
      - sequence_anomaly => privilege escalation chain.
      - module_propagation => lateral movement via module.
      - presence of metric_drift finding + routing correlation => config change root cause.
    Mark all as speculative with low confidence.
    """
    hyps = []
    for c in state.correlations:
        if 'sequence_anomaly' in c.tags:
            hyps.append({
                'id': f"hyp_{len(hyps)+1}",
                'summary': 'Potential privilege escalation chain (new SUID then IP forwarding)',
                'rationale': [c.rationale],
                'confidence': 'low',
                'speculative': True
            })
        if 'module_propagation' in c.tags:
            hyps.append({
                'id': f"hyp_{len(hyps)+1}",
                'summary': 'Possible lateral movement via near-simultaneous kernel module deployment',
                'rationale': [c.rationale or 'simultaneous module emergence across hosts'],
                'confidence': 'low',
                'speculative': True
            })
    
    # Check for drift and routing conditions
    drift_present, routing_corr = _check_drift_and_routing_conditions(state)
    if drift_present and routing_corr:
        hyps.append({
            'id': f"hyp_{len(hyps)+1}",
            'summary': 'Configuration change likely triggered routing and risk metric drift',
            'rationale': ['metric drift finding plus routing-related correlation(s)'],
            'confidence': 'low',
            'speculative': True
        })
    
    # Deduplicate by summary, cap
    return _deduplicate_hypotheses(hyps, max_hypotheses)


def _check_drift_and_routing_conditions(state) -> tuple[bool, bool]:
    """Check for metric drift findings and routing correlations."""
    drift_present = any(f.category == 'metric_drift' for r in state.report.results for f in r.findings) if state.report else False
    routing_corr = any('routing' in (c.tags or []) for c in state.correlations)
    return drift_present, routing_corr


def _deduplicate_hypotheses(hyps: list[dict], max_hypotheses: int) -> list[dict]:
    """Deduplicate hypotheses by summary and cap at max_hypotheses."""
    seen = set()
    out = []
    for h in hyps:
        summary = h['summary']
        if summary not in seen:
            out.append(h)
            seen.add(summary)
        if len(out) >= max_hypotheses:
            break
    return out


def correlate(state):
    """Apply correlation rules to findings."""
    _correlate(state)
    return state


def sequence_correlation(state):
    """Detect suspicious temporal sequences."""
    _sequence_correlation(state)
    return state


def summarize(state):
    """Generate summaries using LLM analysis."""
    if not state.report:
        return state

    # Collect all findings
    all_findings = []
    for sr in state.report.results:
        all_findings.extend(sr.findings)

    # Generate reductions
    reductions_obj = reduce_all(all_findings)
    state.reductions = reductions_obj.model_dump()  # Convert to dict for AgentState

    # Generate correlations if not already done
    if not hasattr(state, 'correlations') or not state.correlations:
        correlate(state)
        sequence_correlation(state)

    # Generate summaries using LLM
    try:
        llm = LLMClient()
        state.summaries = llm.summarize(
            reductions=reductions_obj,
            correlations=state.correlations or [],
            actions=[]  # No actions in basic pipeline
        )
    except Exception:
        # Fallback to basic summary if LLM fails
        state.summaries = Summaries(
            executive_summary=f"Processed {len(all_findings)} findings",
            analyst={"finding_count": len(all_findings)},
            consistency_findings=[],
            triage_summary={"top_findings": [], "correlation_count": len(state.correlations or [])},
            action_narrative="Analysis completed",
            metrics={"findings_count": len(all_findings)}
        )

    # Generate causal hypotheses
    try:
        if state.summaries:
            state.summaries.causal_hypotheses = generate_causal_hypotheses(state)
    except Exception:
        # Skip causal hypotheses if there's an error
        pass

    return state


def run_pipeline(report_path: Path) -> EnrichedOutput:
    """Run the complete pipeline from report loading to summarization."""
    state = AgentState()

    # Load report
    state = load_report(state, report_path)

    # Augment findings
    state = augment(state)

    # Apply correlations
    correlate(state)
    sequence_correlation(state)

    # Baseline and novelty processing
    baseline_rarity(state)
    process_novelty(state)

    # Reduce findings
    all_findings = []
    if state.report and state.report.results:
        for sr in state.report.results:
            all_findings.extend(sr.findings)
    reductions_obj = reduce_all(all_findings)
    state.reductions = reductions_obj.model_dump()  # Convert to dict for AgentState

    # Counterfactual reduction
    reduce(state)

    # Summarize
    state = summarize(state)

    # Build enriched output
    return EnrichedOutput(
        correlations=state.correlations,
        reductions=state.reductions,
        summaries=state.summaries,
        actions=state.actions
    )


# Re-export other functions for compatibility
def build_output(state) -> EnrichedOutput:
    """Build enriched output from state."""
    return EnrichedOutput(
        correlations=state.correlations,
        reductions=state.reductions,
        summaries=state.summaries,
        actions=state.actions
    )


def apply_policy(state: AgentState) -> AgentState:
    """Apply policy adjustments (placeholder for now)."""
    # Policy application logic would go here
    return state