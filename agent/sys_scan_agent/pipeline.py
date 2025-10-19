"""
pipeline compatibility module.

This module provides backward compatibility for functions that were previously
in the monolithic pipeline.py file. It imports from the new modular components.
"""

from pathlib import Path
from typing import List
import os
from . import models
from .loader import load_report
from .enricher import augment
from .correlator import correlate as _correlate, sequence_correlation as _sequence_correlation
from .reduction import reduce_all
from .llm import LLMClient
from .utils import _recompute_finding_risk
from .audit import log_stage

# Import model classes
Finding = models.Finding
ScannerResult = models.ScannerResult

# Stub functions for compatibility - these were in the original pipeline but not yet modularized
def baseline_rarity(state, baseline_path=None):
    """Process baseline rarity and detect metric drift."""
    if not state.report:
        return state

    from .baseline import BaselineStore
    from .config import load_config
    import hashlib

    # Get baseline DB path
    if baseline_path is None:
        baseline_path = os.environ.get('AGENT_BASELINE_DB', 'agent_baseline.db')

    baseline_path = Path(baseline_path)
    store = BaselineStore(baseline_path)

    # Extract host_id from report meta
    host_id = state.report.meta.hostname or state.report.meta.host_id or 'unknown_host'

    # Generate scan_id using a counter stored in baseline
    scan_counter_key = f"scan_counter:{host_id}"
    current_counter = store._get_meta(scan_counter_key)
    if current_counter:
        try:
            counter = int(current_counter) + 1
        except ValueError:
            counter = 1
    else:
        counter = 1
    store._set_meta(scan_counter_key, str(counter))
    scan_id = f"scan_{counter}"

    # Record the scan
    store.record_scan(host_id, scan_id)

    # Extract metrics from report summary
    metrics = {}
    if state.report.summary:
        metrics['finding_count_total'] = float(state.report.summary.finding_count_total or 0)
        metrics['finding_count_emitted'] = float(state.report.summary.finding_count_emitted or 0)
        if state.report.summary.severity_counts:
            for sev, count in state.report.summary.severity_counts.items():
                metrics[f'severity_{sev}'] = float(count)

    # Record metrics and check for drift
    if metrics:
        drift_results = store.record_metrics(host_id, scan_id, metrics)

        # Check for metric drift using z-score threshold
        config = load_config()
        threshold = config.thresholds.metric_drift_z

        for metric_name, result in drift_results.items():
            z_score = result.get('z')
            if z_score is not None and abs(z_score) > threshold:
                # Create metric drift finding
                drift_finding = Finding(
                    id=f"metric_drift_{metric_name}_{scan_id}",
                    title=f"Metric drift detected in {metric_name}",
                    severity="medium",
                    risk_score=50,
                    description=f"Statistical anomaly detected in {metric_name}: z-score {z_score:.2f} exceeds threshold {threshold}",
                    metadata={
                        "metric": metric_name,
                        "current_value": result['value'],
                        "mean": result.get('mean'),
                        "std": result.get('std'),
                        "z_score": z_score,
                        "history_n": result.get('history_n', 0)
                    },
                    category="metric_drift",
                    tags=["metric_drift"],
                    rationale=[f"Metric drift detected in {metric_name}: z-score {z_score:.2f} exceeds threshold {threshold}"]
                )

                # Add to the first scanner result or create a new one
                if state.report.results:
                    state.report.results[0].findings.append(drift_finding)
                    state.report.results[0].finding_count += 1
                else:
                    # Create a new scanner result for drift findings
                    drift_scanner = ScannerResult(
                        scanner="metric_drift_detector",
                        finding_count=1,
                        findings=[drift_finding]
                    )
                    state.report.results.append(drift_scanner)

                # Update summary counts
                if state.report.summary:
                    state.report.summary.finding_count_total = (state.report.summary.finding_count_total or 0) + 1
                    state.report.summary.finding_count_emitted = (state.report.summary.finding_count_emitted or 0) + 1
                    if state.report.summary.severity_counts:
                        sev = drift_finding.severity
                        state.report.summary.severity_counts[sev] = state.report.summary.severity_counts.get(sev, 0) + 1

    return state

def process_novelty(state, baseline_path=None):
    """Process novelty detection by comparing against baseline."""
    if not state.report or not baseline_path:
        return state

    import json
    from pathlib import Path

    baseline_file = Path(baseline_path)
    known_processes = set()

    # Load existing baseline if it exists
    if baseline_file.exists():
        try:
            with open(baseline_file, 'r') as f:
                baseline_data = json.load(f)
                known_processes = set(baseline_data.get('processes', []))
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    # Collect current processes
    current_processes = set()
    for sr in state.report.results:
        for finding in sr.findings:
            if finding.category == 'process':
                # Extract process name from title or metadata
                process_name = None
                if 'process' in finding.metadata:
                    process_name = finding.metadata['process']
                elif finding.title:
                    # Try to extract process name from title
                    import re
                    match = re.search(r'Process:?\s*([^\s]+)', finding.title, re.IGNORECASE)
                    if match:
                        process_name = match.group(1)
                    else:
                        # Use the first word as process name
                        process_name = finding.title.split()[0]

                if process_name:
                    current_processes.add(process_name)

    # Tag novel processes
    for sr in state.report.results:
        for finding in sr.findings:
            if finding.category == 'process':
                process_name = None
                if 'process' in finding.metadata:
                    process_name = finding.metadata['process']
                elif finding.title:
                    import re
                    match = re.search(r'Process:?\s*([^\s]+)', finding.title, re.IGNORECASE)
                    if match:
                        process_name = match.group(1)
                    else:
                        process_name = finding.title.split()[0]

                if process_name and process_name not in known_processes:
                    if not finding.tags:
                        finding.tags = []
                    finding.tags.append('process_novel')

    # Update baseline with current processes
    baseline_data = {'processes': list(current_processes)}
    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    with open(baseline_file, 'w') as f:
        json.dump(baseline_data, f)

    return state

def reduce(state):
    """Stub function for counterfactual reduction."""
    # TODO: Implement counterfactual reduction logic if needed
    return state

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

    # Extract compliance information from raw report if present
    if state.raw_report and 'compliance_summary' in state.raw_report:
        compliance_summary = state.raw_report['compliance_summary']
        if state.summaries.metrics is None:
            state.summaries.metrics = {}
        state.summaries.metrics['compliance_summary'] = compliance_summary
        
        # Also extract compliance_gaps if present
        if 'compliance_gaps' in state.raw_report:
            compliance_gaps = state.raw_report['compliance_gaps']
            state.summaries.metrics['compliance_gaps'] = compliance_gaps
            state.summaries.metrics['compliance_gap_count'] = len(compliance_gaps)

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
    log_stage('load_report', report_path=str(report_path))
    state = load_report(state, report_path)

    # Augment findings
    log_stage('augment')
    state = augment(state)

    # Apply correlations
    log_stage('correlate')
    correlate(state)
    sequence_correlation(state)

    # Baseline and novelty processing
    log_stage('baseline_rarity')
    baseline_rarity(state)
    process_novelty(state)

    # Apply policy adjustments
    log_stage('apply_policy')
    apply_policy(state)

    # Reduce findings
    log_stage('reduce')
    all_findings = []
    if state.report and state.report.results:
        for sr in state.report.results:
            all_findings.extend(sr.findings)
    reductions_obj = reduce_all(all_findings)
    state.reductions = reductions_obj.model_dump()  # Convert to dict for AgentState

    # Counterfactual reduction
    reduce(state)

    # Actions (placeholder for now)
    log_stage('actions')

    # Summarize
    log_stage('summarize')
    state = summarize(state)

    # Extract enriched findings (flattened from all scanner results)
    enriched_findings = []
    if state.report and state.report.results:
        for sr in state.report.results:
            enriched_findings.extend(sr.findings)

    # Calculate integrity (SHA256 of original report)
    from .integrity import sha256_file
    integrity = {
        'sha256_actual': sha256_file(report_path)
    }

    # Build enriched output
    return EnrichedOutput(
        correlations=state.correlations,
        reductions=state.reductions,
        summaries=state.summaries,
        actions=state.actions,
        enriched_findings=enriched_findings,
        integrity=integrity
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
    """Apply policy adjustments to findings based on approved directories and allowlists."""
    if not state.report or not state.report.results:
        return state
    
    # Get policy configuration from environment
    approved_dirs = os.environ.get('AGENT_APPROVED_DIRS', '').split(':') if os.environ.get('AGENT_APPROVED_DIRS') else []
    allowlist = os.environ.get('AGENT_POLICY_ALLOWLIST', '').split(',') if os.environ.get('AGENT_POLICY_ALLOWLIST') else []
    
    # Clean up empty strings
    approved_dirs = [d for d in approved_dirs if d.strip()]
    allowlist = [a for a in allowlist if a.strip()]
    
    for sr in state.report.results:
        for finding in sr.findings:
            if finding.metadata and 'exe' in finding.metadata:
                exe_path = finding.metadata['exe']
                
                # Check if path is in approved directories
                is_approved = any(exe_path.startswith(approved_dir) for approved_dir in approved_dirs)
                
                # Check if path is in allowlist
                is_allowlisted = exe_path in allowlist
                
                if not is_approved and not is_allowlisted:
                    # Escalate severity to high
                    finding.severity = 'high'
                    
                    # Add policy tag
                    if not finding.tags:
                        finding.tags = []
                    if 'policy:denied_path' not in finding.tags:
                        finding.tags.append('policy:denied_path')
                    
                    # Add rationale
                    rationale = f"policy escalation: executable '{exe_path}' not in approved directories {approved_dirs} and not in allowlist {allowlist}"
                    if finding.rationale:
                        finding.rationale.append(rationale)
                    else:
                        finding.rationale = [rationale]
    
    return state