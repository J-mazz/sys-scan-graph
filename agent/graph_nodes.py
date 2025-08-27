from __future__ import annotations
"""Graph node functions mapping high-level analysis steps onto GraphState.

These nodes operate on the lightweight dict-based GraphState (see graph.py)
while internally leveraging existing Pydantic model pipeline components.

They are intentionally defensive: if any underlying module raises, the node
captures the error as a warning entry and proceeds without aborting the graph.
"""
from typing import Any, List, Dict
import tempfile, json

from .graph import GraphState
from .data_governance import get_data_governor
from .models import Finding, ScannerResult, Report, Meta, Summary, SummaryExtension, AgentState
from .knowledge import apply_external_knowledge
from .pipeline import augment as _augment
from .reduction import reduce_all
from .llm_provider import get_llm_provider
from .rules import Correlator, DEFAULT_RULES
from .rule_gap_miner import mine_gap_candidates
try:  # Optional: message classes for tool planning/integration
    from langchain_core.messages import AIMessage, ToolMessage  # type: ignore
except Exception:  # pragma: no cover
    AIMessage = ToolMessage = None  # type: ignore


def _append_warning(state: GraphState, module: str, stage: str, error: str, hint: str | None = None):
    wl = state.setdefault('warnings', [])
    wl.append({
        'module': module,
        'stage': stage,
        'error': error,
        'hint': hint
    })


def _findings_from_graph(state: GraphState) -> List[Finding]:
    out: List[Finding] = []
    for f in state.get('raw_findings', []) or []:
        try:
            # Provide minimal required fields; defaults for missing
            out.append(Finding(
                id=f.get('id','unknown'),
                title=f.get('title','(no title)'),
                severity=f.get('severity','info'),
                risk_score=int(f.get('risk_score', f.get('risk_total', 0)) or 0),
                metadata=f.get('metadata', {})
            ))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


def enrich_findings(state: GraphState) -> GraphState:
    """Knowledge + augmentation stage.

    Converts raw_findings into enriched_findings using existing augment + knowledge code.
    """
    try:
        findings = _findings_from_graph(state)
        sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = Report(meta=Meta(), summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
                        results=[sr], collection_warnings=[], scanner_errors=[], summary_extension=SummaryExtension(total_risk_score=0))
        astate = AgentState(report=report)
        astate = _augment(astate)
        astate = apply_external_knowledge(astate)
        # Export back to dict form
        enriched = []
        if astate.report and astate.report.results:
            for r in astate.report.results:
                for f in r.findings:
                    enriched.append(f.model_dump())
        state['enriched_findings'] = enriched
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'enrich', str(e))
        state.setdefault('enriched_findings', state.get('raw_findings', []))
    return state


def correlate_findings(state: GraphState) -> GraphState:
    try:
        findings: List[Finding] = []
        for f in state.get('enriched_findings', []) or []:
            try:
                findings.append(Finding(**{k: v for k, v in f.items() if k in Finding.model_fields}))
            except Exception:
                continue
        sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = Report(meta=Meta(), summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
                        results=[sr], collection_warnings=[], scanner_errors=[], summary_extension=SummaryExtension(total_risk_score=0))
        astate = AgentState(report=report)
        correlator = Correlator(DEFAULT_RULES)
        astate.correlations = correlator.apply(findings)
        for c in astate.correlations:
            for f in findings:
                if f.id in c.related_finding_ids and c.id not in f.correlation_refs:
                    f.correlation_refs.append(c.id)
        state['correlated_findings'] = [f.model_dump() for f in findings]
        state['correlations'] = [c.model_dump() for c in astate.correlations]
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'correlate', str(e))
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])
    return state


def summarize_host_state(state: GraphState) -> GraphState:
    try:
        # Iteration guard: default max iterations 3
        max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
        iters = int(state.get('iteration_count', 0))
        if iters >= max_iter:
            state['warnings'] = state.get('warnings', []) + [{'module': 'graph', 'stage': 'summarize', 'error': 'iteration_limit_reached'}]
            return state
        provider = get_llm_provider()
        findings_dicts = state.get('correlated_findings') or state.get('enriched_findings') or []
        findings: List[Finding] = []
        for f in findings_dicts:
            try:
                findings.append(Finding(**{k: v for k, v in f.items() if k in Finding.model_fields}))
            except Exception:
                continue
        reductions = reduce_all(findings)
        from .models import Correlation as _C
        corr_objs = []
        for c in state.get('correlations', []) or []:
            try:
                corr_objs.append(_C(**c))
            except Exception:
                continue
    baseline_context = state.get('baseline_results') or {}
    summaries = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)
    state['summary'] = summaries.model_dump()
    state['iteration_count'] = iters + 1
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'summarize', str(e))
    return state


def suggest_rules(state: GraphState) -> GraphState:
    """Mine candidate rules from enriched findings.

    Uses existing gap miner; writes a temp file to leverage current API.
    """
    try:
        findings = state.get('enriched_findings') or []
        with tempfile.TemporaryDirectory() as td:
            p = tempfile.NamedTemporaryFile('w', delete=False, suffix='.json', dir=td)
            try:
                json.dump({'enriched_findings': findings}, p)
                p.flush(); p.close()
                from pathlib import Path
                res = mine_gap_candidates([Path(p.name)], risk_threshold=10, min_support=2)
            finally:
                try:
                    p.close()
                except Exception:
                    pass
        state['suggested_rules'] = res.get('suggestions', [])
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'rule_mine', str(e))
    return state


def should_suggest_rules(state: GraphState) -> str:  # Router for conditional edge
    """Decide whether to invoke rule suggestion based on enriched findings.

    Heuristic: If at least one enriched finding has severity == 'high' (case-insensitive),
    proceed to the expensive suggestion phase; otherwise end the graph.
    """
    try:
        enriched = state.get('enriched_findings') or []
        high_severity_count = 0
        for f in enriched:
            sev = str(f.get('severity', '')).lower()
            if sev == 'high':
                high_severity_count += 1
                if high_severity_count:
                    break
        if high_severity_count > 0:
            return "suggest_rules"
        # Import END lazily to avoid hard dependency at import time
        try:  # pragma: no cover - trivial import guard
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return "__end__"  # Fallback symbolic end if library missing
    except Exception:  # pragma: no cover - defensive
        try:
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return "__end__"


def choose_post_summarize(state: GraphState) -> str:  # Router after summarize
    """Decide next step after summarize.

    Order of precedence:
    1. If baseline cycle not yet done and any enriched finding missing baseline_status -> plan_baseline
    2. Else defer to should_suggest_rules routing (suggest_rules or END)
    """
    if not state.get('baseline_cycle_done'):
        enriched = state.get('enriched_findings') or []
        for f in enriched:
            if 'baseline_status' not in f:  # simple heuristic trigger
                return 'plan_baseline'
    # Delegate to existing router
    return should_suggest_rules(state)


def plan_baseline_queries(state: GraphState) -> GraphState:
    """Construct tool call messages for baseline queries if needed.

    Populates state['messages'] with an AIMessage containing tool_calls for each
    finding lacking baseline_status. ToolNode will execute these in batch.
    """
    if AIMessage is None:  # Dependency missing; skip planning
        return state
    enriched = state.get('enriched_findings') or []
    pending = [f for f in enriched if 'baseline_status' not in f]
    if not pending:
        return state
    tool_calls = []
    host_id = __import__('os').environ.get('AGENT_GRAPH_HOST_ID','graph_host')
    for f in pending:
        fid = f.get('id') or 'unknown'
        title = f.get('title') or ''
        severity = f.get('severity') or ''
        scanner = f.get('scanner') or 'mixed'
        tool_calls.append({
            'name': 'query_baseline',
            'args': {
                'finding_id': fid,
                'title': title,
                'severity': severity,
                'scanner': scanner,
                'host_id': host_id
            }
        })
    msgs = state.get('messages') or []
    msgs.append(AIMessage(content="Baseline context required", tool_calls=tool_calls))  # type: ignore[arg-type]
    state['messages'] = msgs
    return state


def integrate_baseline_results(state: GraphState) -> GraphState:
    """Collect tool execution outputs into baseline_results mapping in state.

    Marks baseline_cycle_done to prevent repeated looping.
    """
    if ToolMessage is None:  # Dependency missing
        state['baseline_cycle_done'] = True
        return state
    msgs = state.get('messages') or []
    results = state.get('baseline_results') or {}
    for m in msgs:
        try:
            if isinstance(m, ToolMessage):
                # ToolMessage variants may expose .tool_call_id / .content; we expect dict content
                data_obj = getattr(m, 'content', None)
                if isinstance(data_obj, dict):
                    fid = data_obj.get('finding_id')
                    if isinstance(fid, str):
                        results[fid] = data_obj  # type: ignore[index]
        except Exception:  # pragma: no cover
            continue
    state['baseline_results'] = results
    state['baseline_cycle_done'] = True
    return state


__all__ = [
    'enrich_findings',
    'correlate_findings',
    'summarize_host_state',
    'suggest_rules',
    'should_suggest_rules',
    'choose_post_summarize',
    'plan_baseline_queries',
    'integrate_baseline_results'
]