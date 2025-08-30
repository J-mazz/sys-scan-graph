from __future__ import annotations
"""Graph nodes scaffolding module (Step 1: Project Scaffolding & Dependencies)

This module prepares shared imports and forward references for upcoming
graph node implementations without introducing circular import issues.

It intentionally does not yet implement concrete node logic; subsequent
steps will add functions that operate on ``GraphState`` using the imported
helpers.
"""

# Standard library imports
import asyncio
import logging
import time
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

# Forward reference / safe import for GraphState to avoid circular import at module import time.
# If the real GraphState cannot be imported yet (during early bootstrap), we fall back to a
# structural placeholder (dict subtype / alias) sufficient for static typing tools.
try:  # Prefer real definition when available
    if TYPE_CHECKING:
        from .graph import GraphState  # type: ignore  # noqa: F401
    else:  # Runtime attempt (may succeed if import order permits)
        from .graph import GraphState  # type: ignore
except Exception:  # Fallback lightweight alias
    GraphState = Dict[str, Any]  # type: ignore

# Core provider & helper imports (existing project modules)
from .llm_provider import get_llm_provider  # LLM provider abstraction
from .graph_nodes import _findings_from_graph, _append_warning  # Reuse existing parsing & warning helpers
from .pipeline import augment as _augment  # Core augmentation stage
from .knowledge import apply_external_knowledge  # External knowledge enrichment
from .reduction import reduce_all  # Reduction / summarization helpers
from .rule_gap_miner import mine_gap_candidates  # Rule gap mining utility

# Pydantic model imports (data structures used across node logic)
from .models import (
    Finding,
    ScannerResult,
    Report,
    Meta,
    Summary,
    SummaryExtension,
    AgentState,
)

logger = logging.getLogger(__name__)

__all__ = [
    "GraphState",
    "get_llm_provider",
    "_findings_from_graph",
    "_append_warning",
    "_augment",
    "apply_external_knowledge",
    "reduce_all",
    "mine_gap_candidates",
    "enrich_findings",
    "enhanced_enrich_findings",
    "summarize_host_state",
    "enhanced_summarize_host_state",
    "suggest_rules",
    "correlate_findings",
    "get_enhanced_llm_provider",
    "streaming_summarizer",
    "enhanced_suggest_rules",
    "advanced_router",
    "should_suggest_rules",
    "choose_post_summarize",
    "tool_coordinator",
    "plan_baseline_queries",
    "integrate_baseline_results",
    "risk_analyzer",
    "compliance_checker",
    "error_handler",
    "human_feedback_node",
    "cache_manager",
    "metrics_collector",
    # Models
    "Finding",
    "ScannerResult",
    "Report",
    "Meta",
    "Summary",
    "SummaryExtension",
    "AgentState",
]


def enrich_findings(state: "GraphState") -> "GraphState":
    """Basic synchronous enrichment step.

    Steps:
    1. Convert raw findings dicts -> Pydantic `Finding` models via `_findings_from_graph`.
    2. Wrap in `ScannerResult` and `Report` objects (minimal required fields).
    3. Build `AgentState` then run `_augment` and `apply_external_knowledge`.
    4. Export enriched findings back to plain dicts under `state['enriched_findings']`.

    On any exception, a warning is appended and the function falls back to
    leaving (or copying) `raw_findings` into `enriched_findings` so downstream
    nodes can continue operating deterministically.
    """
    try:
        findings = _findings_from_graph(state)
        sr = ScannerResult(
            scanner="mixed",
            finding_count=len(findings),
            findings=findings,
        )
        report = Report(
            meta=Meta(),
            summary=Summary(
                finding_count_total=len(findings),
                finding_count_emitted=len(findings),
            ),
            results=[sr],
            collection_warnings=[],
            scanner_errors=[],
            summary_extension=SummaryExtension(total_risk_score=0),
        )
        astate = AgentState(report=report)
        astate = _augment(astate)
        astate = apply_external_knowledge(astate)

        enriched: List[Dict[str, Any]] = []
        if astate.report and astate.report.results:
            for result in astate.report.results:
                for finding in result.findings:
                    try:
                        enriched.append(finding.model_dump())
                    except Exception:  # pragma: no cover
                        continue
        state["enriched_findings"] = enriched
    except Exception as e:  # pragma: no cover
        logger.exception("enrich_findings failed: %s", e)
        _append_warning(state, "graph", "enrich", str(e))
        if "enriched_findings" not in state:
            # Fallback: propagate raw findings so later stages have data.
            state["enriched_findings"] = state.get("raw_findings", [])
    return state


def summarize_host_state(state: "GraphState") -> "GraphState":
    """Basic host state summarization node.

    Applies an iteration cap (default 3 via env AGENT_MAX_SUMMARY_ITERS) to
    avoid unbounded summarize loops. Uses the default LLM provider (which
    may be a deterministic null provider) to produce a summary object.
    """
    # Iteration guard
    try:
        max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
    except ValueError:
        max_iter = 3
    iters = int(state.get('iteration_count', 0) or 0)
    if iters >= max_iter:
        _append_warning(state, 'graph', 'summarize', 'iteration_limit_reached')
        return state
    try:
        provider = get_llm_provider()
        # Prefer correlated findings; fallback to enriched
        findings_src = state.get('correlated_findings') or state.get('enriched_findings') or []
        findings_models: List[Finding] = []
        for finding_dict in findings_src:
            try:
                findings_models.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
            except Exception:  # pragma: no cover
                continue
        reductions = reduce_all(findings_models)
        # Rehydrate correlations (if present)
        from .models import Correlation as _C
        corr_objs = []
        for c in state.get('correlations', []) or []:
            try:
                corr_objs.append(_C(**c))
            except Exception:  # pragma: no cover
                continue
        baseline_context = state.get('baseline_results') or {}
        summaries = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)
        state['summary'] = summaries.model_dump()
        state['iteration_count'] = iters + 1
    except Exception as e:  # pragma: no cover
        logger.exception("summarize_host_state failed: %s", e)
        _append_warning(state, 'graph', 'summarize', str(e))
    return state


def suggest_rules(state: "GraphState") -> "GraphState":
    """Mine candidate rules from enriched findings.

    Writes enriched findings to a temporary JSON file to satisfy the existing
    mine_gap_candidates interface, then extracts suggestions.
    """
    try:
        findings = state.get('enriched_findings') or []
        import tempfile, json as _json
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
            _json.dump({'enriched_findings': findings}, tf)
            tf.flush()
            from pathlib import Path
            result = mine_gap_candidates([Path(tf.name)], risk_threshold=10, min_support=2)
        state['suggested_rules'] = result.get('suggestions', [])
    except Exception as e:  # pragma: no cover
        logger.exception("suggest_rules failed: %s", e)
        _append_warning(state, 'graph', 'rule_mine', str(e))
    return state


def correlate_findings(state: "GraphState") -> "GraphState":
    """Apply correlation rules to enriched findings and attach correlation references.

    Reuses existing rule correlator (DEFAULT_RULES). Correlation objects and updated
    findings are stored back in the GraphState under 'correlations' and 'correlated_findings'.
    """
    try:
        from .rules import Correlator, DEFAULT_RULES  # local import to avoid circulars on module load
        findings_models: List[Finding] = []
        for finding in state.get('enriched_findings', []) or []:
            try:
                findings_models.append(Finding(**{k: v for k, v in finding.items() if k in Finding.model_fields}))
            except Exception:  # pragma: no cover
                continue
        sr = ScannerResult(
            scanner="mixed",
            finding_count=len(findings_models),
            findings=findings_models,
        )
        report = Report(
            meta=Meta(),
            summary=Summary(
                finding_count_total=len(findings_models),
                finding_count_emitted=len(findings_models),
            ),
            results=[sr],
            collection_warnings=[],
            scanner_errors=[],
            summary_extension=SummaryExtension(total_risk_score=0),
        )
        astate = AgentState(report=report)
        correlator = Correlator(DEFAULT_RULES)
        correlations = correlator.apply(findings_models)
                # Attach correlation refs to findings
        corr_map = {c.id: c for c in correlations}
        for c in correlations:
            for finding in findings_models:
                if finding.id in c.related_finding_ids and c.id not in finding.correlation_refs:
                    finding.correlation_refs.append(c.id)
        state['correlated_findings'] = [finding.model_dump() for finding in findings_models]
        state['correlations'] = [c.model_dump() for c in correlations]
    except Exception as e:  # pragma: no cover
        logger.exception("correlate_findings failed: %s", e)
        _append_warning(state, 'graph', 'correlate', str(e))
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])
    return state


async def enhanced_enrich_findings(state: "GraphState") -> "GraphState":
    """Advanced async enrichment node with caching & metrics.

    Features:
    - Deterministic cache key computed from raw_findings JSON (stable ordering)
    - Cache hit short-circuit (reuses previously enriched findings)
    - Metrics: wall-clock duration stored under state['metrics']['enrich_duration'] (seconds, float)
    - Populates state['enriched_findings'] like basic enrich_findings
    - Records used cache keys in state['cache_keys'] list

    State fields used/created:
    - raw_findings: List[dict]
    - metrics: dict (created if absent)
    - cache_keys: list[str] (created if absent)
    - enrich_cache: dict[str, list[dict]] mapping cache_key -> enriched findings
    """
    start = time.monotonic()
    raw_list = state.get("raw_findings") or []
    # Normalize container fields potentially pre-populated as None by graph initialization
    if state.get('warnings') is None:
        state['warnings'] = []
    if state.get('metrics') is None or not isinstance(state.get('metrics'), dict):
        state['metrics'] = {}
    if state.get('cache_keys') is None or not isinstance(state.get('cache_keys'), list):
        state['cache_keys'] = []
    # Build deterministic cache key (sha256 of canonical JSON of raw findings)
    try:
        import hashlib
        canonical = json.dumps(raw_list, sort_keys=True, separators=(",", ":"))
        h = hashlib.sha256(canonical.encode()).hexdigest()
        cache_key = f"enrich:{h}"
    except Exception:  # pragma: no cover - extremely unlikely
        cache_key = "enrich:invalid_key"
    cache: Dict[str, Any] = state.setdefault("enrich_cache", {})  # mapping key-> enriched findings list
    if not isinstance(cache, dict):  # Defensive if pre-populated with None
        cache = {}
        state['enrich_cache'] = cache
    # Cache hit path
    if cache_key in cache:
        logger.debug("enhanced_enrich_findings cache hit key=%s", cache_key)
        state.setdefault("metrics", {}).setdefault("cache_hits", 0)
        state["metrics"]["cache_hits"] += 1  # type: ignore[index]
        # Rehydrate enriched findings from cache
        cached = cache.get(cache_key) or []
        state["enriched_findings"] = cached
        # Still record very small duration for observability
        duration = time.monotonic() - start
        state.setdefault("metrics", {})["enrich_duration"] = duration
        ck_list = state.setdefault("cache_keys", [])
        if cache_key not in ck_list:
            ck_list.append(cache_key)
        return state
    # Cache miss -> perform enrichment
    try:
        findings = _findings_from_graph(state)
        sr = ScannerResult(
            scanner="mixed",
            finding_count=len(findings),
            findings=findings,
        )
        report = Report(
            meta=Meta(),
            summary=Summary(
                finding_count_total=len(findings),
                finding_count_emitted=len(findings),
            ),
            results=[sr],
            collection_warnings=[],
            scanner_errors=[],
            summary_extension=SummaryExtension(total_risk_score=0),
        )
        astate = AgentState(report=report)
        # Run enrichment pipeline pieces (sync) inside async context
        astate = _augment(astate)
        astate = apply_external_knowledge(astate)
        enriched: List[Dict[str, Any]] = []
        if astate.report and astate.report.results:
            for result in astate.report.results:
                for finding in result.findings:
                    try:
                        enriched.append(finding.model_dump())
                    except Exception:  # pragma: no cover
                        continue
        state["enriched_findings"] = enriched
        # Update cache structures
        cache[cache_key] = enriched
        ck_list = state.setdefault("cache_keys", [])
        if cache_key not in ck_list:
            ck_list.append(cache_key)
    except Exception as e:  # pragma: no cover
        logger.exception("enhanced_enrich_findings failed key=%s error=%s", cache_key, e)
        _append_warning(state, "graph", "enhanced_enrich", f"{type(e).__name__}: {e}")
        if "enriched_findings" not in state:
            state["enriched_findings"] = state.get("raw_findings", [])
    finally:
        duration = time.monotonic() - start
        state.setdefault("metrics", {})["enrich_duration"] = duration
    return state


def get_enhanced_llm_provider():
    """Multi-provider selection wrapper.

    Currently returns the default provider; placeholder for future logic that
    could select alternate providers based on:
      - state['summary_strategy']
      - environment variables (AGENT_LLM_PROVIDER / AGENT_LLM_PROVIDER_ALT)
      - risk / finding volume thresholds
    Deterministic by design (no randomness).
    """
    # Basic strategy: prefer primary; optionally allow alternate env variable if set and distinct
    primary = get_llm_provider()
    alt_env = __import__('os').environ.get('AGENT_LLM_PROVIDER_ALT')
    if alt_env and alt_env == '__use_null__':  # explicit override to force Null provider
        try:
            from .llm_provider import NullLLMProvider  # type: ignore
            return NullLLMProvider()
        except Exception:  # pragma: no cover
            return primary
    return primary


def streaming_summarizer(provider, reductions, correlations, actions, baseline_context):
    """Deterministic streaming facade.

    For now this simply delegates to provider.summarize once (no incremental
    token emission) to maintain determinism. Later this could yield partial
    chunks and assemble them into a final Summaries object.
    """
    return provider.summarize(reductions, correlations, actions, baseline_context=baseline_context)


async def enhanced_summarize_host_state(state: "GraphState") -> "GraphState":
    """Advanced async summarization node with streaming + metrics.

    Enhancements over basic summarize_host_state:
    - Optional streaming mode (state['streaming_enabled'])
    - Multi-provider selection via get_enhanced_llm_provider()
    - Metrics: duration, token usage, call counts
    - Iteration guard (respects AGENT_MAX_SUMMARY_ITERS)
    """
    start = time.monotonic()
    try:
        # Iteration guard
        try:
            max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
        except ValueError:
            max_iter = 3
        iters = int(state.get('iteration_count', 0) or 0)
        if iters >= max_iter:
            _append_warning(state, 'graph', 'enhanced_summarize', 'iteration_limit_reached')
            return state

        provider = get_enhanced_llm_provider()
        findings_src = state.get('correlated_findings') or state.get('enriched_findings') or []
        findings_models: List[Finding] = []
        for finding_dict in findings_src:
            try:
                findings_models.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
            except Exception:  # pragma: no cover
                continue
        reductions = reduce_all(findings_models)
        from .models import Correlation as _C
        corr_objs = []
        for c in state.get('correlations', []) or []:
            try:
                corr_objs.append(_C(**c))
            except Exception:  # pragma: no cover
                continue
        baseline_context = state.get('baseline_results') or {}
        streaming = bool(state.get('streaming_enabled'))
        if streaming:
            summaries = streaming_summarizer(provider, reductions, corr_objs, actions=[], baseline_context=baseline_context)
        else:
            summaries = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)
        state['summary'] = summaries.model_dump()
        state['iteration_count'] = iters + 1
        # Metrics extraction
        sm = summaries.metrics or {}
        metrics = state.setdefault('metrics', {})
        if 'tokens_prompt' in sm:
            metrics['tokens_prompt'] = sm['tokens_prompt']
        if 'tokens_completion' in sm:
            metrics['tokens_completion'] = sm['tokens_completion']
        metrics['summarize_calls'] = metrics.get('summarize_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_summarize_host_state failed: %s', e)
        _append_warning(state, 'graph', 'enhanced_summarize', f"{type(e).__name__}: {e}")
    finally:
        duration = time.monotonic() - start
        state.setdefault('metrics', {})['summarize_duration'] = duration
    return state


async def enhanced_suggest_rules(state: "GraphState") -> "GraphState":
    """Advanced async rule suggestion with optional LLM refinement & metrics.

    Steps:
      1. Serialize enriched findings to temp JSON (reuse existing miner interface)
      2. Run gap miner to derive initial suggestions
      3. If provider exposes refine_rules, refine suggestions deterministically
      4. Store suggestions and metrics (duration, count)
    """
    start = time.monotonic()
    try:
        findings = state.get('enriched_findings') or []
        import tempfile, json as _json
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
            _json.dump({'enriched_findings': findings}, tf)
            tf.flush()
            from pathlib import Path
            # Use slightly permissive thresholds to increase suggestion probability
            result = mine_gap_candidates([Path(tf.name)], risk_threshold=10, min_support=2)
        suggestions = result.get('suggestions', [])
        # Optional refinement
        try:
            provider = get_enhanced_llm_provider()
            refine_fn = getattr(provider, 'refine_rules', None)
            if callable(refine_fn) and suggestions:
                suggestions = refine_fn(suggestions, examples=None)
        except Exception:  # pragma: no cover - refinement fallback
            pass
        state['suggested_rules'] = suggestions
        metrics = state.setdefault('metrics', {})
        metrics['rule_suggest_count'] = len(suggestions)
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_suggest_rules failed: %s', e)
        _append_warning(state, 'graph', 'enhanced_rule_suggest', f"{type(e).__name__}: {e}")
    finally:
        duration = time.monotonic() - start
        state.setdefault('metrics', {})['rule_suggest_duration'] = duration
    return state


def advanced_router(state: "GraphState") -> str:
    """Priority-based routing decision.

    Order:
      1. human_feedback_pending -> 'human_feedback'
      2. Any compliance-related finding -> 'compliance'
      3. High severity finding with missing baseline context -> 'baseline'
      4. Finding requiring external data -> 'risk_analysis'
      5. Fallback -> 'summarize'

    On any exception returns 'error'.
    """
    try:
        # 1. Human feedback gate
        if state.get('human_feedback_pending'):
            return 'human_feedback'
        # Choose findings source preference
        findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
        # 2. Compliance detection (by tag or category or metadata marker)
        for finding in findings:
            tags = [t.lower() for t in (finding.get('tags') or [])]
            cat = str(finding.get('category','')).lower()
            if 'compliance' in tags or cat == 'compliance' or finding.get('metadata',{}).get('compliance_standard'):
                return 'compliance'
        # 3. High severity missing baseline
        high_ids = []
        for finding in findings:
            sev = str(finding.get('severity','')).lower()
            if sev in {'high','critical'}:
                high_ids.append(finding.get('id'))
        if high_ids:
            baseline = state.get('baseline_results') or {}
            # If any high-sev id absent -> baseline
            for hid in high_ids:
                if hid and hid not in baseline:
                    return 'baseline'
        # 4. External data requirement (heuristic: tag 'external' or metadata flag)
        for finding in findings:
            tags = [t.lower() for t in (finding.get('tags') or [])]
            meta = finding.get('metadata',{}) or {}
            if 'external_required' in tags or meta.get('requires_external') or meta.get('threat_feed_lookup'):
                return 'risk_analysis'
        # 5. Default path
        return 'summarize'
    except Exception:  # pragma: no cover
        return 'error'


def should_suggest_rules(state: "GraphState") -> str:
    """Router: decide whether to run rule suggestion.

    Returns 'suggest_rules' if any enriched finding has severity 'high'; otherwise END.
    END constant imported lazily (fallback '__end__').
    """
    try:
        enriched = state.get('enriched_findings') or []
        for finding in enriched:
            sev = str(finding.get('severity','')).lower()
            if sev == 'high':
                return 'suggest_rules'
        try:  # pragma: no cover - library optional
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return '__end__'
    except Exception:  # pragma: no cover
        return 'suggest_rules'  # fail open to ensure progress


def choose_post_summarize(state: "GraphState") -> str:
    """Router after summarization.

    If baseline cycle not completed and any enriched finding lacks 'baseline_status', route to 'plan_baseline'.
    Else delegate to should_suggest_rules.
    """
    try:
        if not state.get('baseline_cycle_done'):
            enriched = state.get('enriched_findings') or []
            for finding in enriched:
                if 'baseline_status' not in finding:
                    return 'plan_baseline'
        return should_suggest_rules(state)
    except Exception:  # pragma: no cover
        return 'suggest_rules'


# ---------------------------------------------------------------------------
# Specialized & Supporting Nodes (Phase 4 - Step 10)
# ---------------------------------------------------------------------------
try:  # Optional: message classes for planning/integration if langchain present
    from langchain_core.messages import AIMessage, ToolMessage  # type: ignore
except Exception:  # pragma: no cover
    AIMessage = ToolMessage = None  # type: ignore


async def tool_coordinator(state: "GraphState") -> "GraphState":
    """Analyze enriched/correlated findings and plan external tool needs.

    Current heuristic (deterministic, side-effect free):
      - For each enriched finding missing 'baseline_status', create a pending
        tool call for 'query_baseline'.
      - Future expansion: triage to different tools based on metadata.

    Writes list of tool call specs (dict) to state['pending_tool_calls'].
    Metrics: increments state['metrics']['tool_coordinator_calls'] and records
    duration under 'tool_coordinator_duration'.
    """
    start = time.monotonic()
    try:
        findings = state.get('correlated_findings') or state.get('enriched_findings') or []
        pending: List[Dict[str, Any]] = []
        host_id = __import__('os').environ.get('AGENT_GRAPH_HOST_ID', 'graph_host')
        for finding in findings:
            if 'baseline_status' not in finding:  # baseline context absent
                fid = finding.get('id') or 'unknown'
                pending.append({
                    'id': f'call_{fid}',
                    'name': 'query_baseline',
                    'args': {
                        'finding_id': fid,
                        'title': finding.get('title') or '',
                        'severity': finding.get('severity') or '',
                        'scanner': finding.get('scanner') or 'mixed',
                        'host_id': host_id,
                    }
                })
        state['pending_tool_calls'] = pending
        metrics = state.setdefault('metrics', {})
        metrics['tool_coordinator_calls'] = metrics.get('tool_coordinator_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('tool_coordinator failed: %s', e)
        _append_warning(state, 'graph', 'tool_coordinator', f"{type(e).__name__}: {e}")
    finally:
        duration = time.monotonic() - start
        state.setdefault('metrics', {})['tool_coordinator_duration'] = duration
    return state


def plan_baseline_queries(state: "GraphState") -> "GraphState":
    """Construct AIMessage with tool_calls for baseline queries.

    Prefers precomputed state['pending_tool_calls'] from tool_coordinator; if not
    present falls back to scanning enriched findings (same heuristic).

    Adds message only if there is at least one pending call and AIMessage is available.
    """
    try:
        if AIMessage is None:  # dependency not available
            return state
        pending = state.get('pending_tool_calls')
        if pending is None:  # derive on-demand
            enriched = state.get('enriched_findings') or []
            host_id = __import__('os').environ.get('AGENT_GRAPH_HOST_ID', 'graph_host')
            derived: List[Dict[str, Any]] = []
            for finding in enriched:
                if 'baseline_status' not in finding:
                    derived.append({
                        'id': f"call_{finding.get('id') or 'unknown'}",
                        'name': 'query_baseline',
                        'args': {
                            'finding_id': finding.get('id') or 'unknown',
                            'title': finding.get('title') or '',
                            'severity': finding.get('severity') or '',
                            'scanner': finding.get('scanner') or 'mixed',
                            'host_id': host_id,
                        }
                    })
            pending = derived
        if not pending:
            return state
        msgs = state.get('messages') or []
        msgs.append(AIMessage(content="Baseline context required", tool_calls=pending))  # type: ignore[arg-type]
        state['messages'] = msgs
        metrics = state.setdefault('metrics', {})
        metrics['baseline_plan_calls'] = metrics.get('baseline_plan_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('plan_baseline_queries (scaffold) failed: %s', e)
        _append_warning(state, 'graph', 'plan_baseline', f"{type(e).__name__}: {e}")
    return state


def integrate_baseline_results(state: "GraphState") -> "GraphState":
    """Integrate ToolMessage outputs into baseline_results & mark cycle done.

    Compatible with legacy implementation but also tolerant to absent ToolMessage
    class. Any dict content under a ToolMessage with a 'finding_id' key is added.
    Sets baseline_cycle_done = True always (conservative to avoid infinite loops).
    """
    try:
        if ToolMessage is None:
            state['baseline_cycle_done'] = True
            return state
        msgs = state.get('messages') or []
        results = state.get('baseline_results') or {}
        import json as _json  # local import
        for m in msgs:
            try:
                if isinstance(m, ToolMessage):
                    payload = getattr(m, 'content', None)
                    data_obj = None
                    if isinstance(payload, dict):
                        data_obj = payload
                    elif isinstance(payload, str):
                        try:
                            data_obj = _json.loads(payload)
                        except Exception:  # pragma: no cover
                            data_obj = None
                    if isinstance(data_obj, dict):
                        fid = data_obj.get('finding_id')
                        if isinstance(fid, str):
                            results[fid] = data_obj  # type: ignore[index]
            except Exception:  # pragma: no cover
                continue
        state['baseline_results'] = results
    except Exception as e:  # pragma: no cover
        logger.exception('integrate_baseline_results (scaffold) failed: %s', e)
        _append_warning(state, 'graph', 'integrate_baseline', f"{type(e).__name__}: {e}")
    finally:
        state['baseline_cycle_done'] = True
    return state


# ---------------------------------------------------------------------------
# High-Level Analysis Nodes (Phase 4 - Step 11)
# ---------------------------------------------------------------------------
async def risk_analyzer(state: "GraphState") -> "GraphState":
    """Aggregate higher-level risk assessment.

    Heuristic logic (deterministic):
      - Count findings by severity (case-insensitive)
      - Compute total and average risk_score (if available)
      - Derive qualitative overall_risk: critical > high > medium > low > info
      - Identify top 3 risk findings (by risk_score) capturing id & title

    Writes dict to state['risk_assessment'] and metrics 'risk_analyzer_duration'.
    """
    start = time.monotonic()
    try:
        findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
        sev_counters: Dict[str, int] = {k: 0 for k in ['critical','high','medium','low','info','unknown']}
        total_risk = 0
        risk_values: List[int] = []
        for finding in findings:
            sev = str(finding.get('severity','unknown')).lower()
            sev_counters[sev] = sev_counters.get(sev, 0) + 1
            try:
                rv = int(finding.get('risk_score', finding.get('risk_total', 0)) or 0)
            except Exception:
                rv = 0
            total_risk += rv
            risk_values.append(rv)
        avg_risk = (sum(risk_values)/len(risk_values)) if risk_values else 0.0
        # Determine qualitative risk
        qualitative = 'info'
        order = ['critical','high','medium','low','info']
        for level in order:
            if sev_counters.get(level):
                qualitative = level
                break
        # Top 3 findings by risk score
        top = sorted([
            {
                'id': finding.get('id'),
                'title': finding.get('title'),
                'risk_score': int(finding.get('risk_score', finding.get('risk_total', 0)) or 0),
                'severity': finding.get('severity'),
            } for finding in findings
        ], key=lambda x: x['risk_score'], reverse=True)[:3]
        assessment = {
            'counts': sev_counters,
            'total_risk_score': total_risk,
            'average_risk_score': avg_risk,
            'overall_risk': qualitative,
            'top_findings': top,
            'finding_count': len(findings),
        }
        state['risk_assessment'] = assessment
        state.setdefault('metrics', {})['risk_analyzer_calls'] = state.get('metrics', {}).get('risk_analyzer_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('risk_analyzer failed: %s', e)
        _append_warning(state, 'graph', 'risk_analyzer', f"{type(e).__name__}: {e}")
    finally:
        state.setdefault('metrics', {})['risk_analyzer_duration'] = time.monotonic() - start
    return state


async def compliance_checker(state: "GraphState") -> "GraphState":
    """Evaluate simple compliance mapping heuristics.

    For each finding, check metadata or tags for compliance cues:
      - If metadata.compliance_standard present, record mapping.
      - If tag matches known standards (pci, hipaa, soc2, iso27001, cis), accumulate.
      - For each standard, count associated findings and list their ids.

    Output structure in state['compliance_check']:
      {
        'standards': {
           'PCI DSS': {'finding_ids': [...], 'count': n},
           'HIPAA': { ... },
           ...
        },
        'total_compliance_findings': X
      }
    Metrics: compliance_checker_duration, compliance_checker_calls.
    """
    start = time.monotonic()
    try:
        findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
        std_map: Dict[str, Dict[str, Any]] = {}
        known_aliases = {
            'pci': 'PCI DSS',
            'pcidss': 'PCI DSS',
            'hipaa': 'HIPAA',
            'soc2': 'SOC 2',
            'soc': 'SOC 2',
            'iso27001': 'ISO 27001',
            'cis': 'CIS Benchmark',
        }
        def normalize_standard(raw: str) -> Optional[str]:
            if not raw:
                return None
            key = raw.lower().replace(' ','')
            return known_aliases.get(key)
        for finding in findings:
            meta = finding.get('metadata', {}) or {}
            tags = [t.lower() for t in (finding.get('tags') or [])]
            candidates: List[str] = []
            # Explicit metadata standard
            ms = meta.get('compliance_standard')
            if isinstance(ms, str):
                norm_meta = normalize_standard(ms) or ms  # attempt normalization; fallback original
                candidates.append(norm_meta)
            # Tag-based discovery
            for t in tags:
                norm = normalize_standard(t)
                if norm:
                    candidates.append(norm)
            # Deduplicate while preserving insertion order
            seen = set()
            unique: List[str] = []
            for c in candidates:
                if c not in seen:
                    seen.add(c); unique.append(c)
            for std in unique:
                bucket = std_map.setdefault(std, {'finding_ids': []})
                fid = finding.get('id')
                if fid and fid not in bucket['finding_ids']:
                    bucket['finding_ids'].append(fid)
        # finalize counts
        total = 0
        for std, bucket in std_map.items():
            bucket['count'] = len(bucket['finding_ids'])
            total += bucket['count']
        state['compliance_check'] = {
            'standards': std_map,
            'total_compliance_findings': total,
        }
        state.setdefault('metrics', {})['compliance_checker_calls'] = state.get('metrics', {}).get('compliance_checker_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('compliance_checker failed: %s', e)
        _append_warning(state, 'graph', 'compliance_checker', f"{type(e).__name__}: {e}")
    finally:
        state.setdefault('metrics', {})['compliance_checker_duration'] = time.monotonic() - start
    return state


# ---------------------------------------------------------------------------
# Operational Nodes (Phase 4 - Step 12)
# ---------------------------------------------------------------------------
async def error_handler(state: "GraphState") -> "GraphState":
    """Analyze recent errors and toggle degraded / fallback modes.

    Heuristics:
      - Count errors with 'timeout' (case-insensitive) in message; if >= 3 -> degraded_mode True
      - Count provider related errors containing 'model' or 'provider'; if >=2 -> set llm_provider_mode='fallback'
      - If degraded_mode True and provider mode not set, set llm_provider_mode='fallback'
    Records metrics: error_handler_calls, error_handler_duration, timeout_error_count.
    """
    start = time.monotonic()
    try:
        errs = state.get('errors') or []
        timeout_count = 0
        provider_errs = 0
        for e in errs[-25:]:  # analyze last 25 for recency bias
            msg = ''
            if isinstance(e, dict):
                msg = str(e.get('error') or e.get('message') or '')
            else:
                msg = str(e)
            low = msg.lower()
            if 'timeout' in low:
                timeout_count += 1
            if 'model' in low or 'provider' in low:
                provider_errs += 1
        if timeout_count >= 3:
            state['degraded_mode'] = True
        # fallback provider decision
        if provider_errs >= 2:
            state['llm_provider_mode'] = 'fallback'
        if state.get('degraded_mode') and not state.get('llm_provider_mode'):
            state['llm_provider_mode'] = 'fallback'
        m = state.setdefault('metrics', {})
        m['error_handler_calls'] = m.get('error_handler_calls', 0) + 1
        m['timeout_error_count'] = timeout_count
    except Exception as e:  # pragma: no cover
        logger.exception('error_handler failed: %s', e)
        _append_warning(state, 'graph', 'error_handler', f"{type(e).__name__}: {e}")
    finally:
        state.setdefault('metrics', {})['error_handler_duration'] = time.monotonic() - start
    return state


async def human_feedback_node(state: "GraphState") -> "GraphState":
    """Placeholder human-in-the-loop node.

    Behavior:
      - If human_feedback_pending True and no 'human_feedback' entry in state, simulate wait (non-blocking quick sleep) and attach a stub
        feedback structure (deterministic placeholder).
      - Clear human_feedback_pending; set human_feedback_processed True.
    Metrics: human_feedback_node_calls, human_feedback_node_duration.
    """
    start = time.monotonic()
    try:
        if state.get('human_feedback_pending'):
            # Simulate minimal async gap (could be replaced by real I/O later)
            await asyncio.sleep(0)
            if 'human_feedback' not in state:
                state['human_feedback'] = {
                    'status': 'auto-ack',
                    'notes': 'No-op placeholder feedback',
                }
        state['human_feedback_pending'] = False
        state['human_feedback_processed'] = True
        m = state.setdefault('metrics', {})
        m['human_feedback_node_calls'] = m.get('human_feedback_node_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('human_feedback_node failed: %s', e)
        _append_warning(state, 'graph', 'human_feedback', f"{type(e).__name__}: {e}")
    finally:
        state.setdefault('metrics', {})['human_feedback_node_duration'] = time.monotonic() - start
    return state


async def cache_manager(state: "GraphState") -> "GraphState":
    """Centralize caching logic.

    Strategy:
      - Maintain state['cache'] dict; composite key segments for phases (enrich, summarize, risk, compliance).
      - If enriched_findings present, store under key 'enrich:<hash>' (reuse existing cache_keys if available, else compute sha256).
      - If summary present, store summary snapshot under 'summary:iter_<n>'.
      - If risk/compliance present, store latest snapshots under fixed keys.
      - Compute cache_hit_rate = cache_hits / (cache_hits + cache_misses) if metrics available.

    Does not mutate primary data; only updates cache & metrics.
    """
    start = time.monotonic()
    try:
        cache_store: Dict[str, Any] = state.setdefault('cache', {})
        # Enrichment caching
        enriched = state.get('enriched_findings')
        if enriched is not None:
            try:
                import hashlib, json as _json
                canonical = _json.dumps(enriched, sort_keys=True, separators=(',',':'))
                ek = f"enrich:{hashlib.sha256(canonical.encode()).hexdigest()}"
                if ek not in cache_store:
                    cache_store[ek] = enriched
            except Exception:  # pragma: no cover
                pass
        # Summary snapshot
        if 'summary' in state:
            iter_count = state.get('iteration_count', 0)
            key = f"summary:iter_{iter_count}"
            if key not in cache_store:
                cache_store[key] = state['summary']
        # Risk / compliance snapshots
        if 'risk_assessment' in state:
            cache_store['risk:latest'] = state['risk_assessment']
        if 'compliance_check' in state:
            cache_store['compliance:latest'] = state['compliance_check']
        # Derived cache metrics
        metrics = state.setdefault('metrics', {})
        hits = metrics.get('cache_hits', 0)
        misses = metrics.get('cache_misses', 0)
        denom = hits + misses
        if denom:
            metrics['cache_hit_rate'] = hits / denom
        metrics['cache_manager_calls'] = metrics.get('cache_manager_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('cache_manager failed: %s', e)
        _append_warning(state, 'graph', 'cache_manager', f"{type(e).__name__}: {e}")
    finally:
        state.setdefault('metrics', {})['cache_manager_duration'] = time.monotonic() - start
    return state


async def metrics_collector(state: "GraphState") -> "GraphState":
    """Aggregate final metrics snapshot.

    Gathers metrics plus derived fields:
      - total_duration if 'start_time' present (difference to now)
      - suggestion_count, finding_counts, compliance/risk summaries
      - llm_provider_mode, degraded_mode flags
      - cache size (#entries)
    Stores in state['final_metrics'] and logs debug summary.
    """
    start = time.monotonic()
    try:
        metrics = dict(state.get('metrics') or {})  # shallow copy
        # Derived counters
        metrics['suggestion_count'] = len(state.get('suggested_rules') or [])
        metrics['enriched_count'] = len(state.get('enriched_findings') or [])
        metrics['correlated_count'] = len(state.get('correlated_findings') or [])
        ra = state.get('risk_assessment') or {}
        metrics['overall_risk'] = ra.get('overall_risk')
        cc = state.get('compliance_check') or {}
        metrics['compliance_standards_count'] = len((cc.get('standards') or {}).keys())
        metrics['llm_provider_mode'] = state.get('llm_provider_mode') or metrics.get('llm_provider_mode') or 'normal'
        metrics['degraded_mode'] = bool(state.get('degraded_mode'))
        cache_store = state.get('cache') or {}
        metrics['cache_entries'] = len(cache_store)
        # total duration (optional start_time recorded externally)
        st = state.get('start_time')
        if isinstance(st, (int, float)):
            metrics['total_duration'] = time.monotonic() - float(st)
        state['final_metrics'] = metrics
        logger.debug('Final metrics: %s', metrics)
        base = state.setdefault('metrics', {})
        base['metrics_collector_calls'] = base.get('metrics_collector_calls', 0) + 1
    except Exception as e:  # pragma: no cover
        logger.exception('metrics_collector failed: %s', e)
        _append_warning(state, 'graph', 'metrics_collector', f"{type(e).__name__}: {e}")
    finally:
        state.setdefault('metrics', {})['metrics_collector_duration'] = time.monotonic() - start
    return state

# ---------------------------------------------------------------------------
# Final consolidated public exports (Step 13: Finalize Exports)
# Re-declare __all__ at module end to ensure late-added symbols are included.
# ---------------------------------------------------------------------------
__all__ = [
    # Core state & helpers
    'GraphState', 'get_llm_provider', '_findings_from_graph', '_append_warning', '_augment',
    'apply_external_knowledge', 'reduce_all', 'mine_gap_candidates',
    # Core / enhanced enrichment & summarization
    'enrich_findings', 'enhanced_enrich_findings', 'summarize_host_state', 'enhanced_summarize_host_state',
    # Rule suggestion & correlation
    'suggest_rules', 'enhanced_suggest_rules', 'correlate_findings',
    # LLM provider utilities
    'get_enhanced_llm_provider', 'streaming_summarizer',
    # Routers
    'advanced_router', 'should_suggest_rules', 'choose_post_summarize',
    # Baseline / tool coordination
    'tool_coordinator', 'plan_baseline_queries', 'integrate_baseline_results',
    # High-level analysis
    'risk_analyzer', 'compliance_checker',
    # Operational nodes
    'error_handler', 'human_feedback_node', 'cache_manager', 'metrics_collector',
    # Models
    'Finding', 'ScannerResult', 'Report', 'Meta', 'Summary', 'SummaryExtension', 'AgentState'
]
