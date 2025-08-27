from __future__ import annotations
"""Graph state schema (INT-FUT-GRAPH-STATE)

Central TypedDict describing the evolving state passed between LangGraph nodes
for the future LLM-driven analysis agent. This is a lightweight, JSON-friendly
structure distinct from the richer Pydantic models in models.py to allow
incremental population and external serialization without validation overhead.
"""
from typing import TypedDict, List, Dict, Any

# Runtime graph assembly (experimental minimal linear workflow)
try:  # Optional dependency guard
    from langgraph.graph import StateGraph, END  # type: ignore
    from langgraph.prebuilt import ToolNode  # type: ignore
    from .graph_nodes import (
        enrich_findings,
        summarize_host_state,
        suggest_rules,
        should_suggest_rules,
        choose_post_summarize,
        plan_baseline_queries,
        integrate_baseline_results,
    )
    from .tools import query_baseline
except Exception:  # pragma: no cover - graph optional
    StateGraph = None  # type: ignore
    END = None  # type: ignore
    ToolNode = None  # type: ignore
    enrich_findings = summarize_host_state = suggest_rules = None  # type: ignore
    should_suggest_rules = choose_post_summarize = plan_baseline_queries = integrate_baseline_results = None  # type: ignore
    query_baseline = None  # type: ignore


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

if StateGraph is not None and all(callable(fn) for fn in [enrich_findings, summarize_host_state, suggest_rules]):  # type: ignore
    workflow = StateGraph(GraphState)  # type: ignore[arg-type]
    # Add nodes (ignore type checking for simple function nodes)
    workflow.add_node("enrich", enrich_findings)  # type: ignore[arg-type]
    workflow.add_node("summarize", summarize_host_state)  # type: ignore[arg-type]
    workflow.add_node("suggest_rules", suggest_rules)  # type: ignore[arg-type]
    if callable(plan_baseline_queries):
        workflow.add_node("plan_baseline", plan_baseline_queries)  # type: ignore[arg-type]
    if ToolNode is not None and query_baseline is not None:
        workflow.add_node("baseline_tools", ToolNode([query_baseline]))  # type: ignore[arg-type]
    if callable(integrate_baseline_results):
        workflow.add_node("integrate_baseline", integrate_baseline_results)  # type: ignore[arg-type]
    workflow.set_entry_point("enrich")
    workflow.add_edge("enrich", "summarize")
    # Post-summarize routing: baseline planning cycle or direct rule suggestion
    try:
        if callable(choose_post_summarize):
            mapping = {"suggest_rules": "suggest_rules", END: END}
            if callable(plan_baseline_queries):
                mapping["plan_baseline"] = "plan_baseline"
            workflow.add_conditional_edges("summarize", choose_post_summarize, mapping)  # type: ignore[arg-type]
        else:
            workflow.add_edge("summarize", "suggest_rules")
    except Exception:  # pragma: no cover
        workflow.add_edge("summarize", "suggest_rules")
    # Baseline cycle (plan -> tools -> integrate -> summarize)
    if callable(plan_baseline_queries) and ToolNode is not None and callable(integrate_baseline_results):
        workflow.add_edge("plan_baseline", "baseline_tools")
        workflow.add_edge("baseline_tools", "integrate_baseline")
        workflow.add_edge("integrate_baseline", "summarize")
        # Direct cycle: allow summarization re-entry immediately after tool execution
        try:  # pragma: no cover - optional direct shortcut
            workflow.add_edge("baseline_tools", "summarize")
        except Exception:
            pass
    workflow.add_edge("suggest_rules", END)  # type: ignore[arg-type]
    try:
        app = workflow.compile()
    except Exception:  # pragma: no cover
        app = None
else:  # Fallback placeholder
    workflow = None
    app = None

__all__ = ["GraphState", "workflow", "app"]