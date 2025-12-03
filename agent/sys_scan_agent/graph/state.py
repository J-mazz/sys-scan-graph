"""GraphState schema definition (INT-FUT-GRAPH-STATE).

Central TypedDict describing the evolving state passed between LangGraph nodes
for the LLM-driven analysis agent. This is a lightweight, JSON-friendly
structure distinct from the richer Pydantic models in models.py to allow
incremental population and external serialization without validation overhead.

This module serves as the single source of truth for the GraphState type,
avoiding circular imports and redefinitions across the codebase.
"""

from __future__ import annotations
from typing import TypedDict, List, Dict, Any


class GraphState(TypedDict, total=False):
    """State schema for the LangGraph-based analysis workflow.
    
    All fields are optional (total=False) to support incremental population
    during workflow execution.
    """
    # Core findings pipeline
    raw_findings: List[Dict[str, Any]]            # Raw scanner findings (pre-enrichment)
    enriched_findings: List[Dict[str, Any]]       # Findings after augmentation / risk recompute
    correlated_findings: List[Dict[str, Any]]     # Findings annotated with correlation references
    suggested_rules: List[Dict[str, Any]]         # Candidate correlation / refinement suggestions
    
    # Analysis artifacts
    summary: Dict[str, Any]                       # LLM or heuristic summary artifacts
    correlations: List[Dict[str, Any]]            # Correlation objects (optional)
    reductions: Dict[str, Any]                    # Artifacts related to findings reduction/consolidation
    risk_assessment: Dict[str, Any]               # Aggregated risk metrics / qualitative judgment
    compliance_check: Dict[str, Any]              # Compliance standards evaluation results
    
    # Warnings and errors
    warnings: List[Any]                           # Structured warning / error entries
    errors: List[Dict[str, Any]]                  # Collected error records (optional, separate from warnings)
    
    # Tool calling and messaging
    messages: List[Any]                           # LangChain message list for tool execution
    pending_tool_calls: List[Dict[str, Any]]      # Planned tool calls (pre ToolNode execution)
    baseline_results: Dict[str, Any]              # Mapping finding_id -> baseline tool result
    baseline_cycle_done: bool                     # Guard to prevent infinite loop
    
    # Iteration and progress tracking
    iteration_count: int                          # Number of summarize iterations executed
    current_stage: str                            # Current processing stage for observability
    start_time: str                               # Processing start timestamp
    summarize_progress: float                     # Summarization progress (0.0-1.0)
    
    # Caching
    metrics: Dict[str, Any]                       # Metrics for node durations / counters
    cache_keys: List[str]                         # Cache keys used during processing
    enrich_cache: Dict[str, List[Dict[str, Any]]] # Mapping cache_key -> enriched findings list
    cache: Dict[str, Any]                         # General-purpose cache store (centralized)
    cache_hits: List[str]                         # Cache hit tracking
    
    # Mode flags
    streaming_enabled: bool                       # Flag to enable streaming summarization
    human_feedback_pending: bool                  # Indicates waiting for human input / approval
    human_feedback_processed: bool                # Human feedback step completed
    degraded_mode: bool                           # Indicates system is in degraded / fallback mode
    llm_provider_mode: str                        # Active LLM provider mode (normal|fallback|null)
    
    # Final outputs
    final_metrics: Dict[str, Any]                 # Aggregated final metrics snapshot
    host_id: str                                  # Host identifier for baseline queries
    
    # Memory management fields (for cross-iteration learning)
    memory: Dict[str, Any]                        # Memory store for cross-iteration learning
    reflection: Dict[str, Any]                    # Reflection and cyclical reasoning results


# Type alias for backward compatibility
StateType = Dict[str, Any]


__all__ = ['GraphState', 'StateType']
