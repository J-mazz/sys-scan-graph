from __future__ import annotations
"""LangGraph-based orchestration for the sys-scan agent.

This converts the earlier sequential pipeline into an explicit DAG enabling
future streaming / checkpointing. For now it runs locally in-process.
"""

from pathlib import Path
from typing import Any
import json
from pydantic import BaseModel
from langgraph.graph import Graph
import os, json, time

from .models import AgentState, EnrichedOutput
from .pipeline import (
    load_report,
    augment,
    correlate,
    baseline_rarity,
    reduce as reduce_step,
    summarize,
    actions,
    build_output,
)
from jsonschema import validate as js_validate, ValidationError
import hashlib


class GraphWrapperState(BaseModel):
    state: AgentState = AgentState()
    report_path: str
    enriched: EnrichedOutput | None = None
    checkpoint_dir: str | None = None
    _order: int = 0  # internal sequencing for checkpoint filenames
    schema_path: str | None = None
    index_dir: str | None = None

    def checkpoint(self, label: str):
        if not self.checkpoint_dir:
            return
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        self._order += 1
        path = os.path.join(self.checkpoint_dir, f"{self._order:02d}_{label}.json")
        with open(path, "w") as f:
            f.write(self.state.model_dump_json(indent=2))


def node_load(s: GraphWrapperState) -> GraphWrapperState:
    s.state = load_report(s.state, Path(s.report_path))
    s.checkpoint("load")
    return s


def node_validate(s: GraphWrapperState) -> GraphWrapperState:
    if s.schema_path:
        try:
            schema = json.loads(Path(s.schema_path).read_text())
            js_validate(instance=s.state.raw_report, schema=schema)
        except FileNotFoundError:
            pass  # non-fatal
        except ValidationError as e:
            # record validation error as a synthetic finding-like warning structure
            if s.state.report:
                s.state.report.collection_warnings.append({
                    "scanner": "validator",
                    "message": f"schema_validation_error: {e.message[:200]}"
                })
    s.checkpoint("validate")
    return s


def node_augment(s: GraphWrapperState) -> GraphWrapperState:
    s.state = augment(s.state)
    s.checkpoint("augment")
    return s


def node_correlate(s: GraphWrapperState) -> GraphWrapperState:
    # Correlations now run in parallel path with baseline (no dependency on baseline rarity)
    s.state = correlate(s.state)
    s.checkpoint("correlate")
    return s


def node_baseline(s: GraphWrapperState) -> GraphWrapperState:
    s.state = baseline_rarity(s.state)
    s.checkpoint("baseline")
    return s


def node_reduce(s: GraphWrapperState) -> GraphWrapperState:
    # Reduce waits for both baseline & correlate edges
    s.state = reduce_step(s.state)
    s.checkpoint("reduce")
    return s


def node_summarize(s: GraphWrapperState) -> GraphWrapperState:
    s.state = summarize(s.state)
    s.checkpoint("summarize")
    return s


def node_actions(s: GraphWrapperState) -> GraphWrapperState:
    s.state = actions(s.state)
    s.checkpoint("actions")
    return s


def node_output(s: GraphWrapperState) -> GraphWrapperState:
    s.enriched = build_output(s.state, Path(s.report_path))
    s.checkpoint("output")
    return s


def build_graph() -> Graph:
    g = Graph()
    # Nodes
    for name, fn in [
        ("load", node_load),
        ("validate", node_validate),
        ("augment", node_augment),
        ("correlate", node_correlate),
        ("baseline", node_baseline),
        ("reduce", node_reduce),
        ("summarize", node_summarize),
        ("actions", node_actions),
        ("output", node_output),
    ]:
        g.add_node(name, fn)
    # Linear ordering to satisfy simple Graph constraint (no multi-edges from same node)
    for a, b in [
        ("load", "validate"),
        ("validate", "augment"),
        ("augment", "correlate"),
        ("correlate", "baseline"),
        ("baseline", "reduce"),
        ("reduce", "summarize"),
        ("summarize", "actions"),
        ("actions", "output"),
    ]:
        g.add_edge(a, b)
    g.set_entry_point("load")
    g.set_finish_point("output")
    return g


def run_graph(report_path: Path, checkpoint_dir: str | None = None, schema_path: str | None = None, index_dir: str | None = None) -> EnrichedOutput:
    g = build_graph()
    wrapper = GraphWrapperState(report_path=str(report_path), checkpoint_dir=checkpoint_dir, schema_path=schema_path, index_dir=index_dir)
    app = g.compile()
    final: GraphWrapperState = app.invoke(wrapper)  # type: ignore
    enriched = final.enriched
    if enriched and index_dir:
        os.makedirs(index_dir, exist_ok=True)
        # Write/update index JSON (append style)
        idx_path = Path(index_dir) / "index.json"
        entry = {
            "report_path": str(report_path),
            "enriched_hash": hashlib.sha256(enriched.model_dump_json().encode()).hexdigest(),
            "scan_id": final.state.report.meta.scan_id if final.state.report else None,
            "host_id": final.state.report.meta.host_id if final.state.report else None,
            "timestamp": int(time.time()),
            "finding_total": final.state.report.summary.finding_count_total if final.state.report else None,
            "correlation_count": len(enriched.correlations),
            "action_count": len(enriched.actions)
        }
        if idx_path.exists():
            try:
                existing = json.loads(idx_path.read_text())
                if isinstance(existing, list):
                    existing.append(entry)
                    idx_path.write_text(json.dumps(existing, indent=2))
                else:
                    idx_path.write_text(json.dumps([existing, entry], indent=2))
            except Exception:
                idx_path.write_text(json.dumps([entry], indent=2))
        else:
            idx_path.write_text(json.dumps([entry], indent=2))
    return enriched  # type: ignore
