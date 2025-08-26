from __future__ import annotations
import json, hashlib, os, uuid
from pathlib import Path
from typing import List
from .models import AgentState, Report, Finding, EnrichedOutput, ActionItem, ScannerResult, MultiHostCorrelation, Correlation
from .knowledge import apply_external_knowledge
from .rules import Correlator, DEFAULT_RULES
from .reduction import reduce_all
from .llm import LLMClient
from .baseline import BaselineStore
from .risk import compute_risk, load_persistent_weights
from .calibration import apply_probability
from .graph_analysis import annotate_and_summarize
from .endpoint_classification import classify as classify_host_role
from .executors import hash_binary, query_package_manager
from .integrity import sha256_file, verify_file
from .audit import log_stage, hash_text
import yaml
from .baseline import process_feature_vector
import yaml as _yaml
import uuid as _uuid
from .config import load_config
import concurrent.futures

# -----------------
# Internal helpers (risk recomputation & error logging)
# -----------------

def _recompute_finding_risk(f: Finding):
    """Recompute risk fields after any risk_subscores mutation.
    Safe no-op if subscores absent; logs errors instead of raising."""
    try:
        subs = getattr(f, 'risk_subscores', None)
        if not subs:
            return
        weights = load_persistent_weights()
        score, raw = compute_risk(subs, weights)
        f.risk_score = score
        f.risk_total = score
        subs["_raw_weighted_sum"] = round(raw, 3)
        f.probability_actionable = apply_probability(raw)
    except Exception as e:  # pragma: no cover (defensive)
        try:
            log_stage('risk_recompute_error', error=str(e), type=type(e).__name__)
        except Exception:
            pass

def _log_error(stage: str, e: Exception):
    try:
        log_stage(f'{stage}_error', error=str(e), type=type(e).__name__)
    except Exception:
        pass

# Node functions (imperative; future step: convert to LangGraph graph)

def load_report(state: AgentState, path: Path) -> AgentState:
    """Securely load and parse the raw JSON report.

    Hardening steps:
    1. Enforce maximum size (default 5 MB, override via AGENT_MAX_REPORT_MB env).
    2. Read bytes then decode strictly as UTF-8 (reject invalid sequences).
    3. Canonicalize newlines to '\n' before JSON parsing to avoid platform variance.
    """
    max_mb_env = os.environ.get('AGENT_MAX_REPORT_MB')
    try:
        max_mb = int(max_mb_env) if max_mb_env else 5
    except ValueError:
        max_mb = 5
    raw_bytes = Path(path).read_bytes()
    size_mb = len(raw_bytes) / (1024 * 1024)
    if size_mb > max_mb:
        raise ValueError(f"Report size {size_mb:.2f} MB exceeds maximum size {max_mb} MB")
    try:
        text = raw_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError as e:
        raise ValueError(f"Report is not valid UTF-8: {e}") from e
    # Canonicalize newlines (CRLF, CR -> LF)
    if '\r' in text:
        text = text.replace('\r\n', '\n').replace('\r', '\n')
    data = json.loads(text)
    state.raw_report = data
    state.report = Report.model_validate(data)
    return state


def augment(state: AgentState) -> AgentState:
    """Derive host_id, scan_id, finding categories & basic tags without modifying core C++ schema.
    host_id: stable hash of hostname (and kernel if present) unless provided.
    scan_id: random uuid4 hex per run.
    category: inferred from scanner name.
    tags: severity, scanner, plus simple heuristics (network_port, suid, module, kernel_param).
    risk_subscores: placeholder computation (impact/exposure/anomaly/confidence) using existing fields only.
    """
    if not state.report:
        return state
    meta_raw = state.raw_report.get("meta", {}) if state.raw_report else {}
    hostname = meta_raw.get("hostname", "unknown")
    kernel = meta_raw.get("kernel", "")
    # Derive host_id if absent
    if not state.report.meta.host_id:
        h = hashlib.sha256()
        h.update(hostname.encode())
        h.update(b"|")
        h.update(kernel.encode())
        state.report.meta.host_id = h.hexdigest()[:32]
    # Always assign a fresh scan_id (caller can override later if desired)
    state.report.meta.scan_id = uuid.uuid4().hex
    # Category mapping table
    cat_map = {
        "process": "process",
        "network": "network_socket",
        "kernel_params": "kernel_param",
        "kernel_modules": "kernel_module",
        "modules": "kernel_module",
        "world_writable": "filesystem",
        "suid": "privilege_escalation_surface",
        "ioc": "ioc",
        "mac": "mac",
        "integrity": "integrity",
        "rules": "rule_enrichment"
    }
    # Policy multipliers for impact based on category/policy nature
    policy_multiplier = {
        "ioc": 2.0,
        "privilege_escalation_surface": 1.5,
        "network_socket": 1.3,
        "kernel_module": 1.2,
        "kernel_param": 1.1,
    }
    severity_base = {"info":1, "low":2, "medium":3, "high":4, "critical":5, "error":4}
    # Iterate findings to enrich
    if not state.report or not state.report.results:
        return state
    # Apply external knowledge dictionaries after base tagging
    # First pass host role classification prerequisites (we need basic tags/listeners etc) so classification after loop
    for sr in state.report.results:
        inferred_cat = cat_map.get(sr.scanner.lower(), sr.scanner.lower())
        for f in sr.findings:
            if not f.category:
                f.category = inferred_cat
            # Base tags
            base_tags = {f"scanner:{sr.scanner}", f"severity:{f.severity}"}
            # Heuristic tags
            md = f.metadata
            if md.get("port"): base_tags.add("network_port")
            if md.get("state") == "LISTEN": base_tags.add("listening")
            if md.get("suid") == "true": base_tags.add("suid")
            if md.get("module"): base_tags.add("module")
            if md.get("sysctl_key"): base_tags.add("kernel_param")
            if not f.tags:
                f.tags = list(sorted(base_tags))
            else:
                # merge preserving existing list order
                existing = set(f.tags)
                for t in sorted(base_tags):
                    if t not in existing:
                        f.tags.append(t)
            # Structured risk subscores initialization
            if not f.risk_subscores:
                exposure = 0.0
                if any(t in f.tags for t in ["listening","suid","routing","nat"]):
                    # exposure scoring additive, clamp later
                    if "listening" in f.tags: exposure += 1.0
                    if "suid" in f.tags: exposure += 1.0
                    if any(t.startswith("network_port") for t in f.tags): exposure += 0.5
                    if "routing" in f.tags: exposure += 0.5
                    if "nat" in f.tags: exposure += 0.5
                cat_key = f.category or inferred_cat or "unknown"
                impact = float(severity_base.get(f.severity,1)) * policy_multiplier.get(cat_key,1.0)
                anomaly = 0.0  # baseline stage will add weights
                confidence = 1.0  # default; heuristic rules may lower
                f.risk_subscores = {
                    "impact": round(impact,2),
                    "exposure": round(min(exposure,3.0),2),
                    "anomaly": anomaly,
                    "confidence": confidence
                }
    # Host role classification (second pass after initial tagging so we can count listeners etc.)
    if state.report:
        role, role_signals = classify_host_role(state.report)
        for sr in state.report.results:
            for f in sr.findings:
                f.host_role = role
                if not f.host_role_rationale:
                    f.host_role_rationale = role_signals
                if f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward' and f.risk_subscores:
                    impact_changed = False
                    if role in {'lightweight_router','container_host'}:
                        new_imp = round(max(0.5, f.risk_subscores['impact'] * 0.6),2)
                        if new_imp != f.risk_subscores['impact']:
                            f.risk_subscores['impact'] = new_imp; impact_changed = True
                        note = f"host_role {role} => ip_forward normalized (impact adjusted)"
                    elif role in {'workstation','dev_workstation'}:
                        new_imp = round(min(10.0, f.risk_subscores['impact'] * 1.2 + 0.5),2)
                        if new_imp != f.risk_subscores['impact']:
                            f.risk_subscores['impact'] = new_imp; impact_changed = True
                        note = f"host_role {role} => ip_forward unusual (impact raised)"
                    else:
                        note = None
                    if note:
                        if f.rationale:
                            f.rationale.append(note)
                        else:
                            f.rationale = [note]
                    if impact_changed:
                        _recompute_finding_risk(f)
    # Initial risk computation for findings lacking risk_score
    if state.report:
        for sr in state.report.results:
            for f in sr.findings:
                if f.risk_subscores and f.risk_score is None:
                    _recompute_finding_risk(f)
    return state


def correlate(state: AgentState) -> AgentState:
    # Add external knowledge enrichment pass before correlation (ensures knowledge tags in correlations)
    state = apply_external_knowledge(state)
    all_findings: List[Finding] = []
    if not state.report:
        return state
    for r in state.report.results:
        for f in r.findings:
            all_findings.append(f)
    cfg = load_config()
    # Merge default + rule dirs (dedupe by id keeping first)
    from .rules import load_rules_dir, DEFAULT_RULES
    merged = []
    seen = set()
    for rd in (cfg.paths.rule_dirs or []):
        for rule in load_rules_dir(rd):
            rid = rule.get('id')
            if rid and rid in seen: continue
            merged.append(rule); seen.add(rid)
    for rule in DEFAULT_RULES:
        rid = rule.get('id')
        if rid and rid in seen: continue
        merged.append(rule); seen.add(rid)
    correlator = Correlator(merged)
    state.correlations = correlator.apply(all_findings)
    # back-reference correlation ids (simple example: attach first correlation id)
    corr_map = {}
    for c in state.correlations:
        for fid in c.related_finding_ids:
            corr_map.setdefault(fid, []).append(c.id)
    for f in all_findings:
        f.correlation_refs = corr_map.get(f.id, [])
    return state


def baseline_rarity(state: AgentState, baseline_path: Path = Path("agent_baseline.db")) -> AgentState:
    """Update findings with rarity/anomaly score based on baseline store.
    New finding => anomaly=1.0, existing => anomaly decays toward 0.
    Exposure + impact remain unchanged; recalculates composite risk_score (simple formula for now).
    """
    if not state.report:
        return state
    import os as _os
    env_path = _os.environ.get('AGENT_BASELINE_DB')
    if env_path:
        baseline_path = Path(env_path)
    store = BaselineStore(baseline_path)
    host_id = state.report.meta.host_id or "unknown_host"
    all_pairs = []
    all_findings: List[Finding] = []
    for sr in state.report.results:
        for f in sr.findings:
            all_pairs.append((sr.scanner, f))
            all_findings.append(f)
    deltas = store.update_and_diff(host_id, all_pairs)
    # Map back anomaly score
    for sr in state.report.results:
        for f in sr.findings:
            from .baseline import hashlib_sha
            h = f.identity_hash()
            comp = hashlib_sha(sr.scanner, h)
            d = deltas.get(comp)
            if not f.risk_subscores:
                continue
            # Anomaly weighting: new +2, existing changed +1 else decay
            rationale_bits = []
            if d:
                if d["status"] == "new":
                    f.risk_subscores["anomaly"] = 2.0
                    if "baseline:new" not in f.tags:
                        f.tags.append("baseline:new")
                    f.baseline_status = "new"
                    rationale_bits.append("new finding (anomaly +2)")
                else:
                    prev = d.get("prev_seen_count", 1)
                    # Changed vs stable heuristic: if prev_seen_count just incremented from 1->2 treat as +1 else decay
                    if prev <= 2:
                        f.risk_subscores["anomaly"] = 1.0
                        f.baseline_status = "recent"
                        rationale_bits.append("recent finding (anomaly +1)")
                    else:
                        f.risk_subscores["anomaly"] = round(max(0.1, 1.0 / (prev)), 2)
                        f.baseline_status = "existing"
                        rationale_bits.append(f"established finding (anomaly {f.risk_subscores['anomaly']})")
                        if prev >= 5:
                            # Very common => tag and downweight anomaly further contextually
                            if 'baseline:common' not in f.tags:
                                f.tags.append('baseline:common')
                            rationale_bits.append('very common baseline occurrence')
            # Confidence adjustment (placeholder): if only pattern-based IOC (tag contains 'ioc-pattern') lower confidence
            if any(t.startswith("ioc-pattern") for t in f.tags):
                f.risk_subscores["confidence"] = min(f.risk_subscores.get("confidence",1.0), 0.7)
                rationale_bits.append("heuristic IOC pattern (confidence down)")
            # Calibrated risk using weights
            weights = load_persistent_weights()
            score, raw = compute_risk(f.risk_subscores, weights)
            f.risk_score = score
            f.risk_subscores["_raw_weighted_sum"] = round(raw,3)
            f.probability_actionable = apply_probability(raw)
            # Impact & exposure rationale
            impact = f.risk_subscores.get("impact")
            exposure = f.risk_subscores.get("exposure")
            rationale_bits.insert(0, f"impact={impact}")
            rationale_bits.insert(1, f"exposure={exposure}")
            if not f.rationale:
                f.rationale = rationale_bits
            else:
                f.rationale.extend(rationale_bits)
            f.risk_total = f.risk_score
            # Log calibration observation (raw sum) for future supervised tuning
            if state.report and state.report.meta and state.report.meta.scan_id:
                comp_hash = comp  # composite hash from earlier
                try:
                    store.log_calibration_observation(host_id, state.report.meta.scan_id, comp_hash, raw)
                except Exception as e:
                    _log_error('calibration_observe', e)
    return state


def process_novelty(state: AgentState, baseline_path: Path = Path("agent_baseline.db"), distance_threshold: float | None = None, anomaly_boost: float = 1.5) -> AgentState:
    """Assign lightweight embedding-based novelty for process findings.
    Uses config threshold if distance_threshold not provided.
    Parallelizes feature vector computation if configured (CPU-bound hashing/light transforms)."""
    if not state.report:
        return state
    cfg = load_config()
    if distance_threshold is None:
        distance_threshold = cfg.thresholds.process_novelty_distance
    env_path = os.environ.get('AGENT_BASELINE_DB')
    if env_path:
        baseline_path = Path(env_path)
    store = BaselineStore(baseline_path)
    host_id = state.report.meta.host_id or "unknown_host"
    # Collect candidate findings
    candidates: List[Finding] = []
    for sr in state.report.results:
        if sr.scanner.lower() != 'process':
            continue
        for f in sr.findings:
            candidates.append(f)
    if not candidates:
        return state
    # Pre-compute feature vectors (parallel if enabled)
    vecs: dict[str, list[float]] = {}
    def _build_vec(f: Finding):
        cmd = f.metadata.get('cmdline') or f.title or f.metadata.get('process') or ''
        return f.id, process_feature_vector(cmd)
    if cfg.performance.parallel_baseline and len(candidates) > 4:
        with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.performance.workers) as ex:
            for fid, v in ex.map(_build_vec, candidates):
                vecs[fid] = v
    else:
        for f in candidates:
            fid, v = _build_vec(f)
            vecs[fid] = v
    for f in candidates:
        vec = vecs.get(f.id)
        if vec is None:
            # Fallback empty vector -> skip novelty
            continue
        cid, dist, is_new = store.assign_process_vector(host_id, vec, distance_threshold=distance_threshold)
        if is_new or dist > distance_threshold:
            if 'process_novel' not in f.tags:
                f.tags.append('process_novel')
            if f.risk_subscores:
                prev = f.risk_subscores.get('anomaly', 0.0)
                from .risk import CAPS
                cap = CAPS.get('anomaly', 2.0)
                new_anom = round(min(prev + anomaly_boost, cap),2)
                if new_anom != prev:
                    f.risk_subscores['anomaly'] = new_anom
                    _recompute_finding_risk(f)
            rationale_note = f"novel process cluster (cid={cid} dist={dist:.2f})"
            if f.rationale:
                f.rationale.append(rationale_note)
            else:
                f.rationale = [rationale_note]
        else:
            if dist > distance_threshold * 0.8:
                note = f"near-novel process (cid={cid} dist={dist:.2f})"
                if f.rationale:
                    f.rationale.append(note)
                else:
                    f.rationale = [note]
    return state


def sequence_correlation(state: AgentState) -> AgentState:
    """Detect suspicious temporal sequences inside a single scan.
    Current heuristic pattern:
      1. New SUID binary (tag baseline:new + suid) appears
      2. net.ipv4.ip_forward kernel param enabled (value=1) in same scan after the SUID finding order.
    If both occur, emit synthetic correlation with tag sequence_anomaly.
    Ordering proxy: we use appearance order in report results since per-scanner timestamps absent.
    """
    if not state.report:
        return state
    # Flatten findings preserving order
    ordered: List[Finding] = []
    for r in state.report.results:
        for f in r.findings:
            ordered.append(f)
    suid_indices = []
    ip_forward_indices = []
    for idx, f in enumerate(ordered):
        if 'suid' in (f.tags or []) and any(t == 'baseline:new' for t in (f.tags or [])):
            suid_indices.append((idx, f))
        if f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward':
            val = str(f.metadata.get('value') or f.metadata.get('desired') or f.metadata.get('current') or '')
            if val in {'1','true','enabled'}:
                ip_forward_indices.append((idx, f))
    if suid_indices and ip_forward_indices:
        # Check if any suid index precedes any ip_forward index
        trigger_pairs = [(s,i) for (s,_) in suid_indices for (i,_) in ip_forward_indices if s < i]
        if trigger_pairs:
            # Build correlation referencing the involved findings (limit to first few to bound size)
            related = []
            for (s_idx, s_f) in suid_indices[:3]:
                related.append(s_f.id)
            for (i_idx, i_f) in ip_forward_indices[:2]:
                related.append(i_f.id)
            # Avoid duplicate correlation creation
            already = any(c.related_finding_ids == related and 'sequence_anomaly' in (c.tags or []) for c in state.correlations)
            if not already:
                corr = Correlation(
                    id=f'seq_{_uuid.uuid4().hex[:10]}',
                    title='Suspicious Sequence: New SUID followed by IP forwarding enabled',
                    rationale='Heuristic: newly introduced SUID binary preceded enabling IP forwarding in same scan',
                    related_finding_ids=related,
                    risk_score_delta=8,
                    tags=['sequence_anomaly','routing','privilege_escalation_surface'],
                    severity='high'
                )
                state.correlations.append(corr)
                # Back-reference on findings
                for f in ordered:
                    if f.id in related:
                        if corr.id not in f.correlation_refs:
                            f.correlation_refs.append(corr.id)
    return state


def reduce(state: AgentState) -> AgentState:
    if not state.report:
        return state
    all_findings: List[Finding] = [f for r in state.report.results for f in r.findings]
    state.reductions = reduce_all(all_findings)
    return state


def summarize(state: AgentState) -> AgentState:
    client = LLMClient()
    cfg = load_config()
    threshold = cfg.thresholds.summarization_risk_sum
    high_med_sum = 0
    new_found = False
    all_findings = [f for r in state.report.results for f in r.findings] if state.report else []
    for f in all_findings:
        sev = f.severity.lower()
        if sev in {"medium","high","critical"}:
            high_med_sum += (f.risk_total or f.risk_score or 0)
        if any(t == 'baseline:new' for t in (f.tags or [])):
            new_found = True
    skip = (high_med_sum < threshold) and (not new_found)
    prev = getattr(state, 'summaries', None)
    state.summaries = client.summarize(state.reductions, state.correlations, state.actions, skip=skip, previous=prev, skip_reason="low_risk_no_change" if skip else None)
    # ATT&CK coverage computation
    try:
        mapping = _load_attack_mapping()
        if state.report and state.summaries:
            covered = {}
            all_tags = set()
            for r in state.report.results:
                for f in r.findings:
                    for t in (f.tags or []):
                        all_tags.add(t)
            for c in state.correlations:
                for t in (c.tags or []):
                    all_tags.add(t)
            techniques = set()
            tag_hits = {}
            for tag in all_tags:
                techs = mapping.get(tag)
                if not techs:
                    continue
                if isinstance(techs, list):
                    for tid in techs:
                        techniques.add(tid)
                elif isinstance(techs, str):
                    techniques.add(techs)
                tag_hits[tag] = techs
            state.summaries.attack_coverage = {
                'technique_count': len(techniques),
                'techniques': sorted(techniques),
                'tag_hits': tag_hits
            }
    except Exception as e:
        _log_error('attack_coverage', e)
    # Experimental causal hypotheses
    try:
        if state.summaries:
            state.summaries.causal_hypotheses = generate_causal_hypotheses(state)
    except Exception as e:
        _log_error('causal_hypotheses', e)
    return state


def actions(state: AgentState) -> AgentState:
    items: List[ActionItem] = []
    # Simple deterministic mapping examples
    for c in state.correlations:
        if "routing" in c.tags:
            items.append(ActionItem(priority=len(items)+1, action="Confirm intent for routing/NAT configuration; disable if not required.", correlation_refs=[c.id]))
    # Baseline noise example: if many SUID unexpected
    if state.reductions.suid_summary and state.reductions.suid_summary.get("unexpected_suid"):
        items.append(ActionItem(priority=len(items)+1, action="Review unexpected SUID binaries; remove SUID bit if unnecessary.", correlation_refs=[]))
    state.actions = items
    return state


def build_output(state: AgentState, raw_path: Path) -> EnrichedOutput:
    sha = hashlib.sha256(Path(raw_path).read_bytes()).hexdigest() if raw_path.exists() else None
    integrity_status = None
    try:
        # If verification key provided via env, attempt signature verification
        vkey = os.environ.get('AGENT_VERIFY_KEY_B64')
        if raw_path.exists():
            if vkey:
                integrity_status = verify_file(raw_path, vkey)
            else:
                # minimal status with sha only
                integrity_status = {'sha256_actual': sha}
    except Exception as e:
        _log_error('integrity_verify', e)
        integrity_status = {'sha256_actual': sha, 'error': 'integrity_check_failed'}
    flat_findings = []
    if state.report:
        for r in state.report.results:
            flat_findings.extend(r.findings)
    # Correlation graph metrics
    graph_meta = annotate_and_summarize(state)
    return EnrichedOutput(
        correlations=state.correlations,
        reductions=state.reductions,
        summaries=state.summaries,
        actions=state.actions,
        raw_reference=sha,
        enriched_findings=flat_findings,
        correlation_graph=graph_meta if graph_meta else None,
        followups=state.followups if state.followups else None,
    enrichment_results=state.enrichment_results or None,
    multi_host_correlation=state.multi_host_correlation or None,
    integrity=integrity_status
    )


# -----------------
# Optional External Corpus Integration (Hugging Face datasets)
# -----------------

def _augment_with_corpus_insights(state: AgentState):
    """Optionally load external cybersecurity corpora (if token & pandas available) to
    attach high-level corpus metrics to summaries.metrics for adaptive reasoning.

    Controlled by env AGENT_LOAD_HF_CORPUS=1. Lightweight: only counts / sample hash.
    Avoids loading if already present in metrics. Silent (logs on error)."""
    if not os.environ.get('AGENT_LOAD_HF_CORPUS'):
        return state
    try:
        from . import hf_loader  # lazy import
    except Exception as e:  # module absent
        _log_error('corpus_import', e)
        return state
    try:
        jsonl_df = hf_loader.load_cybersec_jsonl()
        parquet_df = hf_loader.load_cybersec_parquet()
        j_rows = int(len(jsonl_df)) if jsonl_df is not None else None
        p_rows = int(len(parquet_df)) if parquet_df is not None else None
        # Minimal content fingerprint (no sensitive data): column name hash
        import hashlib as _hl
        def _col_fprint(df):
            if df is None: return None
            h = _hl.sha256()
            for c in sorted(df.columns):
                h.update(c.encode())
            return h.hexdigest()[:16]
        metrics_add = {
            'corpus.jsonl_rows': j_rows,
            'corpus.parquet_rows': p_rows,
            'corpus.jsonl_schema_fprint': _col_fprint(jsonl_df),
            'corpus.parquet_schema_fprint': _col_fprint(parquet_df)
        }
        if state.summaries:
            base = state.summaries.metrics or {}
            # Do not overwrite existing keys unless None
            for k,v in metrics_add.items():
                if k not in base or base[k] is None:
                    base[k] = v
            state.summaries.metrics = base
    except Exception as e:
        _log_error('corpus_insights', e)
    return state


def generate_causal_hypotheses(state: AgentState, max_hypotheses: int = 3) -> list[dict]:
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
    drift_present = any('metric_drift' in (f.tags or []) for r in (state.report.results if state.report else []) for f in r.findings)
    routing_corr = any('routing' in c.tags for c in state.correlations)
    if drift_present and routing_corr:
        hyps.append({
            'id': f"hyp_{len(hyps)+1}",
            'summary': 'Configuration change likely triggered routing and risk metric drift',
            'rationale': ['metric drift finding plus routing-related correlation(s)'],
            'confidence': 'low',
            'speculative': True
        })
    # Deduplicate by summary, cap
    out = []
    seen = set()
    for h in hyps:
        if h['summary'] in seen: continue
        seen.add(h['summary'])
        out.append(h)
        if len(out) >= max_hypotheses:
            break
    return out


def _load_attack_mapping(path: Path = Path('agent/attack_mapping.yaml')) -> dict:
    try:
        if not path.exists():
            return {}
        data = _yaml.safe_load(path.read_text()) or {}
        return data
    except Exception:
        return {}


def run_pipeline(report_path: Path) -> EnrichedOutput:
    state = AgentState()
    state = load_report(state, report_path)
    try:
        log_stage('load_report', file=str(report_path), sha256=hashlib.sha256(report_path.read_bytes()).hexdigest())
    except Exception as e:
        _log_error('load_report_log', e)
    state = augment(state)
    # Policy enforcement (denylist executable paths)
    try:
        state = apply_policy(state)
        log_stage('policy_enforce')
    except Exception as e:
        _log_error('policy_enforce', e)
    try:
        log_stage('augment', findings=sum(len(r.findings) for r in (state.report.results if state.report else [])))
    except Exception as e:
        _log_error('augment_log', e)
    state = correlate(state)
    try:
        log_stage('correlate', correlations=len(state.correlations))
    except Exception as e:
        _log_error('correlate_log', e)
    # Temporal sequence correlations
    try:
        state = sequence_correlation(state)
        log_stage('sequence_correlation')
    except Exception as e:
        _log_error('sequence_correlation', e)
    state = baseline_rarity(state)
    try:
        log_stage('baseline_rarity')
    except Exception as e:
        _log_error('baseline_rarity_log', e)
    # Embedding-based process novelty
    try:
        state = process_novelty(state)
        log_stage('process_novelty')
    except Exception as e:
        _log_error('process_novelty', e)
    # Metric drift detection: derive simple metrics and record; synthesize findings if z>|threshold|
    if state.report and state.report.meta and state.report.meta.host_id and state.report.meta.scan_id:
        host_id = state.report.meta.host_id
        scan_id = state.report.meta.scan_id
        # Derive metrics (can expand later). Examples:
        # 1. total findings
        # 2. high severity count
        # 3. sum risk_total of medium+ severity
        all_findings = [f for r in state.report.results for f in r.findings]
        total_findings = len(all_findings)
        high_count = sum(1 for f in all_findings if f.severity.lower() in {"high","critical"})
        med_hi_risk_sum = sum((f.risk_total or f.risk_score or 0) for f in all_findings if f.severity.lower() in {"medium","high","critical"})
        metrics = {
            'finding.count.total': float(total_findings),
            'finding.count.high': float(high_count),
            'risk.sum.medium_high': float(med_hi_risk_sum)
        }
        store = BaselineStore(Path("agent_baseline.db"))
        metric_stats = store.record_metrics(host_id, scan_id, metrics, history_limit=10)
        # Lower initial thresholds: if history_n >=2 compute z; threshold 2.5; if no std yet use simple delta heuristic
        drift_threshold = 2.5
        drift_findings = []
        for mname, stats in metric_stats.items():
            z = stats.get('z')
            hist_n = stats.get('history_n',0)
            # Accept drift if enough history for z OR early large delta vs mean when hist>=2
            trigger = False
            if z is not None and hist_n >= 2 and abs(z) >= drift_threshold:
                trigger = True
            elif z is None and hist_n >= 2 and stats.get('mean') is not None:
                mean = stats['mean']; val = stats['value']
                # simple 100% increase heuristic
                if mean and (val - mean)/mean >= 1.0:
                    trigger = True
            if trigger:
                # Build synthetic finding
                fid = f"metric:{mname}:drift"
                z_for_sev = abs(z) if z is not None else 0
                from .risk import CAPS
                anomaly_cap = CAPS.get('anomaly', 2.0)
                raw_anom = (abs(z)/3.0) if z is not None else 1.0
                anomaly_val = min(anomaly_cap, raw_anom)
                drift = Finding(
                    id=fid,
                    title="Metric Drift Detected",
                    severity="medium" if z_for_sev < 5 else "high",
                    risk_score=0,
                    metadata={'metric': mname, 'z': z, 'value': stats['value'], 'mean': stats['mean'], 'std': stats['std']},
                    category='telemetry',
                    tags=['synthetic','metric_drift'],
                    risk_subscores={'impact': 3.0, 'exposure': 0.0, 'anomaly': anomaly_val, 'confidence': 0.9},
                    baseline_status='new',
                    metric_drift=stats
                )
                # compute risk for synthetic
                weights = load_persistent_weights()
                # risk_subscores is always set above
                score, raw = compute_risk(drift.risk_subscores or {}, weights)
                drift.risk_score = score
                drift.risk_total = score
                drift.probability_actionable = apply_probability(raw)
                if z is not None:
                    drift.rationale = [f"metric {mname} drift z={z:.2f} value={stats['value']} mean={stats['mean']:.2f} std={stats['std']:.2f}"]
                else:
                    drift.rationale = [f"metric {mname} early drift value={stats['value']} mean={stats['mean']:.2f} (delta >=100%)"]
                drift_findings.append(drift)
        if drift_findings:
            # Append to a synthetic scanner result so downstream logic sees them
            sr = ScannerResult(scanner='metric_drift', finding_count=len(drift_findings), findings=drift_findings)
            state.report.results.append(sr)
    state = reduce(state)
    try:
        log_stage('reduce', top_findings=len(state.reductions.top_findings))
    except Exception as e:
        _log_error('reduce_log', e)
    state = actions(state)
    try:
        log_stage('actions', actions=len(state.actions))
    except Exception as e:
        _log_error('actions_log', e)
    # Cross-host anomaly: module simultaneous emergence
    try:
        if state.report and state.report.results:
            store = BaselineStore(Path(os.environ.get('AGENT_BASELINE_DB','agent_baseline.db')))
            recent = store.recent_module_first_seen(within_seconds=86400)
            threshold = int(os.environ.get('PROPAGATION_HOST_THRESHOLD','3'))
            current_host = state.report.meta.host_id if state.report.meta else None  # reserved for future filtering
            for module, hosts in recent.items():
                if len(hosts) >= threshold:
                    corr = MultiHostCorrelation(type='module_propagation', key=module, host_ids=hosts, rationale=f"Module '{module}' first appeared on {len(hosts)} hosts within 24h window")
                    state.multi_host_correlation.append(corr)
                    fid = f"multi_host_module:{module}"
                    synth = Finding(
                        id=fid,
                        title=f"Potential Propagation: module {module}",
                        severity='medium',
                        risk_score=0,
                        metadata={'module': module, 'host_cluster_size': len(hosts)},
                        category='cross_host',
                        tags=['synthetic','cross_host','module_propagation'],
                        risk_subscores={'impact': 5.0, 'exposure': 0.0, 'anomaly': min(1.5, (__import__('agent.risk', fromlist=['CAPS']).CAPS.get('anomaly',2.0))), 'confidence': 0.8},
                        baseline_status='new'
                    )
                    _recompute_finding_risk(synth)
                    synth.rationale = [f"Module simultaneously observed on {len(hosts)} hosts (>= {threshold})"]
                    added = False
                    for sr in state.report.results:
                        if sr.scanner == 'multi_host':
                            sr.findings.append(synth)
                            sr.finding_count += 1
                            added = True
                            break
                    if not added:
                        state.report.results.append(ScannerResult(scanner='multi_host', finding_count=1, findings=[synth]))
    except Exception as e:
        _log_error('multi_host_correlation', e)
    # Follow-up planning/execution (deterministic gate)
    # Criteria: finding tagged ioc:development-tool and not allowlisted
    if state.report:
        for r in state.report.results:
            for f in r.findings:
                follow = False
                # Heuristic: mark certain IOC executables as development tools
                exe_path = f.metadata.get('exe') or ''
                if exe_path and any(tok in exe_path for tok in ['cpptools','python-env-tools']):
                    if 'ioc:development-tool' not in f.tags:
                        f.tags.append('ioc:development-tool')
                if any(t == 'ioc:development-tool' for t in (f.tags or [])) and not f.allowlist_reason:
                    follow = True
                if r.scanner.lower() == 'suid' and f.metadata.get('path'):
                    follow = True
                if follow:
                    plan = ["hash_binary", "query_package_manager"]
                    results = {}
                    bin_path = f.metadata.get('exe') or f.metadata.get('path')
                    if bin_path:
                        results['hash_binary'] = hash_binary(bin_path)
                        results['query_package_manager'] = query_package_manager(bin_path)
                    from .models import FollowupResult
                    state.followups.append(FollowupResult(finding_id=f.id, plan=plan, results=results))
                    try:
                        log_stage('followup_execute', finding_id=f.id, plan=";".join(plan))
                    except Exception as e:
                        _log_error('followup_execute', e)
    # Post follow-up aggregation / severity adjustments
    if state.followups and state.report:
        # Load trusted manifest
        trust_path = Path(__file__).parent / 'knowledge' / 'trusted_binaries.yaml'
        trusted = {}
        if trust_path.exists():
            try:
                trusted = yaml.safe_load(trust_path.read_text()) or {}
            except Exception as e:
                _log_error('trusted_manifest_load', e)
                trusted = {}
        trust_map = trusted.get('trusted', {})
        report_results = state.report.results or []
        # Build hash->(tool_key, downgrade) index for faster match & robustness
        hash_index = {}
        for tk, meta in trust_map.items():
            for hv in meta.get('sha256', []) or []:
                hash_index[hv] = (tk, meta.get('downgrade_severity_to'))
        for fu in state.followups:
            fobj = None
            for r in report_results:
                for f in r.findings:
                    if f.id == fu.finding_id:
                        fobj = f
                        break
                if fobj:
                    break
            state.enrichment_results.setdefault(fu.finding_id, fu.results)
            # Evaluate trust
            hdata = fu.results.get('hash_binary') or {}
            sha = hdata.get('sha256')
            if fobj and sha:
                # First, direct hash index lookup
                trust_entry = hash_index.get(sha)
                tool_key = None
                downgrade = None
                if trust_entry:
                    tool_key, downgrade = trust_entry
                else:
                    # Fallback heuristic by tool key substring present in path/title
                    title_lower = fobj.title.lower()
                    path_val = fobj.metadata.get('exe') or ''
                    if 'cpptools' in title_lower or 'cpptools' in path_val:
                        tool_key = 'cpptools'
                        meta = trust_map.get(tool_key) or {}
                        if sha in (meta.get('sha256') or []):
                            downgrade = meta.get('downgrade_severity_to')
                if tool_key and downgrade and downgrade != fobj.severity:
                    old = fobj.severity
                    fobj.severity = downgrade
                    if fobj.rationale:
                        fobj.rationale.append(f"trusted binary hash matched ({tool_key}); severity {old}->{downgrade}")
                    else:
                        fobj.rationale = [f"trusted binary hash matched ({tool_key}); severity {old}->{downgrade}"]
                    if 'trusted_binary' not in (fobj.tags or []):
                        fobj.tags.append('trusted_binary')
                    # Also add/update severity: tag list (not removing old to preserve provenance)
                    sev_tag = f"severity:{downgrade}"
                    if fobj.tags and sev_tag not in fobj.tags:
                        fobj.tags.append(sev_tag)
                    # Recompute risk if impact/exposure might depend on severity externally later
                    _recompute_finding_risk(fobj)
    state = summarize(state)
    # Optional external corpus insights after summaries produced
    state = _augment_with_corpus_insights(state)
    try:
        metrics = (state.summaries.metrics if state.summaries else {}) or {}
        log_stage('summarize', tokens_prompt=metrics.get('tokens_prompt'), tokens_completion=metrics.get('tokens_completion'))
    except Exception as e:
        _log_error('summarize_log', e)
    return build_output(state, report_path)


# -----------------
# Policy Layer
# -----------------

APPROVED_DEFAULT = ["/bin","/usr/bin","/usr/local/bin","/sbin","/usr/sbin","/opt/trusted"]
SEVERITY_ORDER = ["info","low","medium","high","critical"]

def _load_policy_allowlist() -> set[str]:
    import yaml
    paths: set[str] = set()
    # Config-based allowlist
    try:
        cfg = load_config()
        for p in cfg.paths.policy_allowlist:
            paths.add(p)
    except Exception:
        pass
    # File allowlist
    allow_file = Path('policy_allowlist.yaml')
    if allow_file.exists():
        try:
            data = yaml.safe_load(allow_file.read_text()) or {}
            for p in (data.get('allow_executables') or []):
                if isinstance(p, str):
                    paths.add(p)
        except Exception as e:
            _log_error('policy_allowlist_load', e)
    # Env variable (colon separated)
    import os as _os
    env_list = _os.environ.get('AGENT_POLICY_ALLOWLIST','')
    for part in env_list.split(':'):
        part = part.strip()
        if part:
            paths.add(part)
    return paths

def _approved_dirs() -> list[str]:
    import os as _os
    env_dirs = _os.environ.get('AGENT_APPROVED_DIRS')
    if env_dirs:
        return [d for d in (p.strip() for p in env_dirs.split(':')) if d]
    return APPROVED_DEFAULT

def apply_policy(state: AgentState) -> AgentState:
    if not state.report:
        return state
    allow = _load_policy_allowlist()
    approved = _approved_dirs()
    # Resolve approved dirs to absolute canonical paths
    approved_real = []
    for d in approved:
        try:
            approved_real.append(str(Path(d).resolve()))
        except Exception:
            approved_real.append(d)
    for sr in state.report.results:
        for f in sr.findings:
            exe = f.metadata.get('exe') if isinstance(f.metadata, dict) else None
            if not exe:
                continue
            # Already allowlisted
            if exe in allow:
                continue
            try:
                exe_real = str(Path(exe).resolve())
            except Exception:
                exe_real = exe
            in_approved = False
            for d in approved_real:
                try:
                    if os.path.commonpath([exe_real, d]) == d:
                        in_approved = True
                        break
                except Exception:
                    continue
            if not in_approved:
                # Escalate severity to at least high unless already critical
                try:
                    sev_idx = SEVERITY_ORDER.index(f.severity.lower()) if f.severity else 0
                except ValueError:
                    sev_idx = 0
                target = 'high'
                if f.severity.lower() != 'critical' and f.severity.lower() != target:
                    # Only raise if below target
                    if SEVERITY_ORDER.index(target) > sev_idx:
                        old = f.severity
                        f.severity = target
                        f.severity_source = 'policy'
                        if f.rationale:
                            f.rationale.append(f"policy escalation: executable outside approved dirs ({exe})")
                        else:
                            f.rationale = [f"policy escalation: executable outside approved dirs ({exe})"]
                        if f.tags is not None:
                            if 'policy:denied_path' not in f.tags:
                                f.tags.append('policy:denied_path')
                            sev_tag = f'severity:{target}'
                            if sev_tag not in f.tags:
                                f.tags.append(sev_tag)
                # risk_subscores impact bump (optional)
                if f.risk_subscores:
                    new_imp = min(10.0, (f.risk_subscores.get('impact',0)+1.0))
                    if new_imp != f.risk_subscores.get('impact'):
                        f.risk_subscores['impact'] = new_imp
                        _recompute_finding_risk(f)
    return state

