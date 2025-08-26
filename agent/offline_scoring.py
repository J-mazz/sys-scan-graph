from __future__ import annotations
import json, math, argparse
from pathlib import Path
from typing import List, Dict, Tuple

Label = Dict[str, str]

def load_labels(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise SystemExit(f"Labels file not found: {path}")
    data = json.loads(path.read_text()) if path.suffix == '.json' else {}
    # Support simple TSV: finding_id<TAB>label
    if not data:
        labels: Dict[str,str] = {}
        for line in path.read_text().splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            fid, lab = line.split('\t')[:2]
            labels[fid]=lab.lower()
        return labels
    return {k:v.lower() for k,v in data.items()}

def collect_findings(enriched_paths: List[Path]) -> List[dict]:
    findings = []
    for p in enriched_paths:
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        for f in data.get('enriched_findings', []) or []:
            findings.append(f)
    return findings

def precision_at_k(findings: List[dict], labels: Dict[str,str], k: int) -> float:
    ranked = sorted(findings, key=lambda f: f.get('risk_total') or f.get('risk_score') or 0, reverse=True)
    top = ranked[:k]
    tp = 0
    denom = len(top) if top else 1
    for f in top:
        fid = f.get('id') or ''
        lab = labels.get(fid)
        if lab == 'tp':
            tp += 1
    return tp/denom

def roc_points(findings: List[dict], labels: Dict[str,str]) -> Tuple[List[Tuple[float,float]], float]:
    scored = []
    for f in findings:
        pid = f.get('probability_actionable')
        if pid is None:
            continue
        fid = f.get('id') or ''
        lab = labels.get(fid)
        if lab not in {'tp','fp'}:
            continue
        scored.append((pid, 1 if lab=='tp' else 0))
    if not scored:
        return [], float('nan')
    scored.sort(key=lambda x: x[0], reverse=True)
    P = sum(1 for _,y in scored if y==1)
    N = sum(1 for _,y in scored if y==0)
    if P==0 or N==0:
        return [], float('nan')
    points = []
    tp = fp = 0
    prev_score = None
    auc = 0.0
    prev_fpr = prev_tpr = 0.0
    for score, y in scored:
        if prev_score is not None and score != prev_score:
            tpr = tp / P
            fpr = fp / N
            # trapezoid area
            auc += (fpr - prev_fpr) * (tpr + prev_tpr) / 2
            points.append((fpr, tpr))
            prev_fpr, prev_tpr = fpr, tpr
        if y==1: tp +=1
        else: fp +=1
        prev_score = score
    # final point
    tpr = tp / P
    fpr = fp / N
    auc += (fpr - prev_fpr) * (tpr + prev_tpr) / 2
    points.append((fpr,tpr))
    return points, auc

def false_positive_reduction(findings: List[dict], labels: Dict[str,str]) -> Dict[str, float]:
    total_fp = sum(1 for f in findings if labels.get(f.get('id') or '')=='fp')
    remaining_fp = sum(1 for f in findings if labels.get(f.get('id') or '')=='fp' and not f.get('allowlist_reason'))
    reduction = (total_fp - remaining_fp) / total_fp if total_fp else 0.0
    return {"fp_total": total_fp, "fp_after_allowlist": remaining_fp, "reduction_pct": round(reduction*100,2)}

def main():
    ap = argparse.ArgumentParser(description='Offline scoring metrics')
    ap.add_argument('--enriched-dir', required=True, help='Directory containing enriched report JSON files')
    ap.add_argument('--labels', required=True, help='Labels file (JSON or TSV) with finding_id -> tp|fp')
    ap.add_argument('--k', type=int, default=20, help='K for precision@k')
    ap.add_argument('--out', default='offline_metrics.json')
    args = ap.parse_args()
    enr_dir = Path(args.enriched_dir)
    enriched_paths = [p for p in enr_dir.glob('*.json')]
    labels = load_labels(Path(args.labels))
    findings = collect_findings(enriched_paths)
    p_at_k = precision_at_k(findings, labels, args.k)
    roc, auc = roc_points(findings, labels)
    fp_red = false_positive_reduction(findings, labels)
    out_obj = {
        'precision_at_k': {f'k={args.k}': p_at_k},
        'roc_points': roc,
        'auc': auc,
        'false_positive_reduction': fp_red,
    'counts': {'findings': len(findings), 'labeled': sum(1 for f in findings if labels.get(f.get('id') or '') in {'tp','fp'})}
    }
    Path(args.out).write_text(json.dumps(out_obj, indent=2))
    print(json.dumps(out_obj, indent=2))

if __name__ == '__main__':
    main()
