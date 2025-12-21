Evaluation Reports
==================
This directory stores synthetic attack detection evaluation outputs.

Workflow:
1. Add or update malicious fixture files under `agent/fixtures/malicious/`.
2. Define expected indicator titles or substrings in `agent/sys_scan_agent/evaluation.py` (`INJECTED_INDICATORS`).
3. Run the evaluator:

```bash
# Ensure `sys_scan_agent` is importable (for example, `pip install -e agent` in your active venv)
python -m sys_scan_agent.evaluation --fixtures compromised_dev_host --out evaluation/report.json
```

Exit Criteria:
- >90% of injected indicators must appear within `reductions.top_risks` for each evaluated fixture.
- Commit `evaluation/report.json` for release tagging to track historical detection rate.

CI Suggestion:
Add a job that runs the evaluator and fails if `overall_detection_rate < 0.9`.
