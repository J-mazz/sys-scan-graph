import json, os, tempfile, shutil
from pathlib import Path
from jsonschema import validate
from agent.cli import build_fleet_report
from agent.baseline import BaselineStore

# We directly invoke the function to generate a fleet report; baseline DB may be empty.

def test_fleet_report_schema_validation(tmp_path: Path):
    db = tmp_path/"baseline.db"
    # create empty baseline store (will have zero hosts)
    BaselineStore(db)  # initializes schema
    out = tmp_path/"fleet_report.json"
    # Force creation of metric table by recording a no-op metric
    store = BaselineStore(db)
    store.record_metrics(host_id="dummy_host", scan_id="init", metrics={})
    data = build_fleet_report(db, top_n=3, recent_seconds=3600, module_min_hosts=1)
    schema = json.loads(Path('schema/fleet_report.schema.json').read_text())
    validate(instance=data, schema=schema)
    assert 'generated_ts' in data
