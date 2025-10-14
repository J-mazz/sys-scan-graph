import json, os, tempfile, shutil
from pathlib import Path
from jsonschema import validate
import pytest
from sys_scan_agent.cli import build_fleet_report
from sys_scan_agent.baseline import BaselineStore

# We directly invoke the function to generate a fleet report; baseline DB may be empty.

def test_fleet_report_schema_validation(tmp_path: Path):
    db = tmp_path/"baseline.db"
    # create empty baseline store (will have zero hosts)
    store = BaselineStore(db)
    # Force creation of metric table by recording a no-op metric
    store.record_metrics(host_id="dummy_host", scan_id="init", metrics={})
    data = build_fleet_report(db, top_n=3, recent_seconds=3600, module_min_hosts=1)
    # Use absolute path to schema file
    schema_path = Path(__file__).parent.parent.parent / 'schema' / 'fleet_report.schema.json'
    schema = json.loads(schema_path.read_text())
    validate(instance=data, schema=schema)
    assert 'generated_ts' in data
    assert 'host_count' in data
    assert 'metric_mean' in data
    assert 'metric_std' in data
    assert 'top_outlier_hosts' in data
    assert 'newly_common_modules' in data
    assert 'risk_distribution' in data
