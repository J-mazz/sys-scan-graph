import sys
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).parent.parent.parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pathlib import Path
from agent.sys_scan_agent.cli import run_intelligence_workflow


def test_run_intelligence_includes_output_path(tmp_path):
    # Use a small dummy report file (empty JSON array) and pass explicit output_path
    report = tmp_path / "report.json"
    report.write_text('{"results": []}')

    out = tmp_path / "my_enriched.json"

    enriched, final_state = run_intelligence_workflow(report, output_path=out)

    assert final_state.get('output_path') == str(out)
