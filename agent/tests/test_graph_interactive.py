import pytest
from sys_scan_agent import graph


def test_build_workflow_accepts_interactive():
    # Ensure build_workflow accepts the 'interactive' keyword without raising a TypeError
    try:
        wf, app = graph.build_workflow(interactive=True)
    except TypeError as e:
        pytest.fail(f"build_workflow raised TypeError when called with interactive=True: {e}")
    # No further assertions; behaviour under optional dependencies is allowed to return (None, None)
