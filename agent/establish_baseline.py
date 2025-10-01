#!/usr/bin/env python3
"""
Establish Performance Baseline

Runs the intelligence workflow with real scanner data to establish a performance baseline
for detecting regressions in CI/CD pipelines.
"""

import json
import sys
import subprocess
import tempfile
from pathlib import Path
from sys_scan_graph_agent.cli import run_intelligence_workflow
from sys_scan_graph_agent.metrics_node import get_node_metrics_summary
from sys_scan_graph_agent.performance_baseline import update_baseline_from_metrics

def run_sys_scan(output_path: Path) -> bool:
    """Run sys-scan to generate real scanner data."""
    try:
        # Build the sys-scan command - use absolute path to sys-scan executable
        sys_scan_path = Path("/home/joseph-mazzini/sys-scan-graph/build/sys-scan")
        if not sys_scan_path.exists():
            print(f"❌ sys-scan executable not found at: {sys_scan_path}")
            return False

        cmd = [
            str(sys_scan_path),
            "--output", str(output_path),
            "--compact",  # Minified JSON for efficiency
            "--parallel",  # Run scanners in parallel for speed
            "--timings"   # Include timing information
        ]

        print(f"🔍 Running sys-scan: {' '.join(cmd)}")

        # Run sys-scan
        result = subprocess.run(
            cmd,
            cwd=Path("../../").resolve(),  # Run from project root
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode != 0:
            print(f"❌ sys-scan failed with exit code: {result.returncode}")
            print(f"stderr: {result.stderr}")
            return False

        # Verify output file was created and has content
        if not output_path.exists():
            print(f"❌ sys-scan output file not created: {output_path}")
            return False

        file_size = output_path.stat().st_size
        if file_size == 0:
            print(f"❌ sys-scan output file is empty: {output_path}")
            return False

        print(f"✅ sys-scan completed successfully, output: {file_size} bytes")
        return True

    except subprocess.TimeoutExpired:
        print("❌ sys-scan timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ Failed to run sys-scan: {e}")
        return False

def create_test_report():
    """Create a minimal test report for baseline establishment (fallback)."""
    return {
        "meta": {
            "hostname": "baseline-test-host",
            "host_id": "baseline_test_001",
            "scan_start": "2024-01-01T00:00:00Z",
            "scan_end": "2024-01-01T00:01:00Z"
        },
        "summary": {
            "finding_count_total": 5,
            "finding_count_emitted": 5,
            "risk_score_max": 85,
            "risk_score_sum": 250
        },
        "results": [
            {
                "scanner": "test_scanner",
                "finding_count": 5,
                "findings": [
                    {
                        "id": "test_finding_1",
                        "title": "Test SUID binary found",
                        "severity": "high",
                        "risk_score": 80,
                        "metadata": {
                            "path": "/usr/bin/test_suid",
                            "permissions": "4755"
                        },
                        "tags": ["suid", "privilege_escalation"]
                    },
                    {
                        "id": "test_finding_2",
                        "title": "Test world-writable file",
                        "severity": "medium",
                        "risk_score": 60,
                        "metadata": {
                            "path": "/tmp/test_world_writable",
                            "permissions": "666"
                        },
                        "tags": ["permissions", "world_writable"]
                    },
                    {
                        "id": "test_finding_3",
                        "title": "Test network service",
                        "severity": "low",
                        "risk_score": 40,
                        "metadata": {
                            "port": 22,
                            "service": "ssh",
                            "state": "open"
                        },
                        "tags": ["network", "service"]
                    },
                    {
                        "id": "test_finding_4",
                        "title": "Test unusual process",
                        "severity": "info",
                        "risk_score": 30,
                        "metadata": {
                            "pid": 1234,
                            "name": "test_process",
                            "cmdline": "/usr/bin/test_process --test"
                        },
                        "tags": ["process"]
                    },
                    {
                        "id": "test_finding_5",
                        "title": "Test configuration issue",
                        "severity": "medium",
                        "risk_score": 40,
                        "metadata": {
                            "config_file": "/etc/test.conf",
                            "issue": "weak_permissions"
                        },
                        "tags": ["configuration"]
                    }
                ]
            }
        ],
        "collection_warnings": [],
        "scanner_errors": []
    }

def establish_baseline():
    """Run workflow and establish performance baseline."""
    print("🚀 Establishing Performance Baseline")
    print("=" * 50)

    # Try to run sys-scan for real data, fallback to test data
    report_path = None
    use_real_data = False

    # Create temporary file for sys-scan output
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
        temp_report_path = Path(temp_file.name)

    try:
        print("🔍 Attempting to run sys-scan for real scanner data...")
        if run_sys_scan(temp_report_path):
            report_path = temp_report_path
            use_real_data = True
            print("✅ Using real scanner data from sys-scan")
        else:
            print("⚠️  sys-scan failed, falling back to test data")
            # Create test report as fallback
            test_report = create_test_report()
            temp_report_path.write_text(json.dumps(test_report, indent=2))
            report_path = temp_report_path
            use_real_data = False
            print("📝 Created fallback test report")

        print(f"📋 Report path: {report_path}")

        # Validate the report has some content
        if report_path.stat().st_size == 0:
            raise ValueError("Report file is empty")

        # Run the intelligence workflow
        print("⚙️  Running intelligence workflow...")
        enriched, final_state = run_intelligence_workflow(report_path)

        # Extract performance metrics
        print("📊 Extracting performance metrics...")
        metrics_summary = get_node_metrics_summary(final_state)

        # Display metrics
        print("\n📈 Performance Metrics Summary:")
        print(f"   Data source: {'Real sys-scan data' if use_real_data else 'Test data'}")
        print(f"   Total nodes executed: {metrics_summary['total_nodes_executed']}")
        print(f"   Total calls: {metrics_summary['total_calls']}")

        if metrics_summary.get('performance_stats'):
            perf_stats = metrics_summary['performance_stats']
            print(".2f")
            print(".2f")
            if perf_stats.get('slowest_node'):
                print(f"   Slowest node: {perf_stats['slowest_node']}")

        print("\n🔍 Node Breakdown:")
        for node_name, node_data in metrics_summary.get('node_breakdown', {}).items():
            print(f"   {node_name}:")
            print(f"     Calls: {node_data['calls']}")
            print(".3f")
            print(".3f")

        # Update baseline
        print("\n💾 Updating performance baseline...")
        update_baseline_from_metrics(metrics_summary)

        print("✅ Baseline established successfully!")
        print("   Baseline saved to: build/performance_baseline.json")

        # Verify baseline was created
        baseline_path = Path("build/performance_baseline.json")
        if baseline_path.exists():
            baseline_data = json.loads(baseline_path.read_text())
            print(f"   Baseline version: {baseline_data.get('version', 'unknown')}")
            print(f"   Expected nodes: {len(baseline_data.get('expected_node_durations', {}))}")
            print(f"   Last updated: {baseline_data.get('last_updated', 'unknown')}")

    except Exception as e:
        print(f"❌ Failed to establish baseline: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Clean up temporary file
        if temp_report_path.exists():
            temp_report_path.unlink()
            print(f"🧹 Cleaned up temporary report: {temp_report_path}")

    return True

if __name__ == "__main__":
    success = establish_baseline()
    sys.exit(0 if success else 1)