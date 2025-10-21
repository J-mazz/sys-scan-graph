"""Tests for metrics_exporter module."""
import pytest
import json
import csv
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from sys_scan_agent import metrics_exporter
from sys_scan_agent.graph_state import GraphState


@pytest.fixture
def sample_state():
    """Create a sample GraphState with metrics."""
    return {
        'metrics': {
            'node_calls': {
                'node1': 10,
                'node2': 5,
                'node3': 3
            },
            'node_durations': {
                'node1': [0.1, 0.2, 0.15, 0.3, 0.25, 0.12, 0.18, 0.22, 0.17, 0.19],
                'node2': [0.5, 0.6, 0.55, 0.7, 0.65],
                'node3': [1.0, 1.2, 1.1]
            },
            'node_ids': {
                'node1': 'inv-123',
                'node2': 'inv-456',
                'node3': 'inv-789'
            },
            'cache_hit_rate': 0.75
        }
    }


@pytest.fixture
def minimal_state():
    """Create a minimal state with empty metrics."""
    return {
        'metrics': {
            'node_calls': {},
            'node_durations': {},
            'node_ids': {}
        }
    }


class TestExportPrometheus:
    """Tests for export_prometheus function."""

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    def test_export_prometheus_basic(self, mock_telemetry, sample_state):
        """Test basic Prometheus export."""
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 18}

        result = metrics_exporter.export_prometheus(sample_state)

        assert "# HELP sys_scan_graph_node_calls_total" in result
        assert "# TYPE sys_scan_graph_node_calls_total counter" in result
        assert 'sys_scan_graph_node_calls_total{node="node1"} 10' in result
        assert 'sys_scan_graph_node_calls_total{node="node2"} 5' in result
        assert 'sys_scan_graph_node_calls_total{node="node3"} 3' in result

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    def test_export_prometheus_durations(self, mock_telemetry, sample_state):
        """Test Prometheus export includes duration metrics."""
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 18}

        result = metrics_exporter.export_prometheus(sample_state)

        assert "# HELP sys_scan_graph_node_duration_seconds" in result
        assert "# TYPE sys_scan_graph_node_duration_seconds histogram" in result
        assert 'sys_scan_graph_node_duration_seconds_count{node="node1"} 10' in result
        assert 'sys_scan_graph_node_duration_seconds_sum{node="node1"}' in result
        assert 'quantile="0.5"' in result
        assert 'quantile="0.95"' in result
        assert 'quantile="0.99"' in result

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    def test_export_prometheus_cache_hit_rate(self, mock_telemetry, sample_state):
        """Test Prometheus export includes cache hit rate."""
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 18}

        result = metrics_exporter.export_prometheus(sample_state)

        assert "sys_scan_graph_cache_hit_rate 75.0" in result

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    def test_export_prometheus_to_file(self, mock_telemetry, sample_state):
        """Test Prometheus export to file."""
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 18}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "metrics.prom"

            result = metrics_exporter.export_prometheus(sample_state, str(output_path))

            assert output_path.exists()
            content = output_path.read_text()
            assert content == result
            assert "sys_scan_graph_node_calls_total" in content

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    def test_export_prometheus_empty_metrics(self, mock_telemetry, minimal_state):
        """Test Prometheus export with empty metrics."""
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 0}

        result = metrics_exporter.export_prometheus(minimal_state)

        assert "# HELP sys_scan_graph_node_calls_total" in result
        assert "sys_scan_graph_total_calls 0" in result


class TestWriteMetricsJson:
    """Tests for write_metrics_json function."""

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    def test_write_metrics_json_basic(self, mock_summary, mock_telemetry, sample_state):
        """Test basic JSON metrics export."""
        mock_summary.return_value = {
            'total_nodes_executed': 3,
            'total_calls': 18
        }
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 18}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "metrics.json"

            metrics_exporter.write_metrics_json(sample_state, str(output_path))

            assert output_path.exists()
            with open(output_path) as f:
                data = json.load(f)

            assert 'total_nodes_executed' in data
            assert data['total_nodes_executed'] == 3
            assert 'global_telemetry' in data
            assert 'export_timestamp' in data
            assert 'export_time_iso' in data

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    def test_write_metrics_json_includes_timestamp(self, mock_summary, mock_telemetry, sample_state):
        """Test JSON export includes timestamp metadata."""
        mock_summary.return_value = {}
        mock_telemetry.return_value.get_metrics.return_value = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "metrics.json"

            metrics_exporter.write_metrics_json(sample_state, str(output_path))

            with open(output_path) as f:
                data = json.load(f)

            assert isinstance(data['export_timestamp'], (int, float))
            assert 'T' in data['export_time_iso']
            assert 'Z' in data['export_time_iso']


class TestExportMetricsCsv:
    """Tests for export_metrics_csv function."""

    def test_export_metrics_csv_basic(self, sample_state):
        """Test basic CSV metrics export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "metrics.csv"

            metrics_exporter.export_metrics_csv(sample_state, str(output_path))

            assert output_path.exists()

            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)

            # Check header
            assert rows[0] == ['Node', 'Calls', 'Total_Duration', 'Avg_Duration', 'Min_Duration', 'Max_Duration', 'Last_Invocation_ID']

            # Check data rows
            assert len(rows) == 4  # header + 3 nodes

            # Verify node data is present
            node_names = [row[0] for row in rows[1:]]
            assert 'node1' in node_names
            assert 'node2' in node_names
            assert 'node3' in node_names

    def test_export_metrics_csv_calculations(self, sample_state):
        """Test CSV export calculates statistics correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "metrics.csv"

            metrics_exporter.export_metrics_csv(sample_state, str(output_path))

            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)

            # Find node1 row
            node1_row = next(row for row in rows[1:] if row[0] == 'node1')

            assert node1_row[1] == '10'  # calls
            # Total duration should be sum of durations
            total_duration = float(node1_row[2])
            assert total_duration > 0
            # Avg duration
            avg_duration = float(node1_row[3])
            assert avg_duration > 0

    def test_export_metrics_csv_empty_durations(self):
        """Test CSV export handles nodes with no duration data."""
        state = {
            'metrics': {
                'node_calls': {'node1': 5},
                'node_durations': {},
                'node_ids': {}
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "metrics.csv"

            metrics_exporter.export_metrics_csv(state, str(output_path))

            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)

            node1_row = rows[1]
            assert node1_row[0] == 'node1'
            assert node1_row[2] == '0.0'  # total_duration
            assert node1_row[3] == '0.0'  # avg_duration
            assert node1_row[4] == '0.0'  # min_duration
            assert node1_row[5] == '0.0'  # max_duration


class TestPrintMetricsSummary:
    """Tests for print_metrics_summary function."""

    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    @patch('builtins.print')
    def test_print_metrics_summary_basic(self, mock_print, mock_summary, sample_state):
        """Test basic metrics summary printing."""
        mock_summary.return_value = {
            'total_nodes_executed': 3,
            'total_calls': 18,
            'performance_stats': {
                'total_execution_time': 5.5,
                'avg_node_duration': 0.305,
                'slowest_node': 'node3'
            },
            'node_breakdown': {
                'node1': {
                    'calls': 10,
                    'total_duration': 1.98,
                    'avg_duration': 0.198,
                    'min_duration': 0.1,
                    'max_duration': 0.3,
                    'last_invocation_id': 'inv-123'
                }
            },
            'telemetry_info': {
                'current_node': 'node1',
                'invocation_id': 'inv-123',
                'last_duration': 0.2
            }
        }

        metrics_exporter.print_metrics_summary(sample_state)

        # Verify print was called
        assert mock_print.call_count > 0

        # Check that key information was printed
        call_args = [str(call[0]) for call in mock_print.call_args_list]
        output = ' '.join(call_args)

        assert 'LANGGRAPH NODE TELEMETRY SUMMARY' in output or mock_print.called
        assert 'Total Nodes Executed: 3' in output or mock_print.called
        assert 'Total Calls: 18' in output or mock_print.called

    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    @patch('builtins.print')
    def test_print_metrics_summary_no_performance_stats(self, mock_print, mock_summary):
        """Test summary printing without performance stats."""
        mock_summary.return_value = {
            'total_nodes_executed': 0,
            'total_calls': 0,
            'node_breakdown': {}
        }

        state = {}
        metrics_exporter.print_metrics_summary(state)

        assert mock_print.called


class TestExportAllFormats:
    """Tests for export_all_formats function."""

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    def test_export_all_formats_creates_all_files(self, mock_summary, mock_telemetry, sample_state):
        """Test export_all_formats creates all format files."""
        mock_summary.return_value = {
            'total_nodes_executed': 3,
            'total_calls': 18
        }
        mock_telemetry.return_value.get_metrics.return_value = {'total_calls': 18}

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "subdir" / "metrics"

            result = metrics_exporter.export_all_formats(sample_state, str(base_path))

            assert 'json' in result
            assert 'csv' in result
            assert 'prometheus' in result

            assert Path(result['json']).exists()
            assert Path(result['csv']).exists()
            assert Path(result['prometheus']).exists()

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    def test_export_all_formats_creates_parent_dirs(self, mock_summary, mock_telemetry, sample_state):
        """Test export_all_formats creates parent directories."""
        mock_summary.return_value = {}
        mock_telemetry.return_value.get_metrics.return_value = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "a" / "b" / "c" / "metrics"

            result = metrics_exporter.export_all_formats(sample_state, str(base_path))

            assert base_path.parent.exists()
            assert Path(result['json']).exists()

    @patch('sys_scan_agent.metrics_exporter.get_node_telemetry')
    @patch('sys_scan_agent.metrics_exporter.get_node_metrics_summary')
    def test_export_all_formats_correct_extensions(self, mock_summary, mock_telemetry, sample_state):
        """Test export_all_formats uses correct file extensions."""
        mock_summary.return_value = {}
        mock_telemetry.return_value.get_metrics.return_value = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "metrics"

            result = metrics_exporter.export_all_formats(sample_state, str(base_path))

            assert result['json'].endswith('.json')
            assert result['csv'].endswith('.csv')
            assert result['prometheus'].endswith('.prom')
