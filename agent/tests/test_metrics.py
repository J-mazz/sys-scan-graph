"""Tests for metrics module."""
import pytest
import json
import time
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open
from sys_scan_agent import metrics


@pytest.fixture
def collector():
    """Create a fresh MetricsCollector for each test."""
    return metrics.MetricsCollector()


@pytest.fixture(autouse=True)
def reset_global_collector():
    """Reset global collector before each test."""
    metrics._metrics_collector = None
    yield
    metrics._metrics_collector = None


class TestMetricsCollectorInit:
    """Tests for MetricsCollector initialization."""

    def test_init_creates_empty_metrics(self, collector):
        """Test MetricsCollector initializes with empty metrics."""
        assert collector.metrics == {}
        assert collector.start_times == {}

    def test_init_separate_instances(self):
        """Test separate instances have independent state."""
        collector1 = metrics.MetricsCollector()
        collector2 = metrics.MetricsCollector()

        collector1.incr('test', 5)

        assert collector1.metrics.get('test') == 5
        assert collector2.metrics.get('test') is None


class TestTimeStage:
    """Tests for time_stage context manager."""

    def test_time_stage_basic(self, collector):
        """Test time_stage records duration."""
        with collector.time_stage('test_stage'):
            time.sleep(0.01)

        assert 'test_stage' in collector.metrics
        assert len(collector.metrics['test_stage']) == 1
        assert collector.metrics['test_stage'][0] >= 0.01

    def test_time_stage_multiple_calls(self, collector):
        """Test time_stage accumulates multiple durations."""
        with collector.time_stage('repeated'):
            time.sleep(0.01)

        with collector.time_stage('repeated'):
            time.sleep(0.01)

        assert len(collector.metrics['repeated']) == 2
        assert all(t >= 0.01 for t in collector.metrics['repeated'])

    def test_time_stage_exception_still_records(self, collector):
        """Test time_stage records duration even on exception."""
        with pytest.raises(ValueError):
            with collector.time_stage('error_stage'):
                raise ValueError("test error")

        assert 'error_stage' in collector.metrics
        assert len(collector.metrics['error_stage']) == 1

    def test_time_stage_different_stages(self, collector):
        """Test time_stage tracks different stages separately."""
        with collector.time_stage('stage1'):
            time.sleep(0.01)

        with collector.time_stage('stage2'):
            time.sleep(0.01)

        assert 'stage1' in collector.metrics
        assert 'stage2' in collector.metrics
        assert len(collector.metrics['stage1']) == 1
        assert len(collector.metrics['stage2']) == 1


class TestIncr:
    """Tests for incr method."""

    def test_incr_new_metric(self, collector):
        """Test incr creates new counter."""
        collector.incr('new_counter')
        assert collector.metrics['new_counter'] == 1

    def test_incr_existing_metric(self, collector):
        """Test incr increments existing counter."""
        collector.incr('counter')
        collector.incr('counter')
        collector.incr('counter')

        assert collector.metrics['counter'] == 3

    def test_incr_custom_value(self, collector):
        """Test incr with custom increment value."""
        collector.incr('counter', 5)
        collector.incr('counter', 3)

        assert collector.metrics['counter'] == 8

    def test_incr_multiple_counters(self, collector):
        """Test incr tracks multiple independent counters."""
        collector.incr('counter1', 2)
        collector.incr('counter2', 3)
        collector.incr('counter1', 4)

        assert collector.metrics['counter1'] == 6
        assert collector.metrics['counter2'] == 3


class TestSnapshot:
    """Tests for snapshot method."""

    def test_snapshot_empty_collector(self, collector):
        """Test snapshot with no metrics."""
        snap = collector.snapshot()

        assert 'metrics' in snap
        assert 'timestamp' in snap
        assert 'total_stages' in snap
        assert snap['metrics'] == {}
        assert snap['total_stages'] == 0
        assert isinstance(snap['timestamp'], float)

    def test_snapshot_with_metrics(self, collector):
        """Test snapshot includes current metrics."""
        collector.incr('counter', 5)
        with collector.time_stage('stage'):
            pass

        snap = collector.snapshot()

        assert snap['metrics']['counter'] == 5
        assert 'stage' in snap['metrics']
        assert snap['total_stages'] == 2

    def test_snapshot_is_copy(self, collector):
        """Test snapshot returns a copy, not reference."""
        collector.incr('counter', 3)
        snap1 = collector.snapshot()

        collector.incr('counter', 2)
        snap2 = collector.snapshot()

        assert snap1['metrics']['counter'] == 3
        assert snap2['metrics']['counter'] == 5

    def test_snapshot_timestamp_increases(self, collector):
        """Test snapshot timestamp is current time."""
        snap1 = collector.snapshot()
        time.sleep(0.01)
        snap2 = collector.snapshot()

        assert snap2['timestamp'] > snap1['timestamp']


class TestLoadBaseline:
    """Tests for load_baseline class method."""

    def test_load_baseline_success(self):
        """Test load_baseline reads valid JSON file."""
        baseline_data = {'metrics': {'stage': 1.5}, 'timestamp': 123456}

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(baseline_data, f)
            temp_path = f.name

        try:
            result = metrics.MetricsCollector.load_baseline(temp_path)
            assert result == baseline_data
        finally:
            Path(temp_path).unlink()

    def test_load_baseline_file_not_found(self):
        """Test load_baseline returns None for missing file."""
        result = metrics.MetricsCollector.load_baseline('/nonexistent/path.json')
        assert result is None

    def test_load_baseline_invalid_json(self):
        """Test load_baseline returns None for invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('invalid json {]')
            temp_path = f.name

        try:
            result = metrics.MetricsCollector.load_baseline(temp_path)
            assert result is None
        finally:
            Path(temp_path).unlink()


class TestCompareToBaseline:
    """Tests for compare_to_baseline class method."""

    def test_compare_no_baseline(self):
        """Test compare_to_baseline with no baseline returns empty list."""
        current = {'metrics': {'stage': 1.5}}
        result = metrics.MetricsCollector.compare_to_baseline(current, None, 0.1)
        assert result == []

    def test_compare_no_regression(self):
        """Test compare_to_baseline with no regression."""
        current = {'metrics': {'stage': 1.0}}
        baseline = {'metrics': {'stage': 1.0}}

        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)
        assert result == []

    def test_compare_with_regression(self):
        """Test compare_to_baseline detects regression."""
        current = {'metrics': {'stage': 2.0}}
        baseline = {'metrics': {'stage': 1.0}}

        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)

        assert len(result) == 1
        assert result[0]['stage'] == 'stage'
        assert result[0]['current_time'] == 2.0
        assert result[0]['baseline_time'] == 1.0
        assert result[0]['regression_pct'] == 100.0

    def test_compare_within_threshold(self):
        """Test compare_to_baseline ignores regressions within threshold."""
        current = {'metrics': {'stage': 1.05}}
        baseline = {'metrics': {'stage': 1.0}}

        # 5% increase with 10% threshold
        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)
        assert result == []

    def test_compare_list_metrics(self):
        """Test compare_to_baseline handles list values (averages)."""
        current = {'metrics': {'stage': [2.0, 2.0, 2.0]}}
        baseline = {'metrics': {'stage': [1.0, 1.0, 1.0]}}

        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)

        assert len(result) == 1
        assert result[0]['current_time'] == 2.0
        assert result[0]['baseline_time'] == 1.0

    def test_compare_mixed_types(self):
        """Test compare_to_baseline handles mixed single/list values."""
        current = {'metrics': {'stage': [2.0, 2.0]}}
        baseline = {'metrics': {'stage': 1.0}}

        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)

        assert len(result) == 1
        assert result[0]['current_time'] == 2.0
        assert result[0]['baseline_time'] == 1.0

    def test_compare_empty_lists(self):
        """Test compare_to_baseline handles empty list values."""
        current = {'metrics': {'stage': []}}
        baseline = {'metrics': {'stage': []}}

        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)
        assert result == []

    def test_compare_missing_baseline_stage(self):
        """Test compare_to_baseline skips stages not in baseline."""
        current = {'metrics': {'new_stage': 2.0}}
        baseline = {'metrics': {'old_stage': 1.0}}

        result = metrics.MetricsCollector.compare_to_baseline(current, baseline, 0.1)
        assert result == []


class TestSaveBaseline:
    """Tests for save_baseline class method."""

    def test_save_baseline_success(self):
        """Test save_baseline writes JSON file."""
        snapshot = {'metrics': {'stage': 1.5}, 'timestamp': 123456}

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'baseline.json'

            metrics.MetricsCollector.save_baseline(str(path), snapshot)

            assert path.exists()
            with open(path) as f:
                saved = json.load(f)
            assert saved == snapshot

    def test_save_baseline_creates_directories(self):
        """Test save_baseline creates parent directories."""
        snapshot = {'metrics': {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'a' / 'b' / 'c' / 'baseline.json'

            metrics.MetricsCollector.save_baseline(str(path), snapshot)

            assert path.exists()

    def test_save_baseline_handles_errors_silently(self):
        """Test save_baseline doesn't raise on errors."""
        snapshot = {'metrics': {}}

        # Try to save to invalid path (should not raise)
        metrics.MetricsCollector.save_baseline('/invalid/path/file.json', snapshot)
        # If we get here, test passes (no exception raised)
        assert True


class TestReset:
    """Tests for reset method."""

    def test_reset_clears_metrics(self, collector):
        """Test reset clears all metrics."""
        collector.incr('counter', 5)
        with collector.time_stage('stage'):
            pass

        collector.reset()

        assert collector.metrics == {}

    def test_reset_allows_new_metrics(self, collector):
        """Test metrics can be added after reset."""
        collector.incr('old', 5)
        collector.reset()
        collector.incr('new', 3)

        assert 'old' not in collector.metrics
        assert collector.metrics['new'] == 3


class TestGlobalCollector:
    """Tests for global collector functions."""

    def test_get_metrics_collector_creates_instance(self):
        """Test get_metrics_collector creates global instance."""
        collector = metrics.get_metrics_collector()

        assert collector is not None
        assert isinstance(collector, metrics.MetricsCollector)

    def test_get_metrics_collector_returns_same_instance(self):
        """Test get_metrics_collector returns same instance."""
        collector1 = metrics.get_metrics_collector()
        collector2 = metrics.get_metrics_collector()

        assert collector1 is collector2

    def test_set_metrics_collector(self):
        """Test set_metrics_collector sets global instance."""
        custom_collector = metrics.MetricsCollector()
        custom_collector.incr('test', 42)

        metrics.set_metrics_collector(custom_collector)
        retrieved = metrics.get_metrics_collector()

        assert retrieved is custom_collector
        assert retrieved.metrics['test'] == 42

    def test_global_collector_state_persists(self):
        """Test global collector maintains state."""
        collector = metrics.get_metrics_collector()
        collector.incr('persistent', 10)

        # Get again and check state persisted
        same_collector = metrics.get_metrics_collector()
        assert same_collector.metrics['persistent'] == 10


class TestModuleExports:
    """Tests for module exports."""

    def test_module_has_all(self):
        """Test module defines __all__."""
        assert hasattr(metrics, '__all__')
        assert 'MetricsCollector' in metrics.__all__
        assert 'get_metrics_collector' in metrics.__all__
        assert 'set_metrics_collector' in metrics.__all__
