import pytest
from pathlib import Path
from unittest.mock import patch, mock_open
import json
try:
    from sys_scan_agent import performance_baseline
    PERFORMANCE_BASELINE_AVAILABLE = True
except ImportError:
    PERFORMANCE_BASELINE_AVAILABLE = False
    performance_baseline = None


# Commented out because performance_baseline module does not exist
# @pytest.mark.skipif(not PERFORMANCE_BASELINE_AVAILABLE, reason="Performance baseline module not available")
# class TestPerformanceBaseline:
#     """Test performance baseline management utilities."""

#     def test_load_baseline_file_exists(self):
#         """Test loading baseline when file exists."""
#         mock_data = {"version": "1.0", "test": "data"}

#         with patch('performance_baseline.Path') as mock_path_class:
#             mock_path = mock_path_class.return_value
#             mock_path.exists.return_value = True

#             # Mock file opening and json loading
#             with patch('builtins.open', mock_open(read_data=json.dumps(mock_data))) as mock_file:
#                 result = performance_baseline.load_baseline("test.json")

#                 assert result == mock_data
#                 mock_path.exists.assert_called_once()
#                 mock_file.assert_called_once_with(mock_path, 'r')

#     def test_load_baseline_file_not_exists(self):
#         """Test loading baseline when file doesn't exist."""
#         with patch('performance_baseline.Path') as mock_path_class:
#             mock_path = mock_path_class.return_value
#             mock_path.exists.return_value = False

#             result = performance_baseline.load_baseline("nonexistent.json")

#             # Should return a copy of BASELINE_METRICS
#             assert result == performance_baseline.BASELINE_METRICS
#             assert result is not performance_baseline.BASELINE_METRICS  # Should be a copy
#             mock_path.exists.assert_called_once()

#     def test_load_baseline_default_path(self):
#         """Test loading baseline with default path."""
#         with patch('performance_baseline.Path') as mock_path_class:
#             mock_path = mock_path_class.return_value
#             mock_path.exists.return_value = False

#             import pytest
from pathlib import Path
from unittest.mock import patch, mock_open
import json
try:
    from sys_scan_agent import performance_baseline
    PERFORMANCE_BASELINE_AVAILABLE = True
except ImportError:
    PERFORMANCE_BASELINE_AVAILABLE = False
    performance_baseline = None


@pytest.mark.skipif(not PERFORMANCE_BASELINE_AVAILABLE, reason="Performance baseline module not available")
class TestPerformanceBaseline:
    """Test performance baseline management utilities."""

    def test_load_baseline_file_exists(self):
        """Test loading baseline when file exists."""
        mock_data = {"version": "1.0", "test": "data"}

        with patch('sys_scan_agent.performance_baseline.Path') as mock_path_class:
            mock_path = mock_path_class.return_value
            mock_path.exists.return_value = True

            # Mock file opening and json loading
            with patch('builtins.open', mock_open(read_data=json.dumps(mock_data))) as mock_file:
                result = performance_baseline.load_baseline("test.json")

                assert result == mock_data
                mock_path.exists.assert_called_once()
                mock_file.assert_called_once_with(mock_path, 'r')

    def test_load_baseline_file_not_exists(self):
        """Test loading baseline when file doesn't exist."""
        with patch('sys_scan_agent.performance_baseline.Path') as mock_path_class:
            mock_path = mock_path_class.return_value
            mock_path.exists.return_value = False

            result = performance_baseline.load_baseline("nonexistent.json")

            # Should return a copy of BASELINE_METRICS
            assert result == performance_baseline.BASELINE_METRICS
            assert result is not performance_baseline.BASELINE_METRICS  # Should be a copy
            mock_path.exists.assert_called_once()

    def test_load_baseline_default_path(self):
        """Test loading baseline with default path."""
        with patch('sys_scan_agent.performance_baseline.Path') as mock_path_class:
            mock_path = mock_path_class.return_value
            mock_path.exists.return_value = False

            result = performance_baseline.load_baseline()

            assert result == performance_baseline.BASELINE_METRICS
            # Should create Path with default path
            mock_path_class.assert_called_once_with("build/performance_baseline.json")

    @patch('sys_scan_agent.performance_baseline.datetime')
    def test_save_baseline(self, mock_datetime):
        """Test saving baseline to file."""
        mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"

        baseline_data = {"version": "1.0", "test": "data"}

        with patch('sys_scan_agent.performance_baseline.Path') as mock_path_class:
            mock_path = mock_path_class.return_value
            mock_parent = mock_path_class.return_value
            mock_path.parent = mock_parent

            with patch('builtins.open', mock_open()) as mock_file, \
                 patch('sys_scan_agent.performance_baseline.json.dump') as mock_json_dump:
                performance_baseline.save_baseline(baseline_data, "test.json")

                # Verify parent.mkdir was called
                mock_parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)

                # Verify file was opened for writing
                mock_file.assert_called_once_with(mock_path, 'w')

                # Verify json.dump was called with updated data
                mock_json_dump.assert_called_once()
                written_data = mock_json_dump.call_args[0][0]
                assert written_data["version"] == "1.0"
                assert written_data["test"] == "data"
                assert written_data["last_updated"] == "2024-01-01T12:00:00"

    @patch('sys_scan_agent.performance_baseline.datetime')
    def test_save_baseline_default_path(self, mock_datetime):
        """Test saving baseline with default path."""
        mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"

        with patch('sys_scan_agent.performance_baseline.Path') as mock_path_class:
            mock_path = mock_path_class.return_value
            mock_parent = mock_path_class.return_value
            mock_path.parent = mock_parent

            with patch('builtins.open', mock_open()):
                performance_baseline.save_baseline({"test": "data"})

                # Should use default path
                mock_path_class.assert_called_once_with("build/performance_baseline.json")

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_check_performance_regression_no_violations(self, mock_load_baseline):
        """Test performance regression check with no violations."""
        mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

        current_metrics = {
            'node_breakdown': {
                'enhanced_enrich_findings': {'avg_duration': 0.3, 'max_duration': 0.5}
            },
            'total_nodes_executed': 10,
            'cache_hit_rate': 0.5,
            'performance_stats': {'total_execution_time': 5.0}
        }

        result = performance_baseline.check_performance_regression(current_metrics)

        assert result['regression_detected'] == False
        assert len(result['violations']) == 0
        assert result['summary']['total_violations'] == 0
        assert result['summary']['nodes_analyzed'] == 1
        assert result['summary']['cache_hit_rate'] == 0.5
        assert result['summary']['total_execution_time'] == 5.0

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_check_performance_regression_duration_violation(self, mock_load_baseline):
        """Test detection of duration regression."""
        mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

        current_metrics = {
            'node_breakdown': {
                'enhanced_enrich_findings': {'avg_duration': 3.0, 'max_duration': 3.0}  # Much slower than expected max 1.0
            },
            'total_nodes_executed': 10,
            'cache_hit_rate': 0.5
        }

        result = performance_baseline.check_performance_regression(current_metrics)

        assert result['regression_detected'] == True
        assert len(result['violations']) == 1
        violation = result['violations'][0]
        assert violation['type'] == 'duration_regression'
        assert violation['node'] == 'enhanced_enrich_findings'
        assert violation['expected_max'] == 1.0
        assert violation['actual'] == 3.0
        assert violation['regression_factor'] == 3.0

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_check_performance_regression_node_count_violations(self, mock_load_baseline):
        """Test detection of node count violations."""
        mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

        # Test insufficient nodes
        current_metrics = {
            'node_breakdown': {},
            'total_nodes_executed': 5,  # Below minimum 8
            'cache_hit_rate': 0.5
        }

        result = performance_baseline.check_performance_regression(current_metrics)

        assert result['regression_detected'] == True
        assert len(result['violations']) == 1
        assert result['violations'][0]['type'] == 'insufficient_nodes'

        # Test excessive nodes
        current_metrics['total_nodes_executed'] = 20  # Above maximum 15

        result = performance_baseline.check_performance_regression(current_metrics)

        assert len(result['violations']) == 1
        assert result['violations'][0]['type'] == 'excessive_nodes'

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_check_performance_regression_cache_violation(self, mock_load_baseline):
        """Test detection of cache hit rate violation."""
        mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

        current_metrics = {
            'node_breakdown': {},
            'total_nodes_executed': 10,
            'cache_hit_rate': -0.1  # Below minimum 0.0
        }

        result = performance_baseline.check_performance_regression(current_metrics)

        assert result['regression_detected'] == True
        assert len(result['violations']) == 1
        assert result['violations'][0]['type'] == 'low_cache_hit_rate'

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_check_performance_regression_multiple_violations(self, mock_load_baseline):
        """Test detection of multiple types of violations."""
        mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

        current_metrics = {
            'node_breakdown': {
                'enhanced_enrich_findings': {'avg_duration': 3.0, 'max_duration': 3.0}
            },
            'total_nodes_executed': 5,  # Insufficient
            'cache_hit_rate': -0.1  # Low cache rate
        }

        result = performance_baseline.check_performance_regression(current_metrics)

        assert result['regression_detected'] == True
        assert len(result['violations']) == 3
        violation_types = {v['type'] for v in result['violations']}
        assert 'duration_regression' in violation_types
        assert 'insufficient_nodes' in violation_types
        assert 'low_cache_hit_rate' in violation_types

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_check_performance_regression_recommendations(self, mock_load_baseline):
        """Test that appropriate recommendations are generated."""
        mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

        current_metrics = {
            'node_breakdown': {
                'enhanced_enrich_findings': {'avg_duration': 3.0, 'max_duration': 3.0}
            },
            'total_nodes_executed': 5,
            'cache_hit_rate': 0.5
        }

        result = performance_baseline.check_performance_regression(current_metrics)

        assert len(result['recommendations']) >= 2
        assert any("regression" in rec.lower() for rec in result['recommendations'])
        assert any("optimizing" in rec.lower() for rec in result['recommendations'])

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    @patch('sys_scan_agent.performance_baseline.save_baseline')
    def test_update_baseline_from_metrics_new_node(self, mock_save_baseline, mock_load_baseline):
        """Test updating baseline with a new node."""
        baseline = performance_baseline.BASELINE_METRICS.copy()
        mock_load_baseline.return_value = baseline

        current_metrics = {
            'node_breakdown': {
                'new_node': {'avg_duration': 0.5, 'max_duration': 1.0}
            }
        }

        performance_baseline.update_baseline_from_metrics(current_metrics)

        # Verify save_baseline was called
        mock_save_baseline.assert_called_once()

        # Check that new node was added
        saved_baseline = mock_save_baseline.call_args[0][0]
        assert 'new_node' in saved_baseline['expected_node_durations']
        new_node_data = saved_baseline['expected_node_durations']['new_node']
        assert new_node_data['mean'] == 0.5
        assert new_node_data['max'] == 1.0

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    @patch('sys_scan_agent.performance_baseline.save_baseline')
    def test_update_baseline_from_metrics_existing_node(self, mock_save_baseline, mock_load_baseline):
        """Test updating baseline for existing node with smoothing."""
        baseline = performance_baseline.BASELINE_METRICS.copy()
        baseline['expected_node_durations']['enhanced_enrich_findings'] = {
            "mean": 0.5, "std": 0.1, "max": 1.0
        }
        mock_load_baseline.return_value = baseline

        current_metrics = {
            'node_breakdown': {
                'enhanced_enrich_findings': {'avg_duration': 0.7, 'max_duration': 1.2}
            }
        }

        performance_baseline.update_baseline_from_metrics(current_metrics, smoothing_factor=0.2)

        mock_save_baseline.assert_called_once()
        saved_baseline = mock_save_baseline.call_args[0][0]

        # Check exponential smoothing: (1-0.2)*0.5 + 0.2*0.7 = 0.8*0.5 + 0.2*0.7 = 0.4 + 0.14 = 0.54
        updated_node = saved_baseline['expected_node_durations']['enhanced_enrich_findings']
        assert abs(updated_node['mean'] - 0.54) < 0.001
        assert updated_node['max'] == 1.2  # Should take the higher max

    @patch('sys_scan_agent.performance_baseline.load_baseline')
    def test_update_baseline_from_metrics_custom_smoothing(self, mock_load_baseline):
        """Test updating baseline with custom smoothing factor."""
        baseline = performance_baseline.BASELINE_METRICS.copy()
        baseline['expected_node_durations']['enhanced_enrich_findings'] = {
            "mean": 1.0, "std": 0.1, "max": 1.0
        }
        mock_load_baseline.return_value = baseline

        current_metrics = {
            'node_breakdown': {
                'enhanced_enrich_findings': {'avg_duration': 0.5, 'max_duration': 0.8}
            }
        }

        with patch('sys_scan_agent.performance_baseline.save_baseline') as mock_save:
            performance_baseline.update_baseline_from_metrics(current_metrics, smoothing_factor=0.5)

            saved_baseline = mock_save.call_args[0][0]
            # With smoothing factor 0.5: (1-0.5)*1.0 + 0.5*0.5 = 0.75
            updated_mean = saved_baseline['expected_node_durations']['enhanced_enrich_findings']['mean']
            assert abs(updated_mean - 0.75) < 0.001

#             assert result == performance_baseline.BASELINE_METRICS
#             # Should create Path with default path
#             mock_path_class.assert_called_once_with("build/performance_baseline.json")

#     @patch('performance_baseline.datetime')
#     def test_save_baseline(self, mock_datetime):
#         """Test saving baseline to file."""
#         mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"

#         baseline_data = {"version": "1.0", "test": "data"}

#         with patch('performance_baseline.Path') as mock_path_class:
#             mock_path = mock_path_class.return_value
#             mock_parent = mock_path_class.return_value
#             mock_path.parent = mock_parent

#             with patch('builtins.open', mock_open()) as mock_file, \
#                  patch('performance_baseline.json.dump') as mock_json_dump:
#                 performance_baseline.save_baseline(baseline_data, "test.json")

#                 # Verify parent.mkdir was called
#                 mock_parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)

#                 # Verify file was opened for writing
#                 mock_file.assert_called_once_with(mock_path, 'w')

#                 # Verify json.dump was called with updated data
#                 mock_json_dump.assert_called_once()
#                 written_data = mock_json_dump.call_args[0][0]
#                 assert written_data["version"] == "1.0"
#                 assert written_data["test"] == "data"
#                 assert written_data["last_updated"] == "2024-01-01T12:00:00"

#     @patch('performance_baseline.datetime')
#     def test_save_baseline_default_path(self, mock_datetime):
#         """Test saving baseline with default path."""
#         mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"

#         with patch('performance_baseline.Path') as mock_path_class:
#             mock_path = mock_path_class.return_value
#             mock_parent = mock_path_class.return_value
#             mock_path.parent = mock_parent

#             with patch('builtins.open', mock_open()):
#                 performance_baseline.save_baseline({"test": "data"})

#                 # Should use default path
#                 mock_path_class.assert_called_once_with("build/performance_baseline.json")

#     @patch('performance_baseline.load_baseline')
#     def test_check_performance_regression_no_violations(self, mock_load_baseline):
#         """Test performance regression check with no violations."""
#         mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

#         current_metrics = {
#             'node_breakdown': {
#                 'enhanced_enrich_findings': {'avg_duration': 0.3, 'max_duration': 0.5}
#             },
#             'total_nodes_executed': 10,
#             'cache_hit_rate': 0.5,
#             'performance_stats': {'total_execution_time': 5.0}
#         }

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert result['regression_detected'] == False
#         assert len(result['violations']) == 0
#         assert result['summary']['total_violations'] == 0
#         assert result['summary']['nodes_analyzed'] == 1
#         assert result['summary']['cache_hit_rate'] == 0.5
#         assert result['summary']['total_execution_time'] == 5.0

#     @patch('performance_baseline.load_baseline')
#     def test_check_performance_regression_duration_violation(self, mock_load_baseline):
#         """Test detection of duration regression."""
#         mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

#         current_metrics = {
#             'node_breakdown': {
#                 'enhanced_enrich_findings': {'avg_duration': 3.0, 'max_duration': 3.0}  # Much slower than expected max 1.0
#             },
#             'total_nodes_executed': 10,
#             'cache_hit_rate': 0.5
#         }

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert result['regression_detected'] == True
#         assert len(result['violations']) == 1
#         violation = result['violations'][0]
#         assert violation['type'] == 'duration_regression'
#         assert violation['node'] == 'enhanced_enrich_findings'
#         assert violation['expected_max'] == 1.0
#         assert violation['actual'] == 3.0
#         assert violation['regression_factor'] == 3.0

#     @patch('performance_baseline.load_baseline')
#     def test_check_performance_regression_node_count_violations(self, mock_load_baseline):
#         """Test detection of node count violations."""
#         mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

#         # Test insufficient nodes
#         current_metrics = {
#             'node_breakdown': {},
#             'total_nodes_executed': 5,  # Below minimum 8
#             'cache_hit_rate': 0.5
#         }

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert result['regression_detected'] == True
#         assert len(result['violations']) == 1
#         assert result['violations'][0]['type'] == 'insufficient_nodes'

#         # Test excessive nodes
#         current_metrics['total_nodes_executed'] = 20  # Above maximum 15

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert len(result['violations']) == 1
#         assert result['violations'][0]['type'] == 'excessive_nodes'

#     @patch('performance_baseline.load_baseline')
#     def test_check_performance_regression_cache_violation(self, mock_load_baseline):
#         """Test detection of cache hit rate violation."""
#         mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

#         current_metrics = {
#             'node_breakdown': {},
#             'total_nodes_executed': 10,
#             'cache_hit_rate': -0.1  # Below minimum 0.0
#         }

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert result['regression_detected'] == True
#         assert len(result['violations']) == 1
#         assert result['violations'][0]['type'] == 'low_cache_hit_rate'

#     @patch('performance_baseline.load_baseline')
#     def test_check_performance_regression_multiple_violations(self, mock_load_baseline):
#         """Test detection of multiple types of violations."""
#         mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

#         current_metrics = {
#             'node_breakdown': {
#                 'enhanced_enrich_findings': {'avg_duration': 3.0, 'max_duration': 3.0}
#             },
#             'total_nodes_executed': 5,  # Insufficient
#             'cache_hit_rate': -0.1  # Low cache rate
#         }

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert result['regression_detected'] == True
#         assert len(result['violations']) == 3
#         violation_types = {v['type'] for v in result['violations']}
#         assert 'duration_regression' in violation_types
#         assert 'insufficient_nodes' in violation_types
#         assert 'low_cache_hit_rate' in violation_types

#     @patch('performance_baseline.load_baseline')
#     def test_check_performance_regression_recommendations(self, mock_load_baseline):
#         """Test that appropriate recommendations are generated."""
#         mock_load_baseline.return_value = performance_baseline.BASELINE_METRICS

#         current_metrics = {
#             'node_breakdown': {
#                 'enhanced_enrich_findings': {'avg_duration': 3.0, 'max_duration': 3.0}
#             },
#             'total_nodes_executed': 5,
#             'cache_hit_rate': 0.5
#         }

#         result = performance_baseline.check_performance_regression(current_metrics)

#         assert len(result['recommendations']) >= 2
#         assert any("regression" in rec.lower() for rec in result['recommendations'])
#         assert any("optimizing" in rec.lower() for rec in result['recommendations'])

#     @patch('performance_baseline.load_baseline')
#     @patch('performance_baseline.save_baseline')
#     def test_update_baseline_from_metrics_new_node(self, mock_save_baseline, mock_load_baseline):
#         """Test updating baseline with a new node."""
#         baseline = performance_baseline.BASELINE_METRICS.copy()
#         mock_load_baseline.return_value = baseline

#         current_metrics = {
#             'node_breakdown': {
#                 'new_node': {'avg_duration': 0.5, 'max_duration': 1.0}
#             }
#         }

#         performance_baseline.update_baseline_from_metrics(current_metrics)

#         # Verify save_baseline was called
#         mock_save_baseline.assert_called_once()

#         # Check that new node was added
#         saved_baseline = mock_save_baseline.call_args[0][0]
#         assert 'new_node' in saved_baseline['expected_node_durations']
#         new_node_data = saved_baseline['expected_node_durations']['new_node']
#         assert new_node_data['mean'] == 0.5
#         assert new_node_data['max'] == 1.0

#     @patch('performance_baseline.load_baseline')
#     @patch('performance_baseline.save_baseline')
#     def test_update_baseline_from_metrics_existing_node(self, mock_save_baseline, mock_load_baseline):
#         """Test updating baseline for existing node with smoothing."""
#         baseline = performance_baseline.BASELINE_METRICS.copy()
#         baseline['expected_node_durations']['enhanced_enrich_findings'] = {
#             "mean": 0.5, "std": 0.1, "max": 1.0
#         }
#         mock_load_baseline.return_value = baseline

#         current_metrics = {
#             'node_breakdown': {
#                 'enhanced_enrich_findings': {'avg_duration': 0.7, 'max_duration': 1.2}
#             }
#         }

#         performance_baseline.update_baseline_from_metrics(current_metrics, smoothing_factor=0.2)

#         mock_save_baseline.assert_called_once()
#         saved_baseline = mock_save_baseline.call_args[0][0]

#         # Check exponential smoothing: (1-0.2)*0.5 + 0.2*0.7 = 0.8*0.5 + 0.2*0.7 = 0.4 + 0.14 = 0.54
#         updated_node = saved_baseline['expected_node_durations']['enhanced_enrich_findings']
#         assert abs(updated_node['mean'] - 0.54) < 0.001
#         assert updated_node['max'] == 1.2  # Should take the higher max

#     @patch('performance_baseline.load_baseline')
#     def test_update_baseline_from_metrics_custom_smoothing(self, mock_load_baseline):
#         """Test updating baseline with custom smoothing factor."""
#         baseline = performance_baseline.BASELINE_METRICS.copy()
#         baseline['expected_node_durations']['enhanced_enrich_findings'] = {
#             "mean": 1.0, "std": 0.1, "max": 1.0
#         }
#         mock_load_baseline.return_value = baseline

#         current_metrics = {
#             'node_breakdown': {
#                 'enhanced_enrich_findings': {'avg_duration': 0.5, 'max_duration': 0.8}
#             }
#         }

#         with patch('performance_baseline.save_baseline') as mock_save:
#             performance_baseline.update_baseline_from_metrics(current_metrics, smoothing_factor=0.5)

#             saved_baseline = mock_save.call_args[0][0]
#             # With smoothing factor 0.5: (1-0.5)*1.0 + 0.5*0.5 = 0.75
#             updated_mean = saved_baseline['expected_node_durations']['enhanced_enrich_findings']['mean']
#             assert abs(updated_mean - 0.75) < 0.001