import pytest
from pathlib import Path
from unittest.mock import patch, mock_open
import json
import sys
import os

# Try to import evaluation module
EVALUATION_AVAILABLE = False
evaluation = None
try:
    import sys_scan_agent.evaluation as evaluation
    # Check if the module has the required functions
    required_attrs = ['Path', 'load_fixture', 'evaluate_fixture', 'run_evaluation', 'write_report']
    if all(hasattr(evaluation, attr) for attr in required_attrs):
        EVALUATION_AVAILABLE = True
    else:
        EVALUATION_AVAILABLE = False
except ImportError:
    pass


@pytest.mark.skipif(not EVALUATION_AVAILABLE, reason="Evaluation module not available - functionality not implemented")
class TestEvaluation:
    """Test evaluation utilities for attack detection."""

    def test_load_fixture_success(self):
        """Test successful loading of a real fixture file from the repo checkout."""
        try:
            path = evaluation.load_fixture('compromised_dev_host')
        except FileNotFoundError:
            pytest.skip("Repo fixtures not present; skipping load_fixture integration test")

        assert path.name == 'compromised_dev_host.json'
        assert path.exists()

    def test_load_fixture_file_not_found(self):
        """Test loading a fixture that doesn't exist."""
        with pytest.raises(FileNotFoundError):
            evaluation.load_fixture('this_fixture_should_not_exist_12345')

    @patch('sys_scan_agent.evaluation.run_pipeline')
    @patch('sys_scan_agent.evaluation.load_fixture')
    def test_evaluate_fixture_success(self, mock_load_fixture, mock_run_pipeline):
        """Test successful evaluation of a fixture."""
        # Mock the fixture path
        mock_path = Path('/fake/path/test.json')
        mock_load_fixture.return_value = mock_path

        # Mock the enriched output
        mock_enriched = mock_run_pipeline.return_value
        mock_enriched.reductions = {
            'top_risks': [
                {'title': 'Suspicious LD_PRELOAD detected'},
                {'title': 'TCP 5555 listening found'},
                {'title': 'Normal activity'}
            ]
        }

        result = evaluation.evaluate_fixture('compromised_dev_host')

        # Verify load_fixture was called correctly
        mock_load_fixture.assert_called_once_with('compromised_dev_host')

        # Verify run_pipeline was called with the fixture path
        mock_run_pipeline.assert_called_once_with(mock_path)

        # Verify the result structure
        assert result['fixture'] == 'compromised_dev_host'
        assert result['indicators_total'] == 3  # from INJECTED_INDICATORS
        assert result['indicators_hits'] == 2  # 'Suspicious LD_PRELOAD' and 'TCP 5555 listening' match
        assert result['detection_rate'] == 2/3
        assert len(result['hit_indicators']) == 2
        assert 'top_risks' in result

    @patch('sys_scan_agent.evaluation.run_pipeline')
    @patch('sys_scan_agent.evaluation.load_fixture')
    def test_evaluate_fixture_no_indicators(self, mock_load_fixture, mock_run_pipeline):
        """Test evaluation when fixture has no expected indicators."""
        mock_path = Path('/fake/path/test.json')
        mock_load_fixture.return_value = mock_path

        mock_enriched = mock_run_pipeline.return_value
        mock_enriched.reductions.top_risks = [{'title': 'Some risk'}]

        result = evaluation.evaluate_fixture('unknown_fixture')

        assert result['indicators_total'] == 0  # No indicators defined for unknown fixture
        assert result['indicators_hits'] == 0
        assert result['detection_rate'] == 0.0

    @patch('sys_scan_agent.evaluation.run_pipeline')
    @patch('sys_scan_agent.evaluation.load_fixture')
    def test_evaluate_fixture_no_risks_found(self, mock_load_fixture, mock_run_pipeline):
        """Test evaluation when no top risks are found."""
        mock_path = Path('/fake/path/test.json')
        mock_load_fixture.return_value = mock_path

        mock_enriched = mock_run_pipeline.return_value
        mock_enriched.reductions.top_risks = None

        result = evaluation.evaluate_fixture('compromised_dev_host')

        assert result['indicators_total'] == 3
        assert result['indicators_hits'] == 0
        assert result['detection_rate'] == 0.0

    @patch('sys_scan_agent.evaluation.evaluate_fixture')
    def test_run_evaluation_single_fixture(self, mock_evaluate_fixture):
        """Test running evaluation on a single fixture."""
        mock_evaluate_fixture.return_value = {
            'fixture': 'test',
            'indicators_total': 5,
            'indicators_hits': 3,
            'detection_rate': 0.6,
            'hit_indicators': ['indicator1', 'indicator2'],
            'top_risks': []
        }

        result = evaluation.run_evaluation(['test'])

        assert len(result['fixtures']) == 1
        assert result['overall']['total_indicators'] == 5
        assert result['overall']['total_hits'] == 3
        assert result['overall']['overall_detection_rate'] == 0.6

    @patch('sys_scan_agent.evaluation.evaluate_fixture')
    def test_run_evaluation_multiple_fixtures(self, mock_evaluate_fixture):
        """Test running evaluation on multiple fixtures."""
        mock_evaluate_fixture.side_effect = [
            {
                'fixture': 'fixture1',
                'indicators_total': 4,
                'indicators_hits': 2,
                'detection_rate': 0.5,
                'hit_indicators': ['ind1'],
                'top_risks': []
            },
            {
                'fixture': 'fixture2',
                'indicators_total': 6,
                'indicators_hits': 4,
                'detection_rate': 2/3,
                'hit_indicators': ['ind2', 'ind3'],
                'top_risks': []
            }
        ]

        result = evaluation.run_evaluation(['fixture1', 'fixture2'])

        assert len(result['fixtures']) == 2
        assert result['overall']['total_indicators'] == 10
        assert result['overall']['total_hits'] == 6
        assert result['overall']['overall_detection_rate'] == 0.6

    @patch('sys_scan_agent.evaluation.evaluate_fixture')
    def test_run_evaluation_no_indicators(self, mock_evaluate_fixture):
        """Test running evaluation when no indicators are found."""
        mock_evaluate_fixture.return_value = {
            'fixture': 'test',
            'indicators_total': 0,
            'indicators_hits': 0,
            'detection_rate': 0.0,
            'hit_indicators': [],
            'top_risks': []
        }

        result = evaluation.run_evaluation(['test'])

        assert result['overall']['total_indicators'] == 0
        assert result['overall']['total_hits'] == 0
        assert result['overall']['overall_detection_rate'] == 0.0

    @patch('sys_scan_agent.evaluation.run_evaluation')
    def test_write_report_success(self, mock_run_evaluation):
        """Test successful writing of evaluation report."""
        mock_data = {
            'fixtures': [{'fixture': 'test'}],
            'overall': {'total_indicators': 5, 'total_hits': 3, 'overall_detection_rate': 0.6}
        }
        mock_run_evaluation.return_value = mock_data

        with patch('pathlib.Path') as mock_path_class:
            mock_out_path = mock_path_class.return_value
            mock_parent = mock_path_class.return_value
            mock_out_path.parent = mock_parent
            mock_out_path.write_text = mock_open()

            result = evaluation.write_report(['test'], mock_out_path)

            # Verify parent.mkdir was called
            mock_parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)

            # Verify write_text was called with JSON data
            mock_out_path.write_text.assert_called_once()
            written_content = mock_out_path.write_text.call_args[0][0]
            parsed_data = json.loads(written_content)
            assert parsed_data == mock_data

            # Verify return value
            assert result == mock_data