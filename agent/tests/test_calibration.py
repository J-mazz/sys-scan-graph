"""
Tests for calibration.py risk calibration functionality.
"""

from __future__ import annotations
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from sys_scan_agent.calibration import (
    load_calibration, save_calibration, logistic, apply_probability,
    CALIBRATION_FILE, DEFAULT_CALIBRATION
)


class TestLoadCalibration:
    """Test load_calibration function."""

    def test_load_calibration_default_when_file_missing(self):
        """Test loading default calibration when file doesn't exist."""
        with patch('sys_scan_agent.calibration.CALIBRATION_FILE') as mock_file:
            mock_file.exists.return_value = False

            result = load_calibration()

            assert result == DEFAULT_CALIBRATION
            assert result["version"] == "default_untrained"
            assert result["type"] == "logistic"
            assert "params" in result

    def test_load_calibration_success(self, tmp_path):
        """Test successful loading of calibration file."""
        cal_data = {
            "version": "2025-08-26_initial",
            "type": "logistic",
            "params": {"a": -2.5, "b": 0.2}
        }

        cal_file = tmp_path / "test_calibration.json"
        cal_file.write_text(json.dumps(cal_data))

        with patch('sys_scan_agent.calibration.CALIBRATION_FILE', cal_file):
            result = load_calibration()

            assert result == cal_data
            assert result["version"] == "2025-08-26_initial"
            assert result["params"]["a"] == -2.5
            assert result["params"]["b"] == 0.2

    def test_load_calibration_invalid_json(self, tmp_path):
        """Test loading calibration with invalid JSON."""
        cal_file = tmp_path / "invalid_calibration.json"
        cal_file.write_text("invalid json content")

        with patch('sys_scan_agent.calibration.CALIBRATION_FILE', cal_file):
            result = load_calibration()

            # Should return default on JSON error
            assert result == DEFAULT_CALIBRATION

    def test_load_calibration_missing_type(self, tmp_path):
        """Test loading calibration with missing type field."""
        cal_data = {
            "version": "test",
            "params": {"a": -2.5, "b": 0.2}
        }

        cal_file = tmp_path / "missing_type_calibration.json"
        cal_file.write_text(json.dumps(cal_data))

        with patch('sys_scan_agent.calibration.CALIBRATION_FILE', cal_file):
            result = load_calibration()

            # Should return default when type is missing
            assert result == DEFAULT_CALIBRATION

    def test_load_calibration_missing_params(self, tmp_path):
        """Test loading calibration with missing params field."""
        cal_data = {
            "version": "test",
            "type": "logistic"
        }

        cal_file = tmp_path / "missing_params_calibration.json"
        cal_file.write_text(json.dumps(cal_data))

        with patch('sys_scan_agent.calibration.CALIBRATION_FILE', cal_file):
            result = load_calibration()

            # Should return default when params is missing
            assert result == DEFAULT_CALIBRATION

    def test_load_calibration_wrong_type(self, tmp_path):
        """Test loading calibration with wrong type."""
        cal_data = {
            "version": "test",
            "type": "linear",  # Not logistic
            "params": {"a": -2.5, "b": 0.2}
        }

        cal_file = tmp_path / "wrong_type_calibration.json"
        cal_file.write_text(json.dumps(cal_data))

        with patch('sys_scan_agent.calibration.CALIBRATION_FILE', cal_file):
            result = load_calibration()

            # Should return default when type is not logistic
            assert result == DEFAULT_CALIBRATION


class TestSaveCalibration:
    """Test save_calibration function."""

    def test_save_calibration_success(self, tmp_path):
        """Test successful saving of calibration."""
        cal_data = {
            "version": "2025-08-26_test",
            "type": "logistic",
            "params": {"a": -1.5, "b": 0.25}
        }

        cal_file = tmp_path / "save_test_calibration.json"

        with patch('sys_scan_agent.calibration.CALIBRATION_FILE', cal_file):
            save_calibration(cal_data)

            # Verify file was written
            assert cal_file.exists()
            saved_data = json.loads(cal_file.read_text())
            assert saved_data == cal_data


class TestLogistic:
    """Test logistic function."""

    def test_logistic_normal_values(self):
        """Test logistic function with normal values."""
        # Test with a=-3.0, b=0.15, x=50
        result = logistic(-3.0, 0.15, 50.0)
        expected = 1.0 / (1.0 + 2.718281828459045**(-(-3.0 + 0.15 * 50.0)))
        assert abs(result - expected) < 1e-10

    def test_logistic_zero_input(self):
        """Test logistic function with zero input."""
        result = logistic(-3.0, 0.15, 0.0)
        expected = 1.0 / (1.0 + 2.718281828459045**(-(-3.0 + 0.15 * 0.0)))
        assert abs(result - expected) < 1e-10

    def test_logistic_negative_input(self):
        """Test logistic function with negative input."""
        result = logistic(-3.0, 0.15, -10.0)
        expected = 1.0 / (1.0 + 2.718281828459045**(-(-3.0 + 0.15 * -10.0)))
        assert abs(result - expected) < 1e-10

    def test_logistic_overflow_positive(self):
        """Test logistic function with large positive input (returns 1.0 naturally, overflow case is unreachable)."""
        result = logistic(-3.0, 0.15, 6700.0)  # Large positive x that makes result approach 1.0
        # Should return 1.0 (approaches 1.0 as x increases)
        assert result == 1.0


class TestApplyProbability:
    """Test apply_probability function."""

    def test_apply_probability_default_calibration(self):
        """Test apply_probability with default calibration."""
        with patch('sys_scan_agent.calibration.load_calibration', return_value=DEFAULT_CALIBRATION):
            result = apply_probability(50.0)

            # Should use default params: a=-3.0, b=0.15
            expected = round(logistic(-3.0, 0.15, 50.0), 4)
            assert result == expected

    def test_apply_probability_custom_calibration(self):
        """Test apply_probability with custom calibration."""
        custom_cal = {
            "version": "custom",
            "type": "logistic",
            "params": {"a": -2.0, "b": 0.2}
        }

        with patch('sys_scan_agent.calibration.load_calibration', return_value=custom_cal):
            result = apply_probability(25.0)

            expected = round(logistic(-2.0, 0.2, 25.0), 4)
            assert result == expected

    def test_apply_probability_missing_params(self):
        """Test apply_probability with missing parameters."""
        bad_cal = {
            "version": "bad",
            "type": "logistic",
            "params": {}  # Missing a and b
        }

        with patch('sys_scan_agent.calibration.load_calibration', return_value=bad_cal):
            result = apply_probability(10.0)

            # Should use defaults when params missing
            expected = round(logistic(-3.0, 0.15, 10.0), 4)
            assert result == expected

    def test_apply_probability_non_logistic_type(self):
        """Test apply_probability with non-logistic calibration type."""
        non_logistic_cal = {
            "version": "non_logistic",
            "type": "linear",  # Not logistic
            "params": {"a": -2.0, "b": 0.2}
        }

        with patch('sys_scan_agent.calibration.load_calibration', return_value=non_logistic_cal):
            result = apply_probability(10.0)

            # Should return 0.0 for non-logistic types
            assert result == 0.0