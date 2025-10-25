"""Tests for risk module."""
import pytest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from sys_scan_agent import risk


@pytest.fixture(autouse=True)
def clean_weights_file():
    """Remove weights file before and after each test."""
    if risk.WEIGHTS_FILE.exists():
        risk.WEIGHTS_FILE.unlink()
    yield
    if risk.WEIGHTS_FILE.exists():
        risk.WEIGHTS_FILE.unlink()


@pytest.fixture(autouse=True)
def clean_env_vars():
    """Clean environment variables before each test."""
    env_vars = ['RISK_W_IMPACT', 'RISK_W_EXPOSURE', 'RISK_W_ANOMALY']
    original_values = {k: os.environ.get(k) for k in env_vars}

    # Clean env vars
    for var in env_vars:
        if var in os.environ:
            del os.environ[var]

    yield

    # Restore original values
    for var in env_vars:
        if original_values[var] is not None:
            os.environ[var] = original_values[var]
        elif var in os.environ:
            del os.environ[var]


class TestConstants:
    """Tests for module constants."""

    def test_default_weights(self):
        """Test DEFAULT_WEIGHTS contains expected values."""
        assert 'impact' in risk.DEFAULT_WEIGHTS
        assert 'exposure' in risk.DEFAULT_WEIGHTS
        assert 'anomaly' in risk.DEFAULT_WEIGHTS
        assert risk.DEFAULT_WEIGHTS['impact'] == 5.0
        assert risk.DEFAULT_WEIGHTS['exposure'] == 3.0
        assert risk.DEFAULT_WEIGHTS['anomaly'] == 2.0

    def test_caps(self):
        """Test CAPS contains expected maximum values."""
        assert 'impact' in risk.CAPS
        assert 'exposure' in risk.CAPS
        assert 'anomaly' in risk.CAPS
        assert risk.CAPS['impact'] == 10.0
        assert risk.CAPS['exposure'] == 3.0
        assert risk.CAPS['anomaly'] == 2.0


class TestLoadPersistentWeights:
    """Tests for load_persistent_weights function."""

    def test_load_defaults_no_file_no_env(self):
        """Test load_persistent_weights returns defaults when no file or env."""
        weights = risk.load_persistent_weights()

        assert weights == risk.DEFAULT_WEIGHTS

    def test_load_from_file(self):
        """Test load_persistent_weights reads from JSON file."""
        custom_weights = {'impact': 10.0, 'exposure': 5.0, 'anomaly': 3.0}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(custom_weights))
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            weights = risk.load_persistent_weights()
            assert weights['impact'] == 10.0
            assert weights['exposure'] == 5.0
            assert weights['anomaly'] == 3.0
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)

    def test_load_from_file_partial(self):
        """Test load_persistent_weights uses defaults for missing keys."""
        partial_weights = {'impact': 8.0}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(partial_weights))
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            weights = risk.load_persistent_weights()
            assert weights['impact'] == 8.0
            assert weights['exposure'] == risk.DEFAULT_WEIGHTS['exposure']
            assert weights['anomaly'] == risk.DEFAULT_WEIGHTS['anomaly']
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)

    def test_load_from_file_invalid_json(self):
        """Test load_persistent_weights returns defaults on invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('invalid json {]')
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            weights = risk.load_persistent_weights()
            assert weights == risk.DEFAULT_WEIGHTS
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)

    def test_load_from_env_vars(self):
        """Test load_persistent_weights reads from environment variables."""
        os.environ['RISK_W_IMPACT'] = '7.0'
        os.environ['RISK_W_EXPOSURE'] = '4.0'
        os.environ['RISK_W_ANOMALY'] = '1.5'

        weights = risk.load_persistent_weights()

        assert weights['impact'] == 7.0
        assert weights['exposure'] == 4.0
        assert weights['anomaly'] == 1.5

    def test_load_from_env_partial(self):
        """Test load_persistent_weights with partial env vars."""
        os.environ['RISK_W_IMPACT'] = '9.0'

        weights = risk.load_persistent_weights()

        assert weights['impact'] == 9.0
        assert weights['exposure'] == risk.DEFAULT_WEIGHTS['exposure']
        assert weights['anomaly'] == risk.DEFAULT_WEIGHTS['anomaly']

    def test_load_from_env_invalid_value(self):
        """Test load_persistent_weights ignores invalid env values."""
        os.environ['RISK_W_IMPACT'] = 'not_a_number'
        os.environ['RISK_W_EXPOSURE'] = '6.0'

        weights = risk.load_persistent_weights()

        assert weights['impact'] == risk.DEFAULT_WEIGHTS['impact']  # Invalid, uses default
        assert weights['exposure'] == 6.0

    def test_file_takes_precedence_over_env(self):
        """Test file takes precedence over environment variables."""
        custom_weights = {'impact': 15.0}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(custom_weights))
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            with patch.dict(os.environ, {'SYS_SCAN_RISK_WEIGHTS': json.dumps({'impact': 20.0})}):
                weights = risk.load_persistent_weights()
                assert weights['impact'] == 15.0  # File should win
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)


class TestSavePersistentWeights:
    """Tests for save_persistent_weights function."""

    def test_save_weights_creates_file(self):
        """Test save_persistent_weights creates JSON file."""
        custom_weights = {'impact': 12.0, 'exposure': 8.0, 'anomaly': 4.0}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            risk.save_persistent_weights(custom_weights)
            assert temp_path.exists()
            saved_data = json.loads(temp_path.read_text())
            assert saved_data == custom_weights
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)

    def test_save_weights_overwrites_existing(self):
        """Test save_persistent_weights overwrites existing file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps({'impact': 1.0}))
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            new_weights = {'impact': 20.0, 'exposure': 15.0, 'anomaly': 10.0}
            risk.save_persistent_weights(new_weights)
            saved_data = json.loads(temp_path.read_text())
            assert saved_data == new_weights
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)

    def test_save_weights_formatted(self):
        """Test save_persistent_weights creates formatted JSON."""
        weights = {'impact': 5.0, 'exposure': 3.0, 'anomaly': 2.0}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            risk.save_persistent_weights(weights)
            content = temp_path.read_text()
            # Should have indentation (formatted)
            assert '\n' in content
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)


class TestComputeRisk:
    """Tests for compute_risk function."""

    def test_compute_risk_basic(self):
        """Test compute_risk with basic subscores."""
        subscores = {
            'impact': 5.0,
            'exposure': 2.0,
            'anomaly': 1.0,
            'confidence': 1.0
        }
        weights = {'impact': 5.0, 'exposure': 3.0, 'anomaly': 2.0}

        score, raw = risk.compute_risk(subscores, weights)

        # Raw = 5*5 + 2*3 + 1*2 = 25 + 6 + 2 = 33
        # Max = 10*5 + 3*3 + 2*2 = 50 + 9 + 4 = 63
        # Scaled = (33/63) * 100 = 52.38
        # Final = round(52.38 * 1.0) = 52
        assert score == 52
        assert raw == 33.0

    def test_compute_risk_with_confidence(self):
        """Test compute_risk applies confidence multiplier."""
        subscores = {
            'impact': 10.0,
            'exposure': 3.0,
            'anomaly': 2.0,
            'confidence': 0.5
        }
        weights = {'impact': 5.0, 'exposure': 3.0, 'anomaly': 2.0}

        score, raw = risk.compute_risk(subscores, weights)

        # Raw = 10*5 + 3*3 + 2*2 = 63
        # Scaled = (63/63) * 100 = 100
        # Final with confidence = round(100 * 0.5) = 50
        assert score == 50
        assert raw == 63.0

    def test_compute_risk_zero_subscores(self):
        """Test compute_risk with zero subscores."""
        subscores = {
            'impact': 0.0,
            'exposure': 0.0,
            'anomaly': 0.0,
            'confidence': 1.0
        }
        weights = risk.DEFAULT_WEIGHTS

        score, raw = risk.compute_risk(subscores, weights)

        assert score == 0
        assert raw == 0.0

    def test_compute_risk_missing_subscores(self):
        """Test compute_risk handles missing subscores."""
        subscores = {'impact': 5.0}  # Missing exposure, anomaly
        weights = risk.DEFAULT_WEIGHTS

        score, raw = risk.compute_risk(subscores, weights)

        # Should default missing to 0
        assert raw == 5.0 * weights['impact']
        assert score >= 0

    def test_compute_risk_missing_confidence(self):
        """Test compute_risk defaults confidence to 1.0."""
        subscores = {'impact': 5.0, 'exposure': 2.0, 'anomaly': 1.0}
        weights = risk.DEFAULT_WEIGHTS

        score, raw = risk.compute_risk(subscores, weights)

        # Should use confidence = 1.0
        assert score >= 0

    def test_compute_risk_loads_weights_if_none(self):
        """Test compute_risk loads persistent weights when weights=None."""
        custom_weights = {'impact': 10.0, 'exposure': 5.0, 'anomaly': 3.0}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            risk.save_persistent_weights(custom_weights)
            subscores = {'impact': 5.0, 'exposure': 2.0, 'anomaly': 1.0, 'confidence': 1.0}
            score, raw = risk.compute_risk(subscores, weights=None)
            # Should use custom weights
            expected_raw = 5.0*10.0 + 2.0*5.0 + 1.0*3.0
            assert raw == expected_raw
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)

    def test_compute_risk_caps_at_100(self):
        """Test compute_risk caps score at 100."""
        subscores = {
            'impact': 100.0,  # Unrealistically high
            'exposure': 100.0,
            'anomaly': 100.0,
            'confidence': 1.0
        }
        weights = {'impact': 100.0, 'exposure': 100.0, 'anomaly': 100.0}

        score, raw = risk.compute_risk(subscores, weights)

        assert score == 100

    def test_compute_risk_floors_at_0(self):
        """Test compute_risk floors score at 0."""
        subscores = {
            'impact': -10.0,  # Negative values
            'exposure': -5.0,
            'anomaly': -2.0,
            'confidence': 1.0
        }
        weights = risk.DEFAULT_WEIGHTS

        score, raw = risk.compute_risk(subscores, weights)

        assert score == 0

    def test_compute_risk_custom_weights(self):
        """Test compute_risk with custom weights."""
        subscores = {'impact': 5.0, 'exposure': 2.0, 'anomaly': 1.0, 'confidence': 1.0}
        custom_weights = {'impact': 10.0, 'exposure': 1.0, 'anomaly': 1.0}

        score, raw = risk.compute_risk(subscores, custom_weights)

        # Raw = 5*10 + 2*1 + 1*1 = 50 + 2 + 1 = 53
        assert raw == 53.0


class TestDescribe:
    """Tests for describe function."""

    def test_describe_with_defaults(self):
        """Test describe returns default weights and max_raw."""
        result = risk.describe()

        assert result['impact'] == risk.DEFAULT_WEIGHTS['impact']
        assert result['exposure'] == risk.DEFAULT_WEIGHTS['exposure']
        assert result['anomaly'] == risk.DEFAULT_WEIGHTS['anomaly']
        assert '_max_raw' in result

    def test_describe_calculates_max_raw(self):
        """Test describe calculates correct _max_raw."""
        weights = {'impact': 5.0, 'exposure': 3.0, 'anomaly': 2.0}

        result = risk.describe(weights)

        expected_max = 10.0*5.0 + 3.0*3.0 + 2.0*2.0  # 50 + 9 + 4 = 63
        assert result['_max_raw'] == expected_max

    def test_describe_with_custom_weights(self):
        """Test describe with custom weights."""
        custom_weights = {'impact': 10.0, 'exposure': 5.0, 'anomaly': 3.0}

        result = risk.describe(custom_weights)

        assert result['impact'] == 10.0
        assert result['exposure'] == 5.0
        assert result['anomaly'] == 3.0

    def test_describe_loads_persistent_if_none(self):
        """Test describe loads persistent weights when weights=None."""
        custom_weights = {'impact': 8.0, 'exposure': 4.0, 'anomaly': 2.5}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        original = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            risk.save_persistent_weights(custom_weights)
            result = risk.describe(weights=None)
            assert result['impact'] == 8.0
            assert result['exposure'] == 4.0
            assert result['anomaly'] == 2.5
        finally:
            risk.WEIGHTS_FILE = original
            temp_path.unlink(missing_ok=True)


class TestIntegration:
    """Integration tests for risk module."""

    def test_save_load_roundtrip(self):
        """Test saving and loading weights maintains values."""
        original = {'impact': 7.5, 'exposure': 4.5, 'anomaly': 2.5}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        orig = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            risk.save_persistent_weights(original)
            loaded = risk.load_persistent_weights()
            assert loaded == original
        finally:
            risk.WEIGHTS_FILE = orig
            temp_path.unlink(missing_ok=True)

    def test_compute_with_persisted_weights(self):
        """Test compute_risk uses persisted weights."""
        # Save custom weights
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        orig = risk.WEIGHTS_FILE
        risk.WEIGHTS_FILE = temp_path
        try:
            risk.save_persistent_weights({'impact': 1.0, 'exposure': 1.0, 'anomaly': 1.0})
            subscores = {'impact': 5.0, 'exposure': 2.0, 'anomaly': 1.0, 'confidence': 1.0}
            score, raw = risk.compute_risk(subscores, weights=None)
            # With equal weights of 1.0
            expected_raw = 5.0 + 2.0 + 1.0
            assert raw == expected_raw
        finally:
            risk.WEIGHTS_FILE = orig
            temp_path.unlink(missing_ok=True)

    def test_describe_matches_compute(self):
        """Test describe and compute_risk use same weights."""
        weights = {'impact': 6.0, 'exposure': 3.5, 'anomaly': 1.5}

        desc = risk.describe(weights)
        subscores = {'impact': 10.0, 'exposure': 3.0, 'anomaly': 2.0, 'confidence': 1.0}
        score, raw = risk.compute_risk(subscores, weights)

        # Max raw should match
        max_raw_from_desc = desc['_max_raw']
        max_raw_computed = risk.CAPS['impact'] * weights['impact'] + \
                          risk.CAPS['exposure'] * weights['exposure'] + \
                          risk.CAPS['anomaly'] * weights['anomaly']

        assert max_raw_from_desc == max_raw_computed
