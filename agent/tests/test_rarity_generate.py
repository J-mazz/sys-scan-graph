"""Tests for rarity_generate module."""
import os
import pytest
import yaml
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from sys_scan_agent import rarity_generate


class TestComputePercentiles:
    """Tests for compute_percentiles function."""

    def test_compute_percentiles_empty(self):
        """Test compute_percentiles with empty dict."""
        result = rarity_generate.compute_percentiles({})
        assert result == {}

    def test_compute_percentiles_single_module(self):
        """Test compute_percentiles with single module."""
        freqs = {'module1': 5}
        result = rarity_generate.compute_percentiles(freqs)
        assert result == {'module1': 1.0}  # Only value, so 100th percentile

    def test_compute_percentiles_uniform_distribution(self):
        """Test compute_percentiles with all same frequencies."""
        freqs = {'mod1': 10, 'mod2': 10, 'mod3': 10}
        result = rarity_generate.compute_percentiles(freqs)
        # All have same count, all at 100th percentile
        assert all(v == 1.0 for v in result.values())

    def test_compute_percentiles_varied_distribution(self):
        """Test compute_percentiles with varied frequencies."""
        freqs = {
            'rare': 1,      # Most rare
            'uncommon': 5,
            'common': 10,
            'very_common': 20
        }
        result = rarity_generate.compute_percentiles(freqs)

        # rare should have lowest percentile (25%)
        assert result['rare'] == 0.25
        # uncommon should have 50%
        assert result['uncommon'] == 0.50
        # common should have 75%
        assert result['common'] == 0.75
        # very_common should have 100%
        assert result['very_common'] == 1.0

    def test_compute_percentiles_duplicate_counts(self):
        """Test compute_percentiles handles duplicate counts correctly."""
        freqs = {
            'mod1': 5,
            'mod2': 5,
            'mod3': 10,
            'mod4': 10,
            'mod5': 15
        }
        result = rarity_generate.compute_percentiles(freqs)

        # Both mod1 and mod2 have count 5 (lowest), should be at same percentile
        assert result['mod1'] == result['mod2'] == pytest.approx(0.333, abs=0.01)
        # mod3 and mod4 have count 10
        assert result['mod3'] == result['mod4'] == pytest.approx(0.666, abs=0.01)
        # mod5 has highest count
        assert result['mod5'] == 1.0


class TestRarityScores:
    """Tests for rarity_scores function."""

    def test_rarity_scores_empty(self):
        """Test rarity_scores with empty dict."""
        result = rarity_generate.rarity_scores({})
        assert result == {}

    def test_rarity_scores_single_module(self):
        """Test rarity_scores with single module."""
        freqs = {'module1': 5}
        result = rarity_generate.rarity_scores(freqs)
        # Percentile is 1.0, so rarity = (1-1)*2 = 0
        assert result['module1'] == 0.0

    def test_rarity_scores_calculation(self):
        """Test rarity_scores calculation formula."""
        freqs = {
            'very_rare': 1,       # percentile 0.25 -> rarity (1-0.25)*2 = 1.5
            'uncommon': 5,        # percentile 0.5  -> rarity (1-0.5)*2 = 1.0
            'common': 10,         # percentile 0.75 -> rarity (1-0.75)*2 = 0.5
            'very_common': 20     # percentile 1.0  -> rarity (1-1.0)*2 = 0.0
        }
        result = rarity_generate.rarity_scores(freqs)

        assert result['very_rare'] == 1.5
        assert result['uncommon'] == 1.0
        assert result['common'] == 0.5
        assert result['very_common'] == 0.0

    def test_rarity_scores_clamped_at_2(self):
        """Test rarity_scores are clamped at maximum 2.0."""
        # Even if percentile is 0, rarity should be max 2.0
        freqs = {'rare_mod': 1, 'common_mod': 100}
        result = rarity_generate.rarity_scores(freqs)

        # rare_mod percentile 0.5, rarity (1-0.5)*2 = 1.0
        assert result['rare_mod'] <= 2.0
        assert result['common_mod'] >= 0.0

    def test_rarity_scores_rounding(self):
        """Test rarity_scores are rounded to 3 decimal places."""
        freqs = {
            'mod1': 1,
            'mod2': 2,
            'mod3': 3
        }
        result = rarity_generate.rarity_scores(freqs)

        # Check all values are rounded to 3 decimals
        for score in result.values():
            assert len(str(score).split('.')[-1]) <= 3 or score == int(score)


class TestGenerate:
    """Tests for generate function."""

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_basic(self, mock_store_class):
        """Test basic generate functionality."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {
            'module1': 5,
            'module2': 10,
            'module3': 2
        }
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'test.db'
            out_path = Path(tmpdir) / 'rarity.yaml'

            result = rarity_generate.generate(db_path, out_path)

            assert result == out_path
            assert out_path.exists()

            # Verify YAML structure
            content = yaml.safe_load(out_path.read_text())
            assert 'modules' in content
            assert 'signature' in content
            assert isinstance(content['modules'], list)
            assert len(content['modules']) == 3

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_includes_signature(self, mock_store_class):
        """Test generate includes signature for tamper-evidence."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {
            'module1': 5
        }
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / 'rarity.yaml'

            rarity_generate.generate(Path(tmpdir) / 'test.db', out_path)

            content = yaml.safe_load(out_path.read_text())
            assert 'signature' in content
            assert len(content['signature']) == 64  # SHA256 hex length

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_module_structure(self, mock_store_class):
        """Test generate creates correct module structure."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {
            'test_module': 7
        }
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / 'rarity.yaml'

            rarity_generate.generate(Path(tmpdir) / 'test.db', out_path)

            content = yaml.safe_load(out_path.read_text())
            module_entry = content['modules'][0]

            assert 'module' in module_entry
            assert 'hosts' in module_entry
            assert 'rarity_score' in module_entry
            assert module_entry['module'] == 'test_module'
            assert module_entry['hosts'] == 7

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_sorted_modules(self, mock_store_class):
        """Test generate sorts modules alphabetically."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {
            'zebra': 5,
            'alpha': 10,
            'beta': 3
        }
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / 'rarity.yaml'

            rarity_generate.generate(Path(tmpdir) / 'test.db', out_path)

            content = yaml.safe_load(out_path.read_text())
            module_names = [m['module'] for m in content['modules']]

            assert module_names == ['alpha', 'beta', 'zebra']

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_empty_frequencies(self, mock_store_class):
        """Test generate handles empty module frequencies."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {}
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / 'rarity.yaml'

            rarity_generate.generate(Path(tmpdir) / 'test.db', out_path)

            content = yaml.safe_load(out_path.read_text())
            assert content['modules'] == []
            assert 'signature' in content

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_signature_consistency(self, mock_store_class):
        """Test generate creates consistent signatures for same data."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {
            'module1': 5,
            'module2': 10
        }
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path1 = Path(tmpdir) / 'rarity1.yaml'
            out_path2 = Path(tmpdir) / 'rarity2.yaml'

            rarity_generate.generate(Path(tmpdir) / 'test.db', out_path1)
            rarity_generate.generate(Path(tmpdir) / 'test.db', out_path2)

            content1 = yaml.safe_load(out_path1.read_text())
            content2 = yaml.safe_load(out_path2.read_text())

            # Same input should produce same signature
            assert content1['signature'] == content2['signature']

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_generate_default_paths(self, mock_store_class):
        """Test generate uses default paths when not specified."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {}
        mock_store_class.return_value = mock_store

        # This would try to create files in current directory
        # We'll just verify the store was created with default path
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = None
            try:
                original_dir = os.getcwd()
            except FileNotFoundError:
                pass
            try:
                if original_dir:
                    os.chdir(tmpdir)
                with patch.object(Path, 'write_text'):
                    result = rarity_generate.generate()
                    assert result == Path('rarity.yaml')
            finally:
                if original_dir:
                    os.chdir(original_dir)


class TestIntegration:
    """Integration tests for rarity_generate module."""

    @patch('sys_scan_agent.rarity_generate.baseline.BaselineStore')
    def test_full_workflow(self, mock_store_class):
        """Test complete workflow from frequencies to YAML output."""
        mock_store = MagicMock()
        mock_store.aggregate_module_frequencies.return_value = {
            'very_rare_module': 1,
            'uncommon_module': 5,
            'common_module': 10,
            'very_common_module': 20
        }
        mock_store_class.return_value = mock_store

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'baseline.db'
            out_path = Path(tmpdir) / 'rarity.yaml'

            result = rarity_generate.generate(db_path, out_path)

            assert result.exists()
            content = yaml.safe_load(result.read_text())

            # Verify structure
            assert 'modules' in content
            assert 'signature' in content

            # Find specific module and verify rarity score calculation
            modules_dict = {m['module']: m for m in content['modules']}

            # very_rare should have high rarity score
            assert modules_dict['very_rare_module']['rarity_score'] > 1.0

            # very_common should have low rarity score
            assert modules_dict['very_common_module']['rarity_score'] == 0.0

            # Verify all required fields present
            for module in content['modules']:
                assert 'module' in module
                assert 'hosts' in module
                assert 'rarity_score' in module
                assert 0.0 <= module['rarity_score'] <= 2.0
