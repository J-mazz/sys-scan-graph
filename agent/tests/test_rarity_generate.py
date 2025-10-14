import pytest
from pathlib import Path
from unittest.mock import patch, mock_open
import yaml
try:
    from sys_scan_agent import rarity_generate
    RARITY_GENERATE_AVAILABLE = True
except ImportError:
    RARITY_GENERATE_AVAILABLE = False
    rarity_generate = None


# Commented out because rarity_generate module does not exist
# @pytest.mark.skipif(not RARITY_GENERATE_AVAILABLE, reason="Rarity generate module not available")
# class TestRarityGenerate:
#     """Test rarity score generation utilities."""

#     def test_compute_percentiles_empty_dict(self):
#         """Test computing percentiles for empty frequency dictionary."""
#         result = rarity_generate.compute_percentiles({})
#         assert result == {}

#     def test_compute_percentiles_single_item(self):
#         """Test computing percentiles for single item."""
#         freqs = {"module1": 5}
#         result = rarity_generate.compute_percentiles(freqs)
#         assert result == {"module1": 1.0}

#     def test_compute_percentiles_multiple_items(self):
#         """Test computing percentiles for multiple items."""
#         freqs = {"module1": 1, "module2": 2, "module3": 2, "module4": 3}
#         result = rarity_generate.compute_percentiles(freqs)

#         # Expected percentiles:
#         # Unique sorted counts: [1, 2, 3]
#         # n = 3
#         # module1 (1): less_equal = 1 (1 <= 1) → 1/3 ≈ 0.333
#         # module2 (2): less_equal = 2 (1,2 <= 2) → 2/3 ≈ 0.667
#         # module3 (2): less_equal = 2 → 2/3 ≈ 0.667
#         # module4 (3): less_equal = 3 → 3/3 = 1.0
#         expected = {
#             "module1": 1/3,
#             "module2": 2/3,
#             "module3": 2/3,
#             "module4": 1.0
#         }
#         assert result == expected

#     def test_compute_percentiles_all_same_frequency(self):
#         """Test computing percentiles when all modules have same frequency."""
#         freqs = {"module1": 5, "module2": 5, "module3": 5}
#         result = rarity_generate.compute_percentiles(freqs)

#         # All should have percentile 1.0 since all counts <= 5
#         expected = {"module1": 1.0, "module2": 1.0, "module3": 1.0}
#         assert result == expected

#     def test_rarity_scores_empty_dict(self):
#         """Test rarity scores for empty frequency dictionary."""
#         result = rarity_generate.rarity_scores({})
#         assert result == {}

#     def test_rarity_scores_basic_calculation(self):
#         """Test basic rarity score calculation."""
#         freqs = {"common": 10, "rare": 1, "medium": 5}
#         result = rarity_generate.rarity_scores(freqs)

#         # Percentiles: common=1.0, medium=2/3≈0.667, rare=1/3≈0.333
#         # Rarity scores: (1-pr)*2, clamped to [0,2]
#         # common: (1-1.0)*2 = 0.0
#         # medium: (1-0.667)*2 ≈ 0.666
#         # rare: (1-0.333)*2 ≈ 1.334

#         assert abs(result["common"] - 0.0) < 0.001
#         assert abs(result["medium"] - 0.67) < 0.01  # rounded to 3 decimal places
#         assert abs(result["rare"] - 1.33) < 0.01

#     def test_rarity_scores_clamping(self):
#         """Test that rarity scores are properly clamped to [0, 2]."""
#         # Test that scores are clamped - create a scenario where raw score would be negative
#         # This is hard to test directly since percentiles are always 0-1, so scores are always 0-2
#         # Just test that scores are within bounds
#         freqs = {"common": 10, "rare": 1}
#         result = rarity_generate.rarity_scores(freqs)

#         for score in result.values():
#             assert 0.0 <= score <= 2.0

#     def test_rarity_scores_rounding(self):
#         """Test that rarity scores are rounded to 3 decimal places."""
#        freqs = {"module1": 3}
#         result = rarity_generate.rarity_scores(freqs)

#         # Should be exactly 3 decimal places
#         score_str = f"{result['module1']:.10f}"
#         decimal_part = score_str.split('.')[1]
#         assert len(decimal_part.rstrip('0')) <= 3

#     @patch('rarity_generate.baseline.BaselineStore')
#     def test_generate_success(self, mock_baseline_store):
#         """Test successful generation of rarity file."""
#         # Mock the baseline store
#         mock_store = mock_baseline_store.return_value
#         mock_store.aggregate_module_frequencies.return_value = {
#             "module1": 5,
#             "module2": 1,
#             "module3": 10
#         }

#         # Mock Path operations
#         with patch('pathlib.Path') as mock_path_class:
#             mock_db_path = mock_path_class.return_value
#             mock_out_path = mock_path_class.return_value

#             # Configure the paths
#             mock_db_path.__str__ = lambda: "test.db"
#             mock_out_path.__str__ = lambda: "rarity.yaml"
#             mock_out_path.write_text = mock_open()

#             # Call generate
#             result = rarity_generate.generate(mock_db_path, mock_out_path)

#             # Verify baseline store was created correctly
#             mock_baseline_store.assert_called_once_with(mock_db_path)

#             # Verify aggregate_module_frequencies was called
#             mock_store.aggregate_module_frequencies.assert_called_once()

#             # Verify write_text was called
#             mock_out_path.write_text.assert_called_once()

#             # Check the written content
#             call_args = mock_out_path.write_text.call_args[0][0]
#             data = yaml.safe_load(call_args)

#             # Verify structure
#             assert "modules" in data
#             assert "signature" in data
#             assert len(data["modules"]) == 3

#             # Verify modules are sorted and have correct structure
#             modules = data["modules"]
#             assert modules[0]["module"] == "module1"
#             assert modules[1]["module"] == "module2"
#             assert modules[2]["module"] == "module3"

#             # Verify signature is present and is a string
#             assert isinstance(data["signature"], str)
#             assert len(data["signature"]) == 64  # SHA256 hex length