"""Tests for hf_loader.py - Hugging Face dataset loading utilities."""
import os
import tempfile
from unittest.mock import patch, mock_open, MagicMock
import pytest

from sys_scan_agent import hf_loader

# Check if pandas is available for optional tests
try:
    import pandas  # noqa: F401
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# Skip all tests if pandas is not available
hf_loader = pytest.importorskip("sys_scan_agent.hf_loader")


class TestHFLoader:
    """Test Hugging Face dataset loading utilities."""

    def test_get_token_no_env_var(self):
        """Test token retrieval when no environment variable is set."""
        with patch.dict(os.environ, {}, clear=True):
            assert hf_loader._get_token() is None

    def test_get_token_invalid_prefix(self):
        """Test token retrieval with invalid token prefix."""
        with patch.dict(os.environ, {'HUGGINGFACE_TOKEN': 'invalid_token'}):
            assert hf_loader._get_token() is None

    def test_get_token_valid(self):
        """Test token retrieval with valid token."""
        test_token = 'hf_1234567890abcdef'
        with patch.dict(os.environ, {'HUGGINGFACE_TOKEN': test_token}):
            assert hf_loader._get_token() == test_token

    def test_get_token_with_dotenv(self):
        """Test token retrieval with .env file."""
        test_token = 'hf_abcdef1234567890'
        dotenv_content = f'HUGGINGFACE_TOKEN={test_token}\n'

        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            with open('.env', 'w') as f:
                f.write(dotenv_content)

            # Set the token in environment to simulate what dotenv would do
            with patch.dict(os.environ, {'HUGGINGFACE_TOKEN': test_token}):
                result = hf_loader._get_token()
                assert result == test_token

    def test_get_token_dotenv_import_fails(self):
        """Test token retrieval when dotenv import fails."""
        test_token = 'hf_testtoken123'
        dotenv_content = f'HUGGINGFACE_TOKEN={test_token}\n'

        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            with open('.env', 'w') as f:
                f.write(dotenv_content)

            with patch.dict(os.environ, {}, clear=True):
                # dotenv import will fail, should still work if token in env
                with patch.dict(os.environ, {'HUGGINGFACE_TOKEN': test_token}):
                    result = hf_loader._get_token()
                    assert result == test_token

    def test_import_pd_success(self):
        """Test successful pandas import."""
        with patch.dict('sys.modules', {'pandas': MagicMock()}):
            pd = hf_loader._import_pd()
            assert pd is not None

    def test_import_pd_failure(self):
        """Test pandas import failure."""
        # Simulate import failure
        def mock_import(name, *args, **kwargs):
            if name == 'pandas':
                raise ImportError("No module named 'pandas'")
            return __builtins__['__import__'](name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=mock_import):
            pd = hf_loader._import_pd()
            assert pd is None

    def test_load_cybersec_jsonl_no_pandas(self):
        """Test JSONL loading when pandas is not available."""
        with patch('sys_scan_agent.hf_loader._import_pd', return_value=None):
            result = hf_loader.load_cybersec_jsonl()
            assert result is None

    def test_load_cybersec_jsonl_no_token(self):
        """Test JSONL loading when no token is available."""
        mock_pd = MagicMock()
        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value=None):
                result = hf_loader.load_cybersec_jsonl()
                assert result is None
                # pandas should not be called
                mock_pd.read_json.assert_not_called()

    @pytest.mark.skipif(not PANDAS_AVAILABLE, reason="pandas not available")
    def test_load_cybersec_jsonl_success(self):
        """Test successful JSONL loading."""
        mock_pd = MagicMock()
        mock_df = MagicMock()
        mock_pd.read_json.return_value = mock_df
        test_token = 'hf_testtoken123'

        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value=test_token):
                result = hf_loader.load_cybersec_jsonl()

                assert result is mock_df
                mock_pd.read_json.assert_called_once_with(
                    hf_loader._JSONL_PATH,
                    lines=True
                )

    @pytest.mark.skipif(not PANDAS_AVAILABLE, reason="pandas not available")
    def test_load_cybersec_jsonl_lines_false(self):
        """Test JSONL loading with lines=False."""
        mock_pd = MagicMock()
        mock_df = MagicMock()
        mock_pd.read_json.return_value = mock_df
        test_token = 'hf_testtoken123'

        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value=test_token):
                result = hf_loader.load_cybersec_jsonl(lines=False)

                assert result is mock_df
                mock_pd.read_json.assert_called_once_with(
                    hf_loader._JSONL_PATH,
                    lines=False
                )

    @pytest.mark.skipif(not PANDAS_AVAILABLE, reason="pandas not available")
    def test_load_cybersec_jsonl_read_fails(self):
        """Test JSONL loading when read_json fails."""
        mock_pd = MagicMock()
        mock_pd.read_json.side_effect = Exception("Network error")

        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value='hf_testtoken123'):
                result = hf_loader.load_cybersec_jsonl()
                assert result is None

    def test_load_cybersec_parquet_no_pandas(self):
        """Test Parquet loading when pandas is not available."""
        with patch('sys_scan_agent.hf_loader._import_pd', return_value=None):
            result = hf_loader.load_cybersec_parquet()
            assert result is None

    def test_load_cybersec_parquet_no_token(self):
        """Test Parquet loading when no token is available."""
        mock_pd = MagicMock()
        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value=None):
                result = hf_loader.load_cybersec_parquet()
                assert result is None
                mock_pd.read_parquet.assert_not_called()

    @pytest.mark.skipif(not PANDAS_AVAILABLE, reason="pandas not available")
    def test_load_cybersec_parquet_success(self):
        """Test successful Parquet loading."""
        mock_pd = MagicMock()
        mock_df = MagicMock()
        mock_pd.read_parquet.return_value = mock_df
        test_token = 'hf_testtoken123'

        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value=test_token):
                result = hf_loader.load_cybersec_parquet()

                assert result is mock_df
                mock_pd.read_parquet.assert_called_once_with(hf_loader._PARQUET_PATH)

    @pytest.mark.skipif(not PANDAS_AVAILABLE, reason="pandas not available")
    def test_load_cybersec_parquet_read_fails(self):
        """Test Parquet loading when read_parquet fails."""
        mock_pd = MagicMock()
        mock_pd.read_parquet.side_effect = Exception("Network error")

        with patch('sys_scan_agent.hf_loader._import_pd', return_value=mock_pd):
            with patch('sys_scan_agent.hf_loader._get_token', return_value='hf_testtoken123'):
                result = hf_loader.load_cybersec_parquet()
                assert result is None

    def test_constants_defined(self):
        """Test that dataset path constants are properly defined."""
        assert hasattr(hf_loader, '_JSONL_PATH')
        assert hasattr(hf_loader, '_PARQUET_PATH')
        assert hf_loader._JSONL_PATH.startswith('hf://')
        assert hf_loader._PARQUET_PATH.startswith('hf://')
        assert 'jsonl' in hf_loader._JSONL_PATH
        assert 'parquet' in hf_loader._PARQUET_PATH