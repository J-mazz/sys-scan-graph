"""Tests for sandbox module."""
import pytest
import subprocess
from unittest.mock import patch, MagicMock
from sys_scan_agent import sandbox


@pytest.fixture(autouse=True)
def reset_sandbox():
    """Reset sandbox config before each test."""
    sandbox.SANDBOX = sandbox.SandboxConfig()
    yield
    sandbox.SANDBOX = sandbox.SandboxConfig()


class TestSandboxConfig:
    """Tests for SandboxConfig model."""

    def test_sandbox_config_defaults(self):
        """Test SandboxConfig default values."""
        config = sandbox.SandboxConfig()
        assert config.dry_run is False
        assert config.timeout_sec == 2.0
        assert config.max_output_bytes == 4096

    def test_sandbox_config_custom_values(self):
        """Test SandboxConfig with custom values."""
        config = sandbox.SandboxConfig(
            dry_run=True,
            timeout_sec=5.0,
            max_output_bytes=8192
        )
        assert config.dry_run is True
        assert config.timeout_sec == 5.0
        assert config.max_output_bytes == 8192


class TestConfigure:
    """Tests for configure function."""

    def test_configure_dry_run(self):
        """Test configure with dry_run parameter."""
        result = sandbox.configure(dry_run=True)
        assert result.dry_run is True
        assert sandbox.SANDBOX.dry_run is True

    def test_configure_timeout_sec(self):
        """Test configure with timeout_sec parameter."""
        result = sandbox.configure(timeout_sec=10.0)
        assert result.timeout_sec == 10.0
        assert sandbox.SANDBOX.timeout_sec == 10.0

    def test_configure_max_output_bytes(self):
        """Test configure with max_output_bytes parameter."""
        result = sandbox.configure(max_output_bytes=2048)
        assert result.max_output_bytes == 2048
        assert sandbox.SANDBOX.max_output_bytes == 2048

    def test_configure_all_parameters(self):
        """Test configure with all parameters."""
        result = sandbox.configure(
            dry_run=True,
            timeout_sec=15.0,
            max_output_bytes=16384
        )
        assert result.dry_run is True
        assert result.timeout_sec == 15.0
        assert result.max_output_bytes == 16384

    def test_configure_none_parameters(self):
        """Test configure with None parameters preserves existing values."""
        sandbox.configure(dry_run=True, timeout_sec=5.0)
        result = sandbox.configure(max_output_bytes=1024)

        # Previous values should be preserved
        assert result.dry_run is True
        assert result.timeout_sec == 5.0
        assert result.max_output_bytes == 1024

    def test_configure_partial_update(self):
        """Test configure updates only specified parameters."""
        sandbox.configure(dry_run=True)
        assert sandbox.SANDBOX.dry_run is True
        assert sandbox.SANDBOX.timeout_sec == 2.0  # default unchanged

        sandbox.configure(timeout_sec=7.0)
        assert sandbox.SANDBOX.dry_run is True  # preserved
        assert sandbox.SANDBOX.timeout_sec == 7.0


class TestRunCommand:
    """Tests for run_command function."""

    def test_run_command_dry_run(self):
        """Test run_command in dry run mode."""
        sandbox.configure(dry_run=True)
        result = sandbox.run_command(['echo', 'test'])

        assert result['dry_run'] is True
        assert result['cmd'] == ['echo', 'test']

    @patch('subprocess.check_output')
    def test_run_command_success(self, mock_check_output):
        """Test run_command with successful execution."""
        mock_check_output.return_value = b'hello world\n'

        result = sandbox.run_command(['echo', 'hello world'])

        assert 'output' in result
        assert result['output'] == 'hello world'
        assert result['truncated'] is False
        mock_check_output.assert_called_once()

    @patch('subprocess.check_output')
    def test_run_command_with_custom_timeout(self, mock_check_output):
        """Test run_command respects custom timeout."""
        mock_check_output.return_value = b'output'
        sandbox.configure(timeout_sec=5.0)

        sandbox.run_command(['test', 'command'])

        call_args = mock_check_output.call_args
        assert call_args[1]['timeout'] == 5.0

    @patch('subprocess.check_output')
    def test_run_command_truncation(self, mock_check_output):
        """Test run_command truncates large output."""
        # Create output larger than max_output_bytes
        large_output = b'x' * 10000
        mock_check_output.return_value = large_output
        sandbox.configure(max_output_bytes=100)

        result = sandbox.run_command(['some', 'command'])

        assert len(result['output']) <= 100
        assert result['truncated'] is True

    @patch('subprocess.check_output')
    def test_run_command_no_truncation_exact_size(self, mock_check_output):
        """Test run_command doesn't truncate when output is exactly max size."""
        exact_output = b'x' * 4096
        mock_check_output.return_value = exact_output

        result = sandbox.run_command(['test'])

        assert result['truncated'] is False

    @patch('subprocess.check_output')
    def test_run_command_timeout_expired(self, mock_check_output):
        """Test run_command handles timeout."""
        mock_check_output.side_effect = subprocess.TimeoutExpired(
            cmd=['slow', 'command'],
            timeout=2.0
        )

        result = sandbox.run_command(['slow', 'command'])

        assert result['error'] == 'timeout'

    @patch('subprocess.check_output')
    def test_run_command_file_not_found(self, mock_check_output):
        """Test run_command handles missing command."""
        mock_check_output.side_effect = FileNotFoundError()

        result = sandbox.run_command(['nonexistent', 'command'])

        assert result['error'] == 'not_found'

    @patch('subprocess.check_output')
    def test_run_command_generic_exception(self, mock_check_output):
        """Test run_command handles generic exceptions."""
        mock_check_output.side_effect = Exception('Something went wrong')

        result = sandbox.run_command(['failing', 'command'])

        assert 'error' in result
        assert 'Something went wrong' in result['error']

    @patch('subprocess.check_output')
    def test_run_command_long_error_truncation(self, mock_check_output):
        """Test run_command truncates long error messages."""
        long_error = 'x' * 500
        mock_check_output.side_effect = Exception(long_error)

        result = sandbox.run_command(['test'])

        assert 'error' in result
        assert len(result['error']) <= 200

    @patch('subprocess.check_output')
    def test_run_command_decode_errors(self, mock_check_output):
        """Test run_command handles decode errors gracefully."""
        # Invalid UTF-8 bytes
        mock_check_output.return_value = b'\xff\xfe invalid utf8 \x80\x81'

        result = sandbox.run_command(['test'])

        # Should not raise, uses errors='replace'
        assert 'output' in result
        assert isinstance(result['output'], str)

    @patch('subprocess.check_output')
    def test_run_command_empty_output(self, mock_check_output):
        """Test run_command with empty output."""
        mock_check_output.return_value = b''

        result = sandbox.run_command(['test'])

        assert result['output'] == ''
        assert result['truncated'] is False

    @patch('subprocess.check_output')
    def test_run_command_whitespace_stripped(self, mock_check_output):
        """Test run_command strips whitespace from output."""
        mock_check_output.return_value = b'  output with spaces  \n\n'

        result = sandbox.run_command(['test'])

        assert result['output'] == 'output with spaces'


class TestGlobalSandbox:
    """Tests for global SANDBOX singleton."""

    def test_global_sandbox_initialized(self):
        """Test global SANDBOX is initialized with defaults."""
        # After fixture reset
        assert sandbox.SANDBOX.dry_run is False
        assert sandbox.SANDBOX.timeout_sec == 2.0

    def test_configure_modifies_global_sandbox(self):
        """Test configure modifies the global SANDBOX instance."""
        original = sandbox.SANDBOX
        sandbox.configure(dry_run=True)

        # Should be a new instance
        assert sandbox.SANDBOX is not original
        assert sandbox.SANDBOX.dry_run is True

    def test_run_command_uses_global_config(self):
        """Test run_command uses current global SANDBOX config."""
        sandbox.configure(dry_run=True)
        result = sandbox.run_command(['test'])
        assert result['dry_run'] is True

        sandbox.configure(dry_run=False)
        # Would actually run command (mocked in other tests)
        # Just verify it's using the updated config
        assert sandbox.SANDBOX.dry_run is False
