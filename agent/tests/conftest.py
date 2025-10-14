"""Pytest configuration for sys-scan-agent tests."""

import os
import pytest

# Skip the sys-scan binary check during test collection
# This allows tests to run even if the C++ binary isn't installed
os.environ['SYS_SCAN_SKIP_CHECK'] = '1'

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables."""
    # Ensure tests don't fail due to missing sys-scan binary
    os.environ.setdefault('SYS_SCAN_SKIP_CHECK', '1')
    yield
    # Cleanup if needed