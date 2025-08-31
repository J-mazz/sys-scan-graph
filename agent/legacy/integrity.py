"""
Legacy Integrity Module

This module provides backward compatibility imports for the integrity functionality
used by the legacy pipeline.
"""

# Import from the main integrity module
from ..integrity import sha256_file, verify_file

# Re-export for legacy compatibility
__all__ = ['sha256_file', 'verify_file']