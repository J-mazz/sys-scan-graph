"""
Legacy Audit Module

This module provides backward compatibility imports for the audit functionality
used by the legacy pipeline.
"""

# Import from the main audit module
from ..audit import log_stage, hash_text

# Re-export for legacy compatibility
__all__ = ['log_stage', 'hash_text']