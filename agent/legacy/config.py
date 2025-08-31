"""
Legacy Config Module

This module provides backward compatibility imports for the config functionality
used by the legacy pipeline.
"""

# Import from the main config module
from ..config import load_config

# Re-export for legacy compatibility
__all__ = ['load_config']