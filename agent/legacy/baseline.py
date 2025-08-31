"""
Legacy Baseline Module

This module provides backward compatibility imports for the baseline functionality
used by the legacy pipeline.
"""

# Import from the main baseline module
from ..baseline import BaselineStore, process_feature_vector, hashlib_sha

# Re-export for legacy compatibility
__all__ = ['BaselineStore', 'process_feature_vector', 'hashlib_sha']