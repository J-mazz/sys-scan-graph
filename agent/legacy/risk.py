"""
Legacy Risk Module

This module provides backward compatibility imports for the risk functionality
used by the legacy pipeline.
"""

# Import from the main risk module
from ..risk import compute_risk, load_persistent_weights

# Re-export for legacy compatibility
__all__ = ['compute_risk', 'load_persistent_weights']