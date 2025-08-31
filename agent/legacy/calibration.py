"""
Legacy Calibration Module

This module provides backward compatibility imports for the calibration functionality
used by the legacy pipeline.
"""

# Import from the main calibration module
from ..calibration import apply_probability

# Re-export for legacy compatibility
__all__ = ['apply_probability']