"""
Legacy Endpoint Classification Module

This module provides backward compatibility imports for the endpoint classification functionality
used by the legacy pipeline.
"""

# Import from the main endpoint_classification module
from ..endpoint_classification import classify

# Re-export for legacy compatibility
__all__ = ['classify']