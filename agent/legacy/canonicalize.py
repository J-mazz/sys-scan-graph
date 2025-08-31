"""
Legacy Canonicalize Module

This module provides backward compatibility imports for the canonicalize functionality
used by the legacy pipeline.
"""

# Import from the main canonicalize module
from ..canonicalize import canonicalize_enriched_output_dict

# Re-export for legacy compatibility
__all__ = ['canonicalize_enriched_output_dict']