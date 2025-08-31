"""
Legacy Graph Analysis Module

This module provides backward compatibility imports for the graph analysis functionality
used by the legacy pipeline.
"""

# Import from the main graph_analysis module
from ..graph_analysis import annotate_and_summarize

# Re-export for legacy compatibility
__all__ = ['annotate_and_summarize']