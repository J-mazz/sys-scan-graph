"""
Legacy Executors Module

This module provides backward compatibility imports for the executors functionality
used by the legacy pipeline.
"""

# Import from the main executors package
from ..executors import hash_binary, query_package_manager

# Re-export for legacy compatibility
__all__ = ['hash_binary', 'query_package_manager']