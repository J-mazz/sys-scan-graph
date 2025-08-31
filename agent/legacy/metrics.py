"""
Legacy Metrics Module

This module provides backward compatibility imports for the metrics functionality
used by the legacy pipeline.
"""

# Import from the main metrics module
from ..metrics import MetricsCollector, get_metrics_collector

# Re-export for legacy compatibility
__all__ = ['MetricsCollector', 'get_metrics_collector']