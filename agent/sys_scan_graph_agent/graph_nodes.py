"""Graph nodes module for baseline query operations.

This module provides the necessary functions and classes for baseline query
operations in the graph workflow.
"""

from .graph import plan_baseline_queries, integrate_baseline_results

# Lazy import to avoid import order issues
def _get_baseline_query_graph():
    """Get the baseline query graph app."""
    from . import graph
    return graph.app

# Create a proxy object that behaves like the app
class BaselineQueryGraphProxy:
    """Proxy for BaselineQueryGraph to handle lazy loading."""
    
    def __getattr__(self, name):
        app = _get_baseline_query_graph()
        if app is None:
            raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}' (app is None)")
        return getattr(app, name)
    
    def __call__(self, *args, **kwargs):
        app = _get_baseline_query_graph()
        if app is None:
            raise TypeError("'BaselineQueryGraph' is not callable (app is None)")
        # CompiledStateGraph is not directly callable, but might have invoke method
        if hasattr(app, 'invoke'):
            return app.invoke(*args, **kwargs)
        else:
            raise TypeError("'BaselineQueryGraph' is not callable")
    
    def __bool__(self):
        return _get_baseline_query_graph() is not None
    
    def __repr__(self):
        app = _get_baseline_query_graph()
        return repr(app)

BaselineQueryGraph = BaselineQueryGraphProxy()

__all__ = ["plan_baseline_queries", "integrate_baseline_results", "BaselineQueryGraph"]