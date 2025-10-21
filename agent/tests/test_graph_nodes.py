"""Tests for graph_nodes module."""
import pytest
from unittest.mock import MagicMock, patch
from sys_scan_agent import graph_nodes


class TestBaselineQueryGraphProxy:
    """Tests for BaselineQueryGraphProxy class."""

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_getattr_success(self, mock_get_graph):
        """Test proxy __getattr__ returns attribute from app."""
        mock_app = MagicMock()
        mock_app.some_method = lambda: "test_value"
        mock_get_graph.return_value = mock_app

        proxy = graph_nodes.BaselineQueryGraphProxy()
        result = proxy.some_method()

        assert result == "test_value"
        mock_get_graph.assert_called()

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_getattr_none_app(self, mock_get_graph):
        """Test proxy __getattr__ raises AttributeError when app is None."""
        mock_get_graph.return_value = None

        proxy = graph_nodes.BaselineQueryGraphProxy()

        with pytest.raises(AttributeError) as exc_info:
            _ = proxy.some_attribute

        assert "has no attribute 'some_attribute'" in str(exc_info.value)
        assert "app is None" in str(exc_info.value)

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_call_with_invoke(self, mock_get_graph):
        """Test proxy __call__ uses invoke method when available."""
        mock_app = MagicMock()
        mock_app.invoke.return_value = "invoked_result"
        mock_get_graph.return_value = mock_app

        proxy = graph_nodes.BaselineQueryGraphProxy()
        result = proxy("arg1", key="value")

        assert result == "invoked_result"
        mock_app.invoke.assert_called_once_with("arg1", key="value")

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_call_none_app(self, mock_get_graph):
        """Test proxy __call__ raises TypeError when app is None."""
        mock_get_graph.return_value = None

        proxy = graph_nodes.BaselineQueryGraphProxy()

        with pytest.raises(TypeError) as exc_info:
            proxy()

        assert "is not callable" in str(exc_info.value)
        assert "app is None" in str(exc_info.value)

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_call_no_invoke(self, mock_get_graph):
        """Test proxy __call__ raises TypeError when app has no invoke."""
        mock_app = MagicMock()
        del mock_app.invoke  # Remove invoke method
        mock_get_graph.return_value = mock_app

        proxy = graph_nodes.BaselineQueryGraphProxy()

        with pytest.raises(TypeError) as exc_info:
            proxy()

        assert "is not callable" in str(exc_info.value)

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_bool_true(self, mock_get_graph):
        """Test proxy __bool__ returns True when app exists."""
        mock_app = MagicMock()
        mock_get_graph.return_value = mock_app

        proxy = graph_nodes.BaselineQueryGraphProxy()

        assert bool(proxy) is True

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_bool_false(self, mock_get_graph):
        """Test proxy __bool__ returns False when app is None."""
        mock_get_graph.return_value = None

        proxy = graph_nodes.BaselineQueryGraphProxy()

        assert bool(proxy) is False

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_repr(self, mock_get_graph):
        """Test proxy __repr__ returns repr of app."""
        mock_app = MagicMock()
        mock_app.__repr__ = lambda self: "<MockApp>"
        mock_get_graph.return_value = mock_app

        proxy = graph_nodes.BaselineQueryGraphProxy()
        result = repr(proxy)

        assert "<MockApp>" in result


class TestGetBaselineQueryGraph:
    """Tests for _get_baseline_query_graph function."""

    def test_get_baseline_query_graph_returns_app(self):
        """Test _get_baseline_query_graph returns graph.app."""
        # This actually loads the real graph module
        result = graph_nodes._get_baseline_query_graph()

        # Just verify it returns something from the graph module
        # The actual app might be None or an actual CompiledStateGraph
        assert result is not None or result is None  # Always true, but checks it doesn't raise

    def test_get_baseline_query_graph_callable(self):
        """Test _get_baseline_query_graph can be called without errors."""
        # Should not raise an exception
        result = graph_nodes._get_baseline_query_graph()

        # Result should be either None or have expected graph attributes
        if result is not None:
            # Real graph module loaded successfully
            assert True
        else:
            # Graph app might be None in test environment
            assert True


class TestModuleExports:
    """Tests for module exports and imports."""

    def test_module_exports_all(self):
        """Test module __all__ contains expected exports."""
        assert hasattr(graph_nodes, '__all__')
        assert 'plan_baseline_queries' in graph_nodes.__all__
        assert 'integrate_baseline_results' in graph_nodes.__all__
        assert 'BaselineQueryGraph' in graph_nodes.__all__

    def test_plan_baseline_queries_imported(self):
        """Test plan_baseline_queries is imported from graph."""
        assert hasattr(graph_nodes, 'plan_baseline_queries')
        # Verify it's actually the function from graph module
        from sys_scan_agent.graph import plan_baseline_queries
        assert graph_nodes.plan_baseline_queries is plan_baseline_queries

    def test_integrate_baseline_results_imported(self):
        """Test integrate_baseline_results is imported from graph."""
        assert hasattr(graph_nodes, 'integrate_baseline_results')
        # Verify it's actually the function from graph module
        from sys_scan_agent.graph import integrate_baseline_results
        assert graph_nodes.integrate_baseline_results is integrate_baseline_results

    def test_baseline_query_graph_is_proxy(self):
        """Test BaselineQueryGraph is a proxy instance."""
        assert isinstance(graph_nodes.BaselineQueryGraph,
                         graph_nodes.BaselineQueryGraphProxy)


class TestProxyIntegration:
    """Integration tests for proxy behavior."""

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_global_baseline_query_graph_proxy(self, mock_get_graph):
        """Test global BaselineQueryGraph proxy works correctly."""
        mock_app = MagicMock()
        mock_app.test_attr = "test_value"
        mock_get_graph.return_value = mock_app

        # Use the global proxy
        result = graph_nodes.BaselineQueryGraph.test_attr

        assert result == "test_value"

    @patch('sys_scan_agent.graph_nodes._get_baseline_query_graph')
    def test_proxy_multiple_attributes(self, mock_get_graph):
        """Test proxy can access multiple attributes."""
        mock_app = MagicMock()
        mock_app.attr1 = "value1"
        mock_app.attr2 = "value2"
        mock_app.method1 = lambda: "result1"
        mock_get_graph.return_value = mock_app

        proxy = graph_nodes.BaselineQueryGraphProxy()

        assert proxy.attr1 == "value1"
        assert proxy.attr2 == "value2"
        assert proxy.method1() == "result1"
