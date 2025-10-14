from __future__ import annotations
import pytest
import tempfile
import time
import json
import pickle
from pathlib import Path
from unittest.mock import patch, MagicMock
import hashlib

from sys_scan_agent.llm_cache import (
    CacheEntry, TTLCache, LLMCache, get_llm_cache,
    cached_llm_operation, invalidate_cache_operation, cleanup_llm_cache
)


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_cache_entry_creation(self):
        """Test basic cache entry creation."""
        entry = CacheEntry(
            key="test_key",
            value="test_value",
            created_at=1000.0,
            ttl_seconds=3600
        )

        assert entry.key == "test_key"
        assert entry.value == "test_value"
        assert entry.created_at == 1000.0
        assert entry.ttl_seconds == 3600
        assert entry.access_count == 0
        assert entry.size_bytes == 0
        assert entry.metadata == {}

    def test_cache_entry_is_expired(self):
        """Test expiration logic."""
        # Not expired
        entry = CacheEntry(
            key="test",
            value="value",
            created_at=time.time(),
            ttl_seconds=3600
        )
        assert not entry.is_expired

        # Expired
        entry = CacheEntry(
            key="test",
            value="value",
            created_at=time.time() - 4000,  # 4000 seconds ago
            ttl_seconds=3600  # 1 hour TTL
        )
        assert entry.is_expired

        # No TTL (never expires)
        entry = CacheEntry(
            key="test",
            value="value",
            created_at=time.time() - 4000,
            ttl_seconds=None
        )
        assert not entry.is_expired

    def test_cache_entry_age(self):
        """Test age calculation."""
        created_at = time.time() - 100  # 100 seconds ago
        entry = CacheEntry(
            key="test",
            value="value",
            created_at=created_at,
            ttl_seconds=3600
        )

        assert abs(entry.age_seconds - 100) < 1  # Allow small timing difference

    def test_cache_entry_touch(self):
        """Test touch functionality."""
        entry = CacheEntry(
            key="test",
            value="value",
            created_at=1000.0,
            ttl_seconds=3600,
            access_count=5
        )

        original_accessed = entry.last_accessed
        time.sleep(0.01)  # Small delay
        entry.touch()

        assert entry.last_accessed > original_accessed
        assert entry.access_count == 6


class TestTTLCache:
    """Test TTLCache class."""

    def test_ttl_cache_creation(self):
        """Test basic cache creation."""
        cache = TTLCache(max_size=100, default_ttl=1800)

        assert cache.max_size == 100
        assert cache.default_ttl == 1800
        assert len(cache._cache) == 0
        assert cache._hits == 0
        assert cache._misses == 0
        assert cache._evictions == 0

    def test_ttl_cache_get_put(self):
        """Test basic get/put operations."""
        cache = TTLCache(max_size=10, default_ttl=3600)

        # Put and get
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

        # Get non-existent key
        assert cache.get("nonexistent") is None

        # Check stats
        stats = cache.get_stats()
        assert stats['entries'] == 1
        assert stats['hits'] == 1
        assert stats['misses'] == 1

    def test_ttl_cache_ttl_expiration(self):
        """Test TTL expiration."""
        cache = TTLCache(max_size=10, default_ttl=1)  # 1 second TTL

        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

        time.sleep(1.1)  # Wait for expiration

        assert cache.get("key1") is None  # Should be expired

    def test_ttl_cache_custom_ttl(self):
        """Test custom TTL per entry."""
        cache = TTLCache(max_size=10, default_ttl=3600)

        cache.put("key1", "value1", ttl_seconds=1)  # 1 second TTL
        assert cache.get("key1") == "value1"

        time.sleep(1.1)

        assert cache.get("key1") is None

    def test_ttl_cache_eviction(self):
        """Test LRU eviction when max size exceeded."""
        cache = TTLCache(max_size=2, default_ttl=3600)

        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.put("key3", "value3")  # Should evict key1 (oldest)

        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"

        stats = cache.get_stats()
        assert stats['entries'] == 2
        assert stats['evictions'] == 1

    def test_ttl_cache_remove(self):
        """Test entry removal."""
        cache = TTLCache(max_size=10, default_ttl=3600)

        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

        assert cache.remove("key1") is True
        assert cache.get("key1") is None
        assert cache.remove("nonexistent") is False

    def test_ttl_cache_clear(self):
        """Test cache clearing."""
        cache = TTLCache(max_size=10, default_ttl=3600)

        cache.put("key1", "value1")
        cache.put("key2", "value2")
        assert cache.get_stats()['entries'] == 2

        cache.clear()
        assert cache.get_stats()['entries'] == 0

    def test_ttl_cache_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = TTLCache(max_size=10, default_ttl=1)

        cache.put("key1", "value1")
        cache.put("key2", "value2", ttl_seconds=3600)  # Won't expire

        time.sleep(1.1)

        removed = cache.cleanup_expired()
        assert removed == 1

        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"

    def test_ttl_cache_persistence(self, tmp_path):
        """Test cache persistence."""
        cache_path = tmp_path / "test_cache.pkl"

        # Create cache with persistence
        cache1 = TTLCache(
            max_size=10,
            default_ttl=3600,
            enable_persistence=True,
            persistence_path=cache_path
        )

        cache1.put("key1", "value1")
        cache1.put("key2", "value2")

        # Create new cache instance that should load from persistence
        cache2 = TTLCache(
            max_size=10,
            default_ttl=3600,
            enable_persistence=True,
            persistence_path=cache_path
        )

        assert cache2.get("key1") == "value1"
        assert cache2.get("key2") == "value2"

    def test_ttl_cache_touch_updates_access(self):
        """Test that get operations update access patterns for LRU."""
        cache = TTLCache(max_size=3, default_ttl=3600)

        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.put("key3", "value3")

        # Access key1 to make it most recently used
        cache.get("key1")

        # Add another item, should evict key2 (least recently used)
        cache.put("key4", "value4")

        assert cache.get("key1") == "value1"  # Should still be there
        assert cache.get("key2") is None     # Should be evicted
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"


class TestLLMCache:
    """Test LLMCache class."""

    def test_llm_cache_creation(self):
        """Test LLM cache creation."""
        cache = LLMCache()

        assert cache.cache is not None
        assert cache.cache.max_size == 500
        assert cache.cache.default_ttl == 1800
        assert 'summarize' in cache.operation_ttls
        assert 'refine_rules' in cache.operation_ttls
        assert 'triage' in cache.operation_ttls

    def test_llm_cache_key_generation(self):
        """Test cache key generation."""
        cache = LLMCache()

        # Same inputs should generate same key
        key1 = cache.generate_key("test_op", "arg1", "arg2", kwarg1="value1")
        key2 = cache.generate_key("test_op", "arg1", "arg2", kwarg1="value1")
        assert key1 == key2

        # Different inputs should generate different keys
        key3 = cache.generate_key("test_op", "arg1", "arg3", kwarg1="value1")
        assert key1 != key3

    def test_llm_cache_key_generation_with_objects(self):
        """Test key generation with complex objects."""
        cache = LLMCache()

        # Mock Pydantic model
        mock_model = MagicMock()
        mock_model.model_dump.return_value = {"field": "value"}

        key1 = cache.generate_key("test_op", mock_model)
        key2 = cache.generate_key("test_op", mock_model)

        assert key1 == key2

        # Different model data should give different key
        mock_model2 = MagicMock()
        mock_model2.model_dump.return_value = {"field": "different_value"}

        key3 = cache.generate_key("test_op", mock_model2)
        assert key1 != key3

    def test_llm_cache_operations(self):
        """Test basic LLM cache operations."""
        cache = LLMCache()

        # Test cache miss
        result = cache.get("test_operation", "arg1", kwarg="value")
        assert result is None

        # Test cache put and get
        cache.put("test_operation", "cached_result", "arg1", kwarg="value")
        result = cache.get("test_operation", "arg1", kwarg="value")
        assert result == "cached_result"

    def test_llm_cache_operation_ttls(self):
        """Test operation-specific TTLs."""
        cache = LLMCache()

        # Put with different operations
        cache.put("summarize", "summary_result", "arg1")
        cache.put("refine_rules", "rules_result", "arg1")
        cache.put("unknown_op", "unknown_result", "arg1")

        # Check TTLs in metadata
        with cache.cache._lock:
            for key, entry in cache.cache._cache.items():
                if "summary_result" in str(entry.value):
                    assert entry.ttl_seconds == 3600  # summarize TTL
                elif "rules_result" in str(entry.value):
                    assert entry.ttl_seconds == 7200  # refine_rules TTL
                elif "unknown_result" in str(entry.value):
                    assert entry.ttl_seconds == 1800  # default TTL

    def test_llm_cache_invalidate_operation(self):
        """Test operation-specific cache invalidation."""
        cache = LLMCache()

        # Put multiple operations
        cache.put("summarize", "result1", "arg1")
        cache.put("summarize", "result2", "arg2")
        cache.put("triage", "result3", "arg3")

        # Invalidate summarize operations
        invalidated = cache.invalidate_operation("summarize")
        assert invalidated == 2

        # Check that summarize results are gone but triage remains
        assert cache.get("summarize", "arg1") is None
        assert cache.get("summarize", "arg2") is None
        assert cache.get("triage", "arg3") == "result3"

    def test_llm_cache_cleanup(self):
        """Test cache cleanup."""
        cache = LLMCache()

        # Create cache with short TTL
        short_cache = TTLCache(max_size=10, default_ttl=1)
        cache.cache = short_cache

        cache.put("test_op", "result", "arg1")
        time.sleep(1.1)

        cleaned = cache.cleanup()
        assert cleaned == 1

        assert cache.get("test_op", "arg1") is None

    def test_llm_cache_stats(self):
        """Test cache statistics."""
        cache = LLMCache()

        stats = cache.get_cache_stats()
        assert 'entries' in stats
        assert 'operation_ttls' in stats
        assert stats['operation_ttls'] == cache.operation_ttls


class TestGlobalFunctions:
    """Test global utility functions."""

    def test_get_llm_cache(self):
        """Test global cache instance."""
        cache1 = get_llm_cache()
        cache2 = get_llm_cache()

        assert cache1 is cache2  # Should be same instance
        assert isinstance(cache1, LLMCache)

    @patch('sys_scan_agent.llm_cache.get_llm_cache')
    def test_cached_llm_operation_decorator(self, mock_get_cache):
        """Test cached_llm_operation decorator."""
        mock_cache = MagicMock()
        mock_get_cache.return_value = mock_cache

        # Mock cache miss then put
        mock_cache.get.return_value = None

        @cached_llm_operation("test_operation")
        def test_function(arg1, arg2="default"):
            return f"result_{arg1}_{arg2}"

        # First call should cache
        result1 = test_function("value1", arg2="value2")
        assert result1 == "result_value1_value2"

        # Verify cache.get was called
        mock_cache.get.assert_called_with("test_operation", "value1", arg2="value2")

        # Verify cache.put was called
        mock_cache.put.assert_called_with("test_operation", "result_value1_value2", "value1", arg2="value2")

        # Second call should return cached result
        mock_cache.get.return_value = "cached_result"
        result2 = test_function("value1", arg2="value2")
        assert result2 == "cached_result"

    def test_invalidate_cache_operation(self):
        """Test global invalidate function."""
        with patch('sys_scan_agent.llm_cache.get_llm_cache') as mock_get:
            mock_cache = MagicMock()
            mock_cache.invalidate_operation.return_value = 5
            mock_get.return_value = mock_cache

            result = invalidate_cache_operation("test_op")
            assert result == 5
            mock_cache.invalidate_operation.assert_called_with("test_op")

    def test_cleanup_llm_cache(self):
        """Test global cleanup function."""
        with patch('sys_scan_agent.llm_cache.get_llm_cache') as mock_get:
            mock_cache = MagicMock()
            mock_cache.cleanup.return_value = 3
            mock_get.return_value = mock_cache

            result = cleanup_llm_cache()
            assert result == 3
            mock_cache.cleanup.assert_called_once()


class TestIntegration:
    """Integration tests for LLM cache."""

    def test_end_to_end_caching_workflow(self):
        """Test complete caching workflow."""
        cache = LLMCache()

        # Simulate LLM operation
        operation = "summarize"
        args = ("text to summarize",)
        kwargs = {"max_length": 100, "style": "concise"}

        # First call - cache miss
        result1 = cache.get(operation, *args, **kwargs)
        assert result1 is None

        # Put result in cache
        result_value = "This is a summary of the text."
        cache.put(operation, result_value, *args, **kwargs)

        # Second call - cache hit
        result2 = cache.get(operation, *args, **kwargs)
        assert result2 == result_value

        # Different args - cache miss
        result3 = cache.get(operation, "different text", max_length=100, style="concise")
        assert result3 is None

    def test_cache_persistence_integration(self, tmp_path):
        """Test persistence in integration scenario."""
        cache_path = tmp_path / "integration_cache.pkl"

        # Create cache with persistence
        cache1 = TTLCache(
            max_size=10,
            default_ttl=3600,
            enable_persistence=True,
            persistence_path=cache_path
        )
        llm_cache1 = LLMCache(cache1)

        # Add some data
        llm_cache1.put("test_op", "test_value", "arg1")

        # Create new instance that loads from persistence
        cache2 = TTLCache(
            max_size=10,
            default_ttl=3600,
            enable_persistence=True,
            persistence_path=cache_path
        )
        llm_cache2 = LLMCache(cache2)

        # Should have persisted data
        result = llm_cache2.get("test_op", "arg1")
        assert result == "test_value"