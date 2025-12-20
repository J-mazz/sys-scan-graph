"""Performance optimizations for batching, caching, and parallel execution.

This module provides lightweight, dependency-free utilities that are safe to use
inside the agent runtime. The focus is on deterministic ordering, bounded
resource usage, and predictable time-to-first-result so the agent can operate
without crashing under load.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, TypeVar

from .models import Finding

T = TypeVar("T")
U = TypeVar("U")


@dataclass
class PerformanceConfig:
    """Runtime tunables for performance-sensitive helpers."""

    batch_size: int = 32
    max_concurrent_db_connections: int = 8
    cache_ttl_seconds: int = 300
    streaming_chunk_size: int = 1024 * 512
    max_memory_mb: int = 512
    thread_pool_workers: int = 8


# Global config instance so tests and callers share defaults
perf_config = PerformanceConfig()


class AdvancedCache:
    """A tiny LRU cache with TTL support.

    - Enforces a maximum size using LRU eviction.
    - Supports per-entry TTL (seconds) using a monotonic clock.
    - Keeps operations O(1) using an OrderedDict.
    """

    def __init__(self, max_size: int = 1024, ttl_seconds: int = perf_config.cache_ttl_seconds):
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._store: "OrderedDict[str, Tuple[Any, float]]" = OrderedDict()

    def _now(self) -> float:
        return time.monotonic()

    def _evict_if_needed(self) -> None:
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)

    def set(self, key: str, value: Any) -> None:
        expiry = self._now() + self._ttl_seconds
        if key in self._store:
            self._store.pop(key, None)
        self._store[key] = (value, expiry)
        self._store.move_to_end(key)
        self._evict_if_needed()

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if item is None:
            return None

        value, expiry = item
        if expiry < self._now():
            # Expired; remove and return miss
            self._store.pop(key, None)
            return None

        # Mark as recently used
        self._store.move_to_end(key)
        return value

    def clear_expired(self) -> None:
        now = self._now()
        expired_keys = [k for k, (_, expiry) in self._store.items() if expiry < now]
        for key in expired_keys:
            self._store.pop(key, None)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._store)


class FindingBatch:
    """Container for accumulating findings with a capacity ceiling."""

    def __init__(self, batch_id: str = "", metadata: Optional[Dict[str, Any]] = None):
        self.batch_id = batch_id
        self.metadata: Dict[str, Any] = metadata or {}
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def is_full(self) -> bool:
        return len(self.findings) >= perf_config.batch_size

    def clear(self) -> None:
        self.findings.clear()
        self.metadata.clear()
        self.batch_id = ""


async def batch_process_findings(
    items: Sequence[T],
    batch_processor: Callable[[List[T]], Awaitable[List[U]]],
    batch_size: Optional[int] = None,
) -> List[U]:
    """Process items in deterministic batches, preserving input order.

    The processor is awaited sequentially per batch to bound memory and avoid
    runaway concurrency while still benefiting from vectorized/batch work.
    """

    if batch_size is None:
        batch_size = perf_config.batch_size
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")

    results: List[U] = []
    total = len(items)
    for start in range(0, total, batch_size):
        batch = list(items[start : start + batch_size])
        processed = await batch_processor(batch)
        if processed is None:
            continue
        results.extend(processed)

    return results


async def parallel_batch_processor(
    items: Sequence[T],
    item_processor: Callable[[T], Awaitable[U]],
    max_concurrent: Optional[int] = None,
) -> List[U | Dict[str, Any]]:
    """Process items concurrently with bounded parallelism.

    - Preserves input ordering in the returned list.
    - Converts exceptions into structured error dictionaries instead of bubbling.
    """

    if max_concurrent is None:
        max_concurrent = max(1, perf_config.thread_pool_workers)
    if max_concurrent <= 0:
        raise ValueError("max_concurrent must be positive")

    if not items:
        return []

    semaphore = asyncio.Semaphore(max_concurrent)
    results: List[Optional[U | Dict[str, Any]]] = [None] * len(items)

    async def worker(idx: int, item: T) -> None:
        try:
            async with semaphore:
                results[idx] = await item_processor(item)
        except Exception as exc:  # pragma: no cover - defensive
            results[idx] = {"error": str(exc)}

    await asyncio.gather(*(worker(i, item) for i, item in enumerate(items)))

    # All slots should be filled; type ignore to satisfy mypy in strict contexts
    return [r for r in results if r is not None]
