"""Unit tests for performance optimizations helpers.

Covers batching, caching, memory-efficient containers, and bounded parallelism.
"""

import asyncio
import time
import unittest
from typing import Any, Dict, List

from sys_scan_agent.models import Finding
from sys_scan_agent.performance import (
    AdvancedCache,
    FindingBatch,
    batch_process_findings,
    parallel_batch_processor,
    perf_config,
)


class TestBatchProcessing(unittest.TestCase):
    def test_batch_process_findings_empty(self):
        async def run_test():
            return await batch_process_findings([], lambda x: x)

        self.assertEqual(asyncio.run(run_test()), [])

    def test_batch_process_findings_basic(self):
        async def run_test():
            items = list(range(10))

            async def double_batch(batch: List[int]) -> List[int]:
                return [x * 2 for x in batch]

            return await batch_process_findings(items, double_batch, batch_size=3)

        results = asyncio.run(run_test())
        expected = [x * 2 for x in range(10)]
        self.assertEqual(results, expected)

    def test_batch_process_findings_deterministic_ordering(self):
        async def run_test():
            items = [f"item_{i}" for i in range(20)]

            async def identity_processor(batch: List[str]) -> List[str]:
                await asyncio.sleep(len(batch) * 0.001)
                return batch

            return await batch_process_findings(items, identity_processor, batch_size=7)

        results = asyncio.run(run_test())
        expected = [f"item_{i}" for i in range(20)]
        self.assertEqual(results, expected)


class TestAdvancedCache(unittest.TestCase):
    def test_cache_basic_operations(self):
        cache = AdvancedCache(max_size=10, ttl_seconds=1)
        cache.set("key1", "value1")
        self.assertEqual(cache.get("key1"), "value1")
        self.assertIsNone(cache.get("nonexistent"))
        time.sleep(1.1)
        self.assertIsNone(cache.get("key1"))

    def test_cache_eviction(self):
        cache = AdvancedCache(max_size=3, ttl_seconds=60)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")
        self.assertIsNone(cache.get("key1"))
        self.assertEqual(cache.get("key2"), "value2")
        self.assertEqual(cache.get("key3"), "value3")
        self.assertEqual(cache.get("key4"), "value4")

    def test_cache_clear_expired(self):
        cache = AdvancedCache(max_size=10, ttl_seconds=1)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        time.sleep(1.1)
        cache.clear_expired()
        self.assertIsNone(cache.get("key1"))
        self.assertIsNone(cache.get("key2"))


class TestFindingBatch(unittest.TestCase):
    def test_finding_batch_basic(self):
        batch = FindingBatch(batch_id="test_batch")
        self.assertFalse(batch.is_full())
        self.assertEqual(len(batch.findings), 0)

        finding1 = Finding(id="1", title="Test Finding 1", severity="high", risk_score=8)
        finding2 = Finding(id="2", title="Test Finding 2", severity="medium", risk_score=5)

        batch.add_finding(finding1)
        batch.add_finding(finding2)

        self.assertEqual(len(batch.findings), 2)
        self.assertEqual(batch.findings[0].id, "1")
        self.assertEqual(batch.findings[1].id, "2")

    def test_finding_batch_capacity(self):
        original_batch_size = perf_config.batch_size
        perf_config.batch_size = 2
        try:
            batch = FindingBatch()
            batch.add_finding(Finding(id="1", title="Finding 1", severity="info", risk_score=1))
            self.assertFalse(batch.is_full())
            batch.add_finding(Finding(id="2", title="Finding 2", severity="info", risk_score=1))
            self.assertTrue(batch.is_full())
        finally:
            perf_config.batch_size = original_batch_size

    def test_finding_batch_clear(self):
        batch = FindingBatch(batch_id="test", metadata={"test": "data"})
        batch.add_finding(Finding(id="1", title="Finding 1", severity="info", risk_score=1))
        self.assertEqual(len(batch.findings), 1)
        self.assertEqual(batch.metadata["test"], "data")
        batch.clear()
        self.assertEqual(len(batch.findings), 0)
        self.assertEqual(len(batch.metadata), 0)
        self.assertEqual(batch.batch_id, "")


class TestPerformanceConfig(unittest.TestCase):
    def test_performance_config_defaults(self):
        config = perf_config
        self.assertGreater(config.batch_size, 0)
        self.assertGreater(config.max_concurrent_db_connections, 0)
        self.assertGreater(config.cache_ttl_seconds, 0)
        self.assertGreater(config.streaming_chunk_size, 0)
        self.assertGreater(config.max_memory_mb, 0)
        self.assertGreater(config.thread_pool_workers, 0)

    def test_performance_config_types(self):
        config = perf_config
        self.assertIsInstance(config.batch_size, int)
        self.assertIsInstance(config.max_concurrent_db_connections, int)
        self.assertIsInstance(config.cache_ttl_seconds, int)
        self.assertIsInstance(config.streaming_chunk_size, int)
        self.assertIsInstance(config.max_memory_mb, int)
        self.assertIsInstance(config.thread_pool_workers, int)


class TestParallelExecution(unittest.TestCase):
    def test_parallel_batch_processor_empty(self):
        async def run_test():
            return await parallel_batch_processor([], lambda x: x)

        self.assertEqual(asyncio.run(run_test()), [])

    def test_parallel_batch_processor_basic(self):
        async def run_test():
            items = list(range(10))

            async def double_item(item: int) -> int:
                await asyncio.sleep(0.01)
                return item * 2

            return await parallel_batch_processor(items, double_item, max_concurrent=3)

        results = asyncio.run(run_test())
        expected = [x * 2 for x in range(10)]
        self.assertEqual(results, expected)

    def test_parallel_batch_processor_with_errors(self):
        async def run_test():
            items = list(range(5))

            async def failing_processor(item: int) -> int:
                if item == 3:
                    raise ValueError(f"Error on item {item}")
                await asyncio.sleep(0.01)
                return item * 2

            return await parallel_batch_processor(items, failing_processor, max_concurrent=2)

        results = asyncio.run(run_test())
        self.assertEqual(len(results), 5)
        self.assertEqual(results[0], 0)
        self.assertEqual(results[1], 2)
        self.assertEqual(results[2], 4)
        self.assertIsInstance(results[3], dict)
        self.assertEqual(results[3]["error"], "Error on item 3")
        self.assertEqual(results[4], 8)


class TestIntegration(unittest.TestCase):
    def test_full_batch_pipeline(self):
        async def run_test():
            findings = [
                Finding(id=f"test_{i}", title=f"Test Finding {i}", severity="info", risk_score=i)
                for i in range(10)
            ]

            async def mock_processor(batch: List[Finding]) -> List[Dict[str, Any]]:
                return [{"processed": f.id, "score": f.risk_score} for f in batch]

            return await batch_process_findings(findings, mock_processor, batch_size=3)

        results = asyncio.run(run_test())
        self.assertEqual(len(results), 10)
        for i, result in enumerate(results):
            self.assertEqual(result["processed"], f"test_{i}")
            self.assertEqual(result["score"], i)

    def test_memory_efficient_processing(self):
        async def run_test():
            large_findings = [
                Finding(id=f"large_{i}", title=f"Large Finding {i}", severity="info", risk_score=i % 10)
                for i in range(100)
            ]

            async def memory_test_processor(batch: List[Finding]) -> List[str]:
                await asyncio.sleep(0.001)
                return [f.id for f in batch]

            return await batch_process_findings(large_findings, memory_test_processor, batch_size=10)

        results = asyncio.run(run_test())
        self.assertEqual(len(results), 100)
        self.assertEqual(results[0], "large_0")
        self.assertEqual(results[-1], "large_99")

    def test_concurrent_operations_limit(self):
        async def run_test():
            items = list(range(20))

            async def slow_processor(item: int) -> int:
                await asyncio.sleep(0.1)
                return item * 2

            start_time = time.time()
            results = await parallel_batch_processor(items, slow_processor, max_concurrent=3)
            duration = time.time() - start_time
            return results, duration

        results, duration = asyncio.run(run_test())
        self.assertLess(duration, 1.5)
        self.assertEqual(len(results), 20)


if __name__ == "__main__":
    unittest.main()
