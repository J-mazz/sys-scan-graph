from __future__ import annotations
"""Scalability enhancements for LangGraph processing.

This module provides horizontal scaling capabilities and distributed processing
patterns to handle increased load efficiently.
"""

from typing import Any, List, Dict, Optional, Callable, AsyncIterator
import asyncio
import logging
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
import multiprocessing
import threading
from contextlib import asynccontextmanager

from .graph import GraphState
from .graph_nodes_performance import PerformanceConfig, perf_config

logger = logging.getLogger(__name__)

# Scalability configuration
@dataclass
class ScalabilityConfig:
    """Configuration for scalability enhancements."""
    max_workers: int = multiprocessing.cpu_count()
    process_pool_workers: int = max(2, multiprocessing.cpu_count() // 2)
    thread_pool_workers: int = min(10, multiprocessing.cpu_count() * 2)
    chunk_size: int = 1000
    max_concurrent_tasks: int = 50
    distributed_mode: bool = False
    worker_timeout: int = 300
    load_balancing_enabled: bool = True

# Global scalability config
scale_config = ScalabilityConfig()

# Process pool for CPU-intensive tasks
process_pool: Optional[ProcessPoolExecutor] = None
thread_pool: Optional[ThreadPoolExecutor] = None

@asynccontextmanager
async def get_process_pool():
    """Context manager for process pool."""
    global process_pool
    if process_pool is None:
        process_pool = ProcessPoolExecutor(max_workers=scale_config.process_pool_workers)
    try:
        yield process_pool
    finally:
        pass  # Keep pool alive for reuse

@asynccontextmanager
async def get_thread_pool():
    """Context manager for thread pool."""
    global thread_pool
    if thread_pool is None:
        thread_pool = ThreadPoolExecutor(max_workers=scale_config.thread_pool_workers)
    try:
        yield thread_pool
    finally:
        pass  # Keep pool alive for reuse

class LoadBalancer:
    """Load balancer for distributing work across workers."""

    def __init__(self, max_workers: Optional[int] = None):
        self.max_workers = max_workers or scale_config.max_workers
        self.worker_loads: Dict[str, int] = {}
        self.worker_queues: Dict[str, asyncio.Queue] = {}
        self._lock = asyncio.Lock()

    async def register_worker(self, worker_id: str):
        """Register a new worker."""
        async with self._lock:
            self.worker_loads[worker_id] = 0
            self.worker_queues[worker_id] = asyncio.Queue()

    async def get_least_loaded_worker(self) -> Optional[str]:
        """Get the worker with the least load."""
        async with self._lock:
            if not self.worker_loads:
                return None
            return min(self.worker_loads.keys(), key=lambda k: self.worker_loads[k])

    async def assign_task(self, worker_id: str, task: Any):
        """Assign a task to a worker."""
        async with self._lock:
            if worker_id in self.worker_queues:
                await self.worker_queues[worker_id].put(task)
                self.worker_loads[worker_id] += 1

    async def complete_task(self, worker_id: str):
        """Mark a task as completed for a worker."""
        async with self._lock:
            if worker_id in self.worker_loads:
                self.worker_loads[worker_id] = max(0, self.worker_loads[worker_id] - 1)

# Global load balancer
load_balancer = LoadBalancer()

async def distribute_workload(items: List[Any], processor_func: Callable, chunk_size: Optional[int] = None) -> List[Any]:
    """Distribute workload across available workers."""
    if chunk_size is None:
        chunk_size = scale_config.chunk_size

    results = []
    semaphore = asyncio.Semaphore(scale_config.max_concurrent_tasks)

    async def process_chunk(chunk: List[Any]) -> List[Any]:
        """Process a chunk of items."""
        async with semaphore:
            try:
                if asyncio.iscoroutinefunction(processor_func):
                    return await processor_func(chunk)
                else:
                    # Use thread pool for sync functions
                    async with get_thread_pool() as pool:
                        loop = asyncio.get_event_loop()
                        return await loop.run_in_executor(pool, processor_func, chunk)
            except Exception as e:
                logger.error(f"Error processing chunk: {e}")
                return []

    # Create tasks for each chunk
    tasks = []
    for i in range(0, len(items), chunk_size):
        chunk = items[i:i + chunk_size]
        task = asyncio.create_task(process_chunk(chunk))
        tasks.append(task)

    # Wait for all tasks to complete
    completed_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect results
    for result in completed_results:
        if isinstance(result, Exception):
            logger.error(f"Task failed: {result}")
        elif isinstance(result, list):
            results.extend(result)

    return results

async def parallel_findings_processing(state: GraphState, findings: List[Dict[str, Any]]) -> GraphState:
    """Process findings in parallel across multiple workers."""
    start_time = time.time()
    state['current_stage'] = 'parallel_processing'

    try:
        # Split findings into chunks for parallel processing
        chunk_size = min(len(findings) // scale_config.max_workers + 1, scale_config.chunk_size)

        async def process_findings_chunk(chunk: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            """Process a chunk of findings."""
            processed = []
            for finding in chunk:
                try:
                    # Apply enrichment and correlation logic
                    processed_finding = finding.copy()

                    # Add processing metadata
                    processed_finding['processed_by'] = f"worker_{hash(str(finding)) % scale_config.max_workers}"
                    processed_finding['processing_timestamp'] = datetime.now().isoformat()

                    processed.append(processed_finding)

                except Exception as e:
                    logger.warning(f"Failed to process finding {finding.get('id')}: {e}")
                    processed.append(finding)  # Return original if processing fails

            return processed

        # Distribute processing across workers
        processed_findings = await distribute_workload(findings, process_findings_chunk, chunk_size)

        state['enriched_findings'] = processed_findings

        # Update metrics
        state.setdefault('metrics', {})['parallel_processing_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['chunks_processed'] = len(range(0, len(findings), chunk_size))
        state.setdefault('metrics', {})['workers_utilized'] = scale_config.max_workers

    except Exception as e:
        logger.error(f"Parallel processing failed: {e}")
        _append_warning(state, 'graph', 'parallel_processing', str(e))
        if 'enriched_findings' not in state:
            state['enriched_findings'] = findings

    return state

async def horizontal_scaling_router(state: GraphState) -> str:
    """Route to appropriate processing strategy based on load."""
    findings_count = len(state.get('raw_findings', []))
    current_load = len(asyncio.all_tasks())

    # High load conditions
    if findings_count > 10000 or current_load > scale_config.max_concurrent_tasks:
        return "parallel_processing"

    # Medium load - use batch processing
    elif findings_count > 1000:
        return "batch_processing"

    # Low load - use standard processing
    else:
        return "standard_processing"

async def adaptive_batch_sizing(state: GraphState) -> int:
    """Dynamically adjust batch size based on system load and data characteristics."""
    findings_count = len(state.get('raw_findings', []))
    system_load = len(asyncio.all_tasks())

    # Base batch size
    base_size = perf_config.batch_size

    # Adjust based on system load
    if system_load > scale_config.max_concurrent_tasks * 0.8:
        # High load - smaller batches
        adjusted_size = max(10, base_size // 4)
    elif system_load > scale_config.max_concurrent_tasks * 0.5:
        # Medium load - slightly smaller batches
        adjusted_size = max(25, base_size // 2)
    else:
        # Low load - can use larger batches
        adjusted_size = min(500, base_size * 2)

    # Adjust based on data size
    if findings_count > 50000:
        adjusted_size = min(adjusted_size, 200)  # Smaller batches for very large datasets
    elif findings_count < 100:
        adjusted_size = max(adjusted_size, 50)  # Larger batches for small datasets

    return adjusted_size

class WorkerPool:
    """Pool of worker processes for distributed processing."""

    def __init__(self, num_workers: Optional[int] = None):
        self.num_workers = num_workers or scale_config.max_workers
        self.workers: List[multiprocessing.Process] = []
        self.task_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self._running = False

    def start_workers(self):
        """Start worker processes."""
        self._running = True
        for i in range(self.num_workers):
            worker = multiprocessing.Process(
                target=self._worker_process,
                args=(i, self.task_queue, self.result_queue)
            )
            worker.start()
            self.workers.append(worker)

    def stop_workers(self):
        """Stop all worker processes."""
        self._running = False
        for _ in self.workers:
            self.task_queue.put(None)  # Poison pill

        for worker in self.workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker.terminate()

    def submit_task(self, task: Any):
        """Submit a task to the worker pool."""
        if self._running:
            self.task_queue.put(task)

    def get_result(self, timeout: float = 1.0) -> Optional[Any]:
        """Get a result from the worker pool."""
        try:
            return self.result_queue.get(timeout=timeout)
        except:
            return None

    @staticmethod
    def _worker_process(worker_id: int, task_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue):
        """Worker process function."""
        logger.info(f"Worker {worker_id} started")

        while True:
            try:
                task = task_queue.get(timeout=1)
                if task is None:  # Poison pill
                    break

                # Process the task (placeholder - implement specific processing logic)
                result = f"Processed by worker {worker_id}: {task}"
                result_queue.put(result)

            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                break

        logger.info(f"Worker {worker_id} stopped")

# Global worker pool
worker_pool: Optional[WorkerPool] = None

async def initialize_scalability():
    """Initialize scalability components."""
    global worker_pool

    if scale_config.distributed_mode and worker_pool is None:
        worker_pool = WorkerPool()
        worker_pool.start_workers()
        logger.info(f"Started {scale_config.max_workers} worker processes")

async def shutdown_scalability():
    """Shutdown scalability components."""
    global worker_pool

    if worker_pool:
        worker_pool.stop_workers()
        worker_pool = None
        logger.info("Stopped worker processes")

# Import time for metrics
import time
from datetime import datetime

def _append_warning(state: GraphState, module: str, stage: str, error: str, hint: str | None = None):
    """Enhanced warning appender with performance tracking."""
    wl = state.setdefault('warnings', [])
    error_entry = {
        'module': module,
        'stage': stage,
        'error': error,
        'hint': hint,
        'timestamp': datetime.now().isoformat(),
        'session_id': state.get('session_id', 'unknown'),
        'performance_impact': 'low'  # Can be upgraded based on error type
    }
    wl.append(error_entry)

    # Track in errors list for better visibility
    errors = state.setdefault('errors', [])
    errors.append(error_entry)