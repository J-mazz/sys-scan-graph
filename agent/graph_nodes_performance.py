from __future__ import annotations
"""Performance-optimized graph node functions with advanced async capabilities.

This module provides high-performance node implementations with:
- Connection pooling and batch database operations
- Streaming processing for large datasets
- Parallel execution patterns
- Memory-efficient data structures
- Advanced caching strategies
- Circuit breaker patterns
"""

from typing import Any, List, Dict, Optional, Union, AsyncIterator, Callable
import asyncio
import time
import logging
import json
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import hashlib
import tempfile
from concurrent.futures import ThreadPoolExecutor

# Use standard sqlite3 for now, can upgrade to aiosqlite later
import sqlite3

from .graph import GraphState
from .data_governance import get_data_governor
from .models import Finding, ScannerResult, Report, Meta, Summary, SummaryExtension, AgentState, Reductions
from .knowledge import apply_external_knowledge
from .pipeline import augment as _augment
from .reduction import reduce_all
from .llm_provider import get_llm_provider
from .rules import Correlator, DEFAULT_RULES
from .rule_gap_miner import mine_gap_candidates

logger = logging.getLogger(__name__)

# Performance configuration
@dataclass
class PerformanceConfig:
    """Configuration for performance optimizations."""
    batch_size: int = 100
    max_concurrent_db_connections: int = 10
    cache_ttl_seconds: int = 3600
    streaming_chunk_size: int = 50
    max_memory_mb: int = 512
    thread_pool_workers: int = 4

# Global performance config
perf_config = PerformanceConfig()

# Connection pool for database operations (using regular sqlite3 for now)
class DatabaseConnectionPool:
    """Async-compatible connection pool for SQLite operations."""

    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool: asyncio.Queue[sqlite3.Connection] = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(max_connections)

    async def initialize(self):
        """Initialize the connection pool."""
        for _ in range(self.max_connections):
            # Use ThreadPoolExecutor for sqlite3 operations
            loop = asyncio.get_event_loop()
            conn = await loop.run_in_executor(None, sqlite3.connect, self.db_path)
            await self._pool.put(conn)

    async def get_connection(self) -> sqlite3.Connection:
        """Get a connection from the pool."""
        await self._semaphore.acquire()
        conn = await self._pool.get()
        return conn

    async def return_connection(self, conn: sqlite3.Connection):
        """Return a connection to the pool."""
        await self._pool.put(conn)
        self._semaphore.release()

    async def execute_query(self, query: str, params: tuple = ()) -> List[tuple]:
        """Execute a query using a pooled connection."""
        conn = await self.get_connection()
        try:
            loop = asyncio.get_event_loop()
            cursor = await loop.run_in_executor(None, conn.cursor)
            await loop.run_in_executor(None, cursor.execute, query, params)
            results = await loop.run_in_executor(None, cursor.fetchall)
            await loop.run_in_executor(None, cursor.close)
            return results
        finally:
            await self.return_connection(conn)

    async def close_all(self):
        """Close all connections in the pool."""
        while not self._pool.empty():
            conn = await self._pool.get()
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, conn.close)

# Global connection pool
db_pool: Optional[DatabaseConnectionPool] = None

@asynccontextmanager
async def get_db_connection(db_path: str):
    """Context manager for database connections."""
    global db_pool
    if db_pool is None:
        db_pool = DatabaseConnectionPool(db_path)
        await db_pool.initialize()

    conn = await db_pool.get_connection()
    try:
        yield conn
    finally:
        await db_pool.return_connection(conn)

# Memory-efficient data structures
@dataclass
class FindingBatch:
    """Memory-efficient batch of findings."""
    findings: List[Finding] = field(default_factory=list)
    batch_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        """Add a finding to the batch."""
        self.findings.append(finding)

    def is_full(self) -> bool:
        """Check if batch is at capacity."""
        return len(self.findings) >= perf_config.batch_size

    def clear(self):
        """Clear the batch."""
        self.findings.clear()
        self.metadata.clear()

# Advanced caching with TTL
class AdvancedCache:
    """Advanced caching with TTL and size limits."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_times: Dict[str, float] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        if key in self._cache:
            if time.time() - self._access_times[key] > self.ttl_seconds:
                del self._cache[key]
                del self._access_times[key]
                return None
            self._access_times[key] = time.time()
            return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        """Set cached value with eviction if needed."""
        if len(self._cache) >= self.max_size:
            # Evict least recently used
            oldest_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
            del self._cache[oldest_key]
            del self._access_times[oldest_key]

        self._cache[key] = value
        self._access_times[key] = time.time()

    def clear_expired(self):
        """Clear expired entries."""
        current_time = time.time()
        expired_keys = [
            key for key, access_time in self._access_times.items()
            if current_time - access_time > self.ttl_seconds
        ]
        for key in expired_keys:
            del self._cache[key]
            del self._access_times[key]

# Global cache instance
advanced_cache = AdvancedCache()

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

def _findings_from_graph(state: GraphState) -> List[Finding]:
    """Convert graph state findings to Pydantic models with batching."""
    out: List[Finding] = []
    raw_findings = state.get('raw_findings', []) or []

    # Process in batches to avoid memory spikes
    for i in range(0, len(raw_findings), perf_config.batch_size):
        batch = raw_findings[i:i + perf_config.batch_size]
        for finding in batch:
            try:
                out.append(Finding(
                    id=finding.get('id','unknown'),
                    title=finding.get('title','(no title)'),
                    severity=finding.get('severity','info'),
                    risk_score=int(finding.get('risk_score', finding.get('risk_total', 0)) or 0),
                    metadata=finding.get('metadata', {})
                ))
            except Exception:
                continue

    return out

async def batch_process_findings(findings: List[Any], processor_func: Callable[[List[Any]], Any], batch_size: Optional[int] = None) -> List[Any]:
    """Process findings in batches for memory efficiency."""
    if batch_size is None:
        batch_size = perf_config.batch_size

    results = []
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        batch_results = await processor_func(batch)
        results.extend(batch_results)
        # Allow other tasks to run
        await asyncio.sleep(0)
    return results

async def enrich_findings_batch(state: GraphState) -> GraphState:
    """Batch-optimized enrichment with streaming and caching."""
    start_time = time.time()
    state['current_stage'] = 'enrich'
    state['start_time'] = state.get('start_time', datetime.now().isoformat())

    try:
        # Check cache first
        cache_key = f"enrich_batch_{hash(str(state.get('raw_findings', [])))}"
        cached_result = advanced_cache.get(cache_key)
        if cached_result:
            logger.info("Using cached enrichment results")
            state.update(cached_result)
            state['cache_hits'] = state.get('cache_hits', []) + [cache_key]
            return state

        findings = _findings_from_graph(state)

        # Process in batches
        async def process_batch(batch: List[Finding]) -> List[Dict[str, Any]]:
            """Process a batch of findings."""
            batch_results = []
            for finding in batch:
                try:
                    # Create minimal report for this finding
                    sr = ScannerResult(
                        scanner='mixed',
                        finding_count=1,
                        findings=[finding]
                    )
                    report = Report(
                        meta=Meta(),
                        summary=Summary(finding_count_total=1, finding_count_emitted=1),
                        results=[sr],
                        collection_warnings=[],
                        scanner_errors=[],
                        summary_extension=SummaryExtension(total_risk_score=finding.risk_score or 0)
                    )
                    astate = AgentState(report=report)

                    # Apply enrichment pipeline
                    astate = _augment(astate)
                    astate = apply_external_knowledge(astate)

                    # Extract enriched finding
                    if astate.report and astate.report.results:
                        for r in astate.report.results:
                            for f in r.findings:
                                batch_results.append(f.model_dump())

                except Exception as e:
                    logger.warning(f"Failed to enrich finding {finding.id}: {e}")
                    continue

            return batch_results

        # Process all findings in batches
        enriched_findings = await batch_process_findings(findings, process_batch)

        state['enriched_findings'] = enriched_findings

        # Cache the results
        cache_data = {
            'enriched_findings': enriched_findings,
            'cache_timestamp': datetime.now().isoformat()
        }
        advanced_cache.set(cache_key, cache_data)
        state['cache_keys'] = state.get('cache_keys', []) + [cache_key]

        # Update metrics
        state.setdefault('metrics', {})['enrich_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['findings_processed'] = len(enriched_findings)

    except Exception as e:
        logger.error(f"Batch enrichment failed: {e}")
        _append_warning(state, 'graph', 'enrich_batch', str(e))
        state.setdefault('enriched_findings', state.get('raw_findings', []))

    return state

async def correlate_findings_batch(state: GraphState) -> GraphState:
    """Batch-optimized correlation with parallel processing."""
    start_time = time.time()
    state['current_stage'] = 'correlate'

    try:
        findings: List[Finding] = []
        enriched_findings = state.get('enriched_findings', []) or []

        # Convert to Pydantic models in batches
        for i in range(0, len(enriched_findings), perf_config.batch_size):
            batch = enriched_findings[i:i + perf_config.batch_size]
            for finding_dict in batch:
                try:
                    findings.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
                except Exception:
                    continue

        if not findings:
            return state

        # Create report for correlation
        sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = Report(
            meta=Meta(),
            summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
            results=[sr],
            collection_warnings=[],
            scanner_errors=[],
            summary_extension=SummaryExtension(total_risk_score=sum(f.risk_score or 0 for f in findings))
        )
        astate = AgentState(report=report)

        # Apply correlation rules
        correlator = Correlator(DEFAULT_RULES)
        correlations = correlator.apply(findings)

        # Attach correlation refs to findings in parallel
        async def attach_correlations():
            """Attach correlation references to findings."""
            tasks = []
            for correlation in correlations:
                task = asyncio.create_task(attach_correlation_refs(findings, correlation))
                tasks.append(task)
            await asyncio.gather(*tasks)

        async def attach_correlation_refs(findings: List[Finding], correlation):
            """Attach correlation refs to relevant findings."""
            for finding in findings:
                if finding.id in correlation.related_finding_ids and correlation.id not in finding.correlation_refs:
                    finding.correlation_refs.append(correlation.id)

        await attach_correlations()

        state['correlated_findings'] = [finding.model_dump() for finding in findings]
        state['correlations'] = [c.model_dump() for c in correlations]

        # Update metrics
        state.setdefault('metrics', {})['correlate_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['correlations_found'] = len(correlations)

    except Exception as e:
        logger.error(f"Batch correlation failed: {e}")
        _append_warning(state, 'graph', 'correlate_batch', str(e))
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])

    return state

async def summarize_host_state_streaming(state: GraphState) -> GraphState:
    """Streaming summarization with real-time updates."""
    start_time = time.time()
    state['current_stage'] = 'summarize'

    try:
        # Iteration guard
        max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
        iters = int(state.get('iteration_count', 0))
        if iters >= max_iter:
            _append_warning(state, 'graph', 'summarize', 'iteration_limit_reached')
            return state

        provider = get_llm_provider()
        findings_dicts = state.get('correlated_findings') or state.get('enriched_findings') or []

        # Convert findings in streaming fashion
        findings: List[Finding] = []
        for finding_dict in findings_dicts:
            try:
                findings.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
            except Exception:
                continue

        # Process in chunks for memory efficiency
        reductions = []
        for i in range(0, len(findings), perf_config.streaming_chunk_size):
            chunk = findings[i:i + perf_config.streaming_chunk_size]
            chunk_reductions = reduce_all(chunk)
            reductions.extend(chunk_reductions)

            # Yield progress updates
            progress = (i + len(chunk)) / len(findings)
            state['summarize_progress'] = progress
            await asyncio.sleep(0)  # Allow other tasks to run

        # Enhanced correlation handling
        corr_objs = []
        correlations = state.get('correlations', []) or []
        for c in correlations:
            try:
                from .models import Correlation as _C
                corr_objs.append(_C(**c))
            except Exception:
                continue

        baseline_context = state.get('baseline_results') or {}

        # Generate summary
        summaries = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)
        state['summary'] = summaries.model_dump()
        state['iteration_count'] = iters + 1

        # Update metrics
        state.setdefault('metrics', {})['summarize_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['chunks_processed'] = len(range(0, len(findings), perf_config.streaming_chunk_size))

    except Exception as e:
        logger.error(f"Streaming summarization failed: {e}")
        _append_warning(state, 'graph', 'summarize_streaming', str(e))

    return state

async def query_baseline_batch(state: GraphState) -> GraphState:
    """Batch baseline queries with connection pooling."""
    start_time = time.time()
    state['current_stage'] = 'baseline_query'

    try:
        enriched = state.get('enriched_findings', []) or []
        if not enriched:
            return state

        db_path = __import__('os').environ.get('AGENT_BASELINE_DB', 'agent_baseline.db')

        # Process baseline queries in batches
        async def process_baseline_batch(batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            """Process a batch of baseline queries."""
            results = []
            async with get_db_connection(db_path) as conn:
                for finding in batch:
                    try:
                        fid = finding.get('id') or 'unknown'
                        title = finding.get('title') or ''
                        severity = finding.get('severity') or ''
                        scanner = finding.get('scanner') or 'mixed'

                        # Compute composite hash
                        identity_core = f"{fid}\n{title}\n{severity}\n".encode()
                        h = hashlib.sha256(identity_core).hexdigest()

                        from .baseline import hashlib_sha
                        composite = hashlib_sha(scanner, h)

                        # Query database
                        loop = asyncio.get_event_loop()
                        cursor = await loop.run_in_executor(None, conn.cursor)
                        await loop.run_in_executor(None, cursor.execute,
                            "SELECT first_seen_ts, seen_count FROM baseline_finding WHERE host_id=? AND finding_hash=?",
                            (state.get('host_id', 'unknown'), composite)
                        )
                        row = await loop.run_in_executor(None, cursor.fetchone)
                        await loop.run_in_executor(None, cursor.close)

                        result = {
                            'finding_id': fid,
                            'host_id': state.get('host_id', 'unknown'),
                            'scanner': scanner,
                            'composite_hash': composite,
                            'db_path': db_path
                        }

                        if row:
                            first_seen, count = row
                            result.update({
                                'status': 'existing',
                                'first_seen_ts': first_seen,
                                'prev_seen_count': count,
                                'baseline_status': 'existing'
                            })
                        else:
                            result.update({
                                'status': 'new',
                                'baseline_status': 'new'
                            })

                        results.append(result)

                    except Exception as e:
                        logger.warning(f"Baseline query failed for finding {finding.get('id')}: {e}")
                        results.append({
                            'finding_id': finding.get('id', 'unknown'),
                            'status': 'error',
                            'error': str(e)
                        })

            return results

        # Process all findings in batches
        baseline_results = await batch_process_findings(enriched, process_baseline_batch)

        # Update findings with baseline status
        for result in baseline_results:
            fid = result.get('finding_id')
            status = result.get('baseline_status')
            if fid and status:
                for finding in enriched:
                    if finding.get('id') == fid:
                        finding['baseline_status'] = status
                        break

        state['baseline_results'] = {r.get('finding_id'): r for r in baseline_results if r.get('finding_id')}
        state['enriched_findings'] = enriched

        # Update metrics
        state.setdefault('metrics', {})['baseline_query_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['baseline_queries_made'] = len(baseline_results)

    except Exception as e:
        logger.error(f"Batch baseline query failed: {e}")
        _append_warning(state, 'graph', 'baseline_batch', str(e))

    return state

async def parallel_node_execution(state: GraphState, nodes: List[Callable[[GraphState], Any]]) -> GraphState:
    """Execute multiple nodes in parallel."""
    start_time = time.time()

    try:
        # Create tasks for parallel execution
        tasks = []
        for node_func in nodes:
            task = asyncio.create_task(node_func(state.copy()))
            tasks.append(task)

        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results back into state
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Parallel node execution failed: {result}")
                _append_warning(state, 'graph', 'parallel_execution', str(result))
            elif isinstance(result, dict):
                # Merge result into main state
                state.update(result)

        # Update metrics
        state.setdefault('metrics', {})['parallel_execution_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['parallel_tasks_executed'] = len(tasks)

    except Exception as e:
        logger.error(f"Parallel execution failed: {e}")
        _append_warning(state, 'graph', 'parallel_execution', str(e))

    return state

# Circuit breaker for external service calls
class CircuitBreaker:
    """Circuit breaker pattern implementation."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = 'closed'  # closed, open, half-open

    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == 'open':
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = 'half-open'
            else:
                raise Exception("Circuit breaker is open")

        try:
            result = await func(*args, **kwargs)
            if self.state == 'half-open':
                self.state = 'closed'
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
            raise e

# Global circuit breaker instances
llm_circuit_breaker = CircuitBreaker()
db_circuit_breaker = CircuitBreaker()

async def circuit_breaker_protected_llm_call(state: GraphState, llm_func, *args, **kwargs):
    """Execute LLM call with circuit breaker protection."""
    try:
        return await llm_circuit_breaker.call(llm_func, *args, **kwargs)
    except Exception as e:
        logger.warning(f"LLM circuit breaker triggered: {e}")
        _append_warning(state, 'graph', 'llm_circuit_breaker', str(e))
        # Return fallback response
        return {"summary": "LLM service temporarily unavailable", "fallback": True}

async def circuit_breaker_protected_db_call(state: GraphState, db_func, *args, **kwargs):
    """Execute database call with circuit breaker protection."""
    try:
        return await db_circuit_breaker.call(db_func, *args, **kwargs)
    except Exception as e:
        logger.warning(f"Database circuit breaker triggered: {e}")
        _append_warning(state, 'graph', 'db_circuit_breaker', str(e))
        # Return empty results
        return {}