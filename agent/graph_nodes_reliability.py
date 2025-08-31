from __future__ import annotations
"""Reliability enhancements for LangGraph processing.

This module provides circuit breaker patterns, comprehensive error handling,
and resilience mechanisms to ensure robust operation.
"""

from typing import Any, List, Dict, Optional, Callable, AsyncIterator
import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from enum import Enum
import traceback
import sys

from .graph import GraphState

logger = logging.getLogger(__name__)

class CircuitBreakerState(Enum):
    """States for circuit breaker pattern."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"

@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5
    recovery_timeout: int = 60
    expected_exception: tuple = (Exception,)
    success_threshold: int = 3
    timeout: float = 10.0

@dataclass
class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""

    config: CircuitBreakerConfig
    _state: CircuitBreakerState = CircuitBreakerState.CLOSED
    _failure_count: int = 0
    _last_failure_time: Optional[float] = None
    _success_count: int = 0

    def __post_init__(self):
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self._success_count = 0

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        if self._state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self._state = CircuitBreakerState.HALF_OPEN
            else:
                raise CircuitBreakerOpenException("Circuit breaker is OPEN")

        try:
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout)
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: func(*args, **kwargs)
                )

            self._on_success()
            return result

        except self.config.expected_exception as e:
            self._on_failure()
            raise e
        except asyncio.TimeoutError:
            self._on_failure()
            raise CircuitBreakerOpenException("Operation timed out")

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self._last_failure_time is None:
            return True
        return time.time() - self._last_failure_time >= self.config.recovery_timeout

    def _on_success(self):
        """Handle successful operation."""
        if self._state == CircuitBreakerState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.success_threshold:
                self._reset()
        else:
            self._success_count = 0

    def _on_failure(self):
        """Handle failed operation."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._failure_count >= self.config.failure_threshold:
            self._state = CircuitBreakerState.OPEN
            logger.warning(f"Circuit breaker opened after {self._failure_count} failures")

    def _reset(self):
        """Reset circuit breaker to closed state."""
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        logger.info("Circuit breaker reset to CLOSED state")

    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self._state

class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open."""
    pass

# Global circuit breakers for different services
llm_circuit_breaker = CircuitBreaker(CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout=30,
    timeout=15.0
))

db_circuit_breaker = CircuitBreaker(CircuitBreakerConfig(
    failure_threshold=5,
    recovery_timeout=60,
    timeout=10.0
))

external_api_circuit_breaker = CircuitBreaker(CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout=120,
    timeout=30.0
))

@dataclass
class RetryConfig:
    """Configuration for retry logic."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_factor: float = 2.0
    jitter: bool = True

class RetryMechanism:
    """Retry mechanism with exponential backoff."""

    def __init__(self, config: RetryConfig):
        self.config = config

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None

        for attempt in range(self.config.max_attempts):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return await asyncio.get_event_loop().run_in_executor(
                        None, lambda: func(*args, **kwargs)
                    )
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_attempts - 1:
                    delay = self._calculate_delay(attempt)
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"All {self.config.max_attempts} attempts failed. Last error: {e}")

        if last_exception is not None:
            raise last_exception
        else:
            raise RuntimeError("All retry attempts failed with unknown error")

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and optional jitter."""
        delay = min(
            self.config.base_delay * (self.config.backoff_factor ** attempt),
            self.config.max_delay
        )

        if self.config.jitter:
            import random
            delay = delay * (0.5 + random.random() * 0.5)  # Add 50% jitter

        return delay

# Global retry mechanisms
default_retry = RetryMechanism(RetryConfig())
fast_retry = RetryMechanism(RetryConfig(max_attempts=2, base_delay=0.5))
slow_retry = RetryMechanism(RetryConfig(max_attempts=5, base_delay=2.0, max_delay=300.0))

@dataclass
class ErrorContext:
    """Context information for errors."""
    operation: str
    stage: str
    timestamp: str
    attempt: int
    error_type: str
    error_message: str
    stack_trace: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ErrorHandler:
    """Comprehensive error handler with recovery strategies."""

    def __init__(self):
        self.error_history: List[ErrorContext] = []
        self.recovery_strategies: Dict[str, Callable] = {}

    def register_recovery_strategy(self, error_type: str, strategy: Callable):
        """Register a recovery strategy for specific error types."""
        self.recovery_strategies[error_type] = strategy

    async def handle_error(self, error: Exception, context: Dict[str, Any]) -> Optional[Any]:
        """Handle an error with appropriate recovery strategy."""
        error_context = ErrorContext(
            operation=context.get('operation', 'unknown'),
            stage=context.get('stage', 'unknown'),
            timestamp=datetime.now().isoformat(),
            attempt=context.get('attempt', 1),
            error_type=type(error).__name__,
            error_message=str(error),
            stack_trace=traceback.format_exc(),
            metadata=context
        )

        self.error_history.append(error_context)

        # Log error with context
        logger.error(f"Error in {error_context.operation} at stage {error_context.stage}: {error_context.error_message}")
        logger.debug(f"Stack trace: {error_context.stack_trace}")

        # Try recovery strategy
        recovery_func = self.recovery_strategies.get(error_context.error_type)
        if recovery_func:
            try:
                logger.info(f"Attempting recovery for {error_context.error_type}")
                return await recovery_func(error, context)
            except Exception as recovery_error:
                logger.error(f"Recovery failed: {recovery_error}")

        return None

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors."""
        if not self.error_history:
            return {"total_errors": 0}

        recent_errors = [e for e in self.error_history
                        if datetime.now() - datetime.fromisoformat(e.timestamp) < timedelta(hours=1)]

        error_types = {}
        for error in recent_errors:
            error_types[error.error_type] = error_types.get(error.error_type, 0) + 1

        return {
            "total_errors": len(self.error_history),
            "recent_errors": len(recent_errors),
            "error_types": error_types,
            "most_common_error": max(error_types.keys(), key=lambda k: error_types[k]) if error_types else None
        }

# Global error handler
error_handler = ErrorHandler()

# Recovery strategies
async def llm_fallback_recovery(error: Exception, context: Dict[str, Any]) -> str:
    """Fallback recovery for LLM failures."""
    return "LLM service temporarily unavailable. Using cached or default response."

async def db_connection_recovery(error: Exception, context: Dict[str, Any]) -> None:
    """Recovery strategy for database connection issues."""
    logger.info("Attempting database reconnection...")
    # Implementation would depend on specific database connection logic
    await asyncio.sleep(1)  # Brief pause before retry

async def network_timeout_recovery(error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
    """Recovery strategy for network timeouts."""
    return {
        "status": "timeout",
        "retry_recommended": True,
        "fallback_data": context.get('fallback_data', {})
    }

# Register recovery strategies
error_handler.register_recovery_strategy("CircuitBreakerOpenException", llm_fallback_recovery)
error_handler.register_recovery_strategy("sqlite3.OperationalError", db_connection_recovery)
error_handler.register_recovery_strategy("asyncio.TimeoutError", network_timeout_recovery)

@dataclass
class HealthCheck:
    """Health check for system components."""

    name: str
    check_func: Callable
    interval: int = 60  # seconds
    timeout: float = 10.0
    last_check: Optional[float] = None
    last_result: Optional[bool] = None
    consecutive_failures: int = 0
    max_consecutive_failures: int = 3

    async def perform_check(self) -> bool:
        """Perform the health check."""
        try:
            if asyncio.iscoroutinefunction(self.check_func):
                result = await asyncio.wait_for(self.check_func(), timeout=self.timeout)
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.check_func()
                )

            self.last_check = time.time()
            self.last_result = bool(result)

            if self.last_result:
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1

            return self.last_result

        except Exception as e:
            logger.error(f"Health check {self.name} failed: {e}")
            self.last_check = time.time()
            self.last_result = False
            self.consecutive_failures += 1
            return False

    def is_healthy(self) -> bool:
        """Check if component is currently healthy."""
        if self.last_result is None:
            return False
        return self.last_result and self.consecutive_failures < self.max_consecutive_failures

    def should_check(self) -> bool:
        """Check if health check should be performed."""
        if self.last_check is None:
            return True
        return time.time() - self.last_check >= self.interval

class HealthMonitor:
    """Monitor health of system components."""

    def __init__(self):
        self.health_checks: Dict[str, HealthCheck] = {}

    def register_check(self, name: str, check_func: Callable, **kwargs):
        """Register a health check."""
        self.health_checks[name] = HealthCheck(name=name, check_func=check_func, **kwargs)

    async def check_all(self) -> Dict[str, bool]:
        """Check health of all registered components."""
        results = {}
        tasks = []

        for name, check in self.health_checks.items():
            if check.should_check():
                tasks.append(self._check_component(name, check))
            else:
                results[name] = check.is_healthy()

        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            for name, result in zip([t[0] for t in tasks], task_results):
                if isinstance(result, Exception):
                    logger.error(f"Health check task failed for {name}: {result}")
                    results[name] = False
                else:
                    results[name] = result

        return results

    async def _check_component(self, name: str, check: HealthCheck) -> bool:
        """Check health of a specific component."""
        return await check.perform_check()

    def get_health_summary(self) -> Dict[str, Any]:
        """Get summary of health status."""
        all_results = {}
        for name, check in self.health_checks.items():
            all_results[name] = {
                "healthy": check.is_healthy(),
                "last_check": check.last_check,
                "consecutive_failures": check.consecutive_failures
            }

        healthy_count = sum(1 for r in all_results.values() if r["healthy"])
        total_count = len(all_results)

        return {
            "overall_healthy": healthy_count == total_count,
            "healthy_components": healthy_count,
            "total_components": total_count,
            "component_details": all_results
        }

# Global health monitor
health_monitor = HealthMonitor()

# Reliability-enhanced node functions
async def reliable_enrich_findings(state: GraphState) -> GraphState:
    """Reliability-enhanced enrichment with circuit breaker and error handling."""
    start_time = time.time()
    state['current_stage'] = 'reliable_enrich'

    try:
        # Use circuit breaker for LLM calls
        async def safe_llm_call():
            return await llm_circuit_breaker.call(
                lambda: _perform_enrichment_logic(state)
            )

        # Use retry mechanism
        enriched_data = await default_retry.execute(safe_llm_call)

        state['enriched_findings'] = enriched_data
        state.setdefault('metrics', {})['reliable_enrich_duration'] = time.time() - start_time

    except Exception as e:
        await error_handler.handle_error(e, {
            'operation': 'enrich_findings',
            'stage': 'reliable_enrich',
            'state': state
        })

        # Fallback: use original findings
        if 'enriched_findings' not in state:
            state['enriched_findings'] = state.get('raw_findings', [])

    return state

async def _perform_enrichment_logic(state: GraphState) -> List[Dict[str, Any]]:
    """Core enrichment logic (placeholder - integrate with existing enrichment)."""
    # This would integrate with existing enrichment logic
    findings = state.get('raw_findings', [])
    # Add reliability metadata
    for finding in findings:
        finding['reliability_checked'] = True
        finding['enrichment_timestamp'] = datetime.now().isoformat()

    return findings

async def reliable_correlate_findings(state: GraphState) -> GraphState:
    """Reliability-enhanced correlation with error recovery."""
    start_time = time.time()
    state['current_stage'] = 'reliable_correlate'

    try:
        # Health check before processing
        health_status = await health_monitor.check_all()
        if not health_status.get('correlation_service', True):
            logger.warning("Correlation service unhealthy, using simplified correlation")

        # Use circuit breaker and retry
        async def safe_correlation():
            return await _perform_correlation_logic(state)

        correlated_data = await default_retry.execute(safe_correlation)
        state.update(correlated_data)
        state.setdefault('metrics', {})['reliable_correlate_duration'] = time.time() - start_time

    except Exception as e:
        await error_handler.handle_error(e, {
            'operation': 'correlate_findings',
            'stage': 'reliable_correlate',
            'state': state
        })

        # Fallback: minimal correlation
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])

    return state

async def _perform_correlation_logic(state: GraphState) -> Dict[str, Any]:
    """Core correlation logic (placeholder - integrate with existing correlation)."""
    # This would integrate with existing correlation logic
    findings = state.get('enriched_findings', [])

    return {
        'correlated_findings': findings,
        'correlations': [],
        'correlation_metadata': {
            'reliability_checked': True,
            'correlation_timestamp': datetime.now().isoformat()
        }
    }

async def reliable_summarize_state(state: GraphState) -> GraphState:
    """Reliability-enhanced summarization with comprehensive error handling."""
    start_time = time.time()
    state['current_stage'] = 'reliable_summarize'

    try:
        # Multiple fallback strategies
        summary = None

        # Try primary summarization
        try:
            summary = await fast_retry.execute(
                lambda: llm_circuit_breaker.call(_perform_summarization_logic, state)
            )
        except Exception as primary_error:
            logger.warning(f"Primary summarization failed: {primary_error}")

            # Try fallback summarization
            try:
                summary = await _fallback_summarization(state)
            except Exception as fallback_error:
                logger.error(f"Fallback summarization also failed: {fallback_error}")
                summary = _emergency_summary(state)

        state['summary'] = summary
        state.setdefault('metrics', {})['reliable_summarize_duration'] = time.time() - start_time

    except Exception as e:
        await error_handler.handle_error(e, {
            'operation': 'summarize_state',
            'stage': 'reliable_summarize',
            'state': state
        })

        # Emergency fallback
        if 'summary' not in state:
            state['summary'] = _emergency_summary(state)

    return state

async def _perform_summarization_logic(state: GraphState) -> Dict[str, Any]:
    """Core summarization logic (placeholder - integrate with existing summarization)."""
    # This would integrate with existing summarization logic
    return {
        'summary_text': 'Analysis completed with reliability enhancements',
        'confidence_score': 0.85,
        'reliability_checked': True,
        'summary_timestamp': datetime.now().isoformat()
    }

async def _fallback_summarization(state: GraphState) -> Dict[str, Any]:
    """Fallback summarization when primary fails."""
    findings_count = len(state.get('correlated_findings', []))
    return {
        'summary_text': f'Fallback summary: Found {findings_count} items for analysis',
        'confidence_score': 0.6,
        'fallback_mode': True,
        'summary_timestamp': datetime.now().isoformat()
    }

def _emergency_summary(state: GraphState) -> Dict[str, Any]:
    """Emergency summary when all else fails."""
    return {
        'summary_text': 'Analysis completed (emergency mode)',
        'confidence_score': 0.0,
        'emergency_mode': True,
        'summary_timestamp': datetime.now().isoformat()
    }

# Health check functions
async def check_llm_service() -> bool:
    """Check if LLM service is healthy."""
    try:
        # Placeholder - implement actual LLM health check
        return llm_circuit_breaker.state != CircuitBreakerState.OPEN
    except Exception:
        return False

async def check_database() -> bool:
    """Check if database is healthy."""
    try:
        # Placeholder - implement actual database health check
        return db_circuit_breaker.state != CircuitBreakerState.OPEN
    except Exception:
        return False

async def check_external_apis() -> bool:
    """Check if external APIs are healthy."""
    try:
        # Placeholder - implement actual API health check
        return external_api_circuit_breaker.state != CircuitBreakerState.OPEN
    except Exception:
        return False

# Register health checks
health_monitor.register_check("llm_service", check_llm_service, interval=30)
health_monitor.register_check("database", check_database, interval=60)
health_monitor.register_check("external_apis", check_external_apis, interval=120)

# Initialization and cleanup
async def initialize_reliability():
    """Initialize reliability components."""
    logger.info("Initializing reliability enhancements...")
    # Perform initial health checks
    await health_monitor.check_all()

async def shutdown_reliability():
    """Shutdown reliability components."""
    logger.info("Shutting down reliability enhancements...")
    # Cleanup if needed