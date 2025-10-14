"""
Shared utilities for the security scanning pipeline.

This module contains common helper functions, constants, and utilities
used across multiple pipeline stages.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

# Category mapping table
CAT_MAP = {
    "process": "process",
    "network": "network_socket",
    "kernel_params": "kernel_param",
    "kernel_modules": "kernel_module",
    "modules": "kernel_module",
    "world_writable": "filesystem",
    "suid": "privilege_escalation_surface",
    "ioc": "ioc",
    "mac": "mac",
    "integrity": "integrity",
    "rules": "rule_enrichment"
}

# Policy multipliers for impact based on category/policy nature
POLICY_MULTIPLIER = {
    "ioc": 2.0,
    "privilege_escalation_surface": 1.5,
    "network_socket": 1.3,
    "kernel_module": 1.2,
    "kernel_param": 1.1,
}

SEVERITY_BASE = {"info":1, "low":2, "medium":3, "high":4, "critical":5, "error":4}


def _recompute_finding_risk(f):
    """Recompute risk fields after any risk_subscores mutation.
    Safe no-op if subscores absent; logs errors instead of raising."""
    try:
        from . import risk
        from . import calibration
        from . import audit
        subs = getattr(f, 'risk_subscores', None)
        if not subs:
            return
        weights = risk.load_persistent_weights()
        score, raw = risk.compute_risk(subs, weights)
        f.risk_score = score
        f.risk_total = score
        subs["_raw_weighted_sum"] = round(raw, 3)
        f.probability_actionable = calibration.apply_probability(raw)
    except (ValueError, TypeError) as e:  # expected computation issues
        try:
            audit.log_stage('risk_recompute_error', error=str(e), type=type(e).__name__)
        except Exception:
            pass
    except Exception as e:  # unexpected
        try:
            audit.log_stage('risk_recompute_error_unexpected', error=str(e), type=type(e).__name__)
        except Exception:
            pass


def _log_error(stage: str, e: Exception, state=None, module: str = 'pipeline', severity: str = 'warning', hint: str | None = None):
    """Log an error with optional state attachment."""
    from . import models
    from . import audit

    if state is not None:
        try:
            state.agent_warnings.append(models.AgentWarning(module=module, stage=stage, error_type=type(e).__name__, message=str(e), severity=severity, hint=hint).model_dump())
        except Exception:
            pass
    try:
        audit.log_stage(f'{stage}_error', error=str(e), type=type(e).__name__)
    except Exception:
        pass