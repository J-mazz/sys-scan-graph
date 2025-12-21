from __future__ import annotations

"""LangChain API-backed LLM provider.

This provider is **opt-in** and intended for users who want to run the
intelligence layer against an external inference provider using LangChain.

Security posture:
- Not enabled by default.
- Requires an explicit enable flag (see llm_provider factory) and the user must
  supply their own credentials for the chosen inference provider.

Dependencies:
- This module intentionally performs **lazy imports** so that the package can be
  installed and used in local-only mode without pulling in any cloud clients.
"""

from dataclasses import dataclass
from datetime import datetime
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import models
from .. import redaction
from ..llm_provider import ILLMProvider, ProviderMetadata

Reductions = models.Reductions
Correlation = models.Correlation
Summaries = models.Summaries
ActionItem = models.ActionItem


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)


@dataclass(frozen=True)
class LangChainAPIConfig:
    """Configuration for the LangChain API provider.

    Environment variables (preferred):
    - AGENT_LANGCHAIN_PROVIDER: openai|anthropic
    - AGENT_LANGCHAIN_MODEL: provider-specific model name
    - AGENT_LANGCHAIN_TEMPERATURE: float (default 0.1)
    - AGENT_LANGCHAIN_TIMEOUT_S: request timeout seconds (default 60)
    """

    provider: str = "openai"
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    timeout_s: int = 60

    @staticmethod
    def from_env() -> "LangChainAPIConfig":
        provider = os.environ.get("AGENT_LANGCHAIN_PROVIDER", "openai").strip().lower()
        model = os.environ.get("AGENT_LANGCHAIN_MODEL", "gpt-4o-mini").strip()
        try:
            temperature = float(os.environ.get("AGENT_LANGCHAIN_TEMPERATURE", "0.1"))
        except Exception:
            temperature = 0.1
        try:
            timeout_s = int(os.environ.get("AGENT_LANGCHAIN_TIMEOUT_S", "60"))
        except Exception:
            timeout_s = 60
        return LangChainAPIConfig(
            provider=provider,
            model=model,
            temperature=temperature,
            timeout_s=timeout_s,
        )


class LangChainAPIProvider(ILLMProvider):
    """LangChain-backed provider using external inference APIs.

    This provider requires provider-specific LangChain integrations to be
    installed (e.g., `langchain-openai`, `langchain-anthropic`) and the user to
    supply credentials via environment variables required by the chosen SDK.

    If the required dependencies are missing, initialization will raise.
    """

    def __init__(self, *, config: Optional[LangChainAPIConfig] = None):
        self.config = config or LangChainAPIConfig.from_env()
        self._chat = self._build_chat_model(self.config)

    @staticmethod
    def _build_chat_model(cfg: LangChainAPIConfig):
        """Create a LangChain chat model instance for the selected provider."""
        # Import inside function to keep local-only installs lightweight.
        if cfg.provider == "openai":
            try:
                from langchain_openai import ChatOpenAI  # type: ignore
            except Exception as e:  # pragma: no cover
                raise ImportError(
                    "LangChain OpenAI integration not installed. "
                    "Install `sys-scan-agent[api]` or `langchain-openai`."
                ) from e
            return ChatOpenAI(model=cfg.model, temperature=cfg.temperature, timeout=cfg.timeout_s)

        if cfg.provider == "anthropic":
            try:
                from langchain_anthropic import ChatAnthropic  # type: ignore
            except Exception as e:  # pragma: no cover
                raise ImportError(
                    "LangChain Anthropic integration not installed. "
                    "Install `sys-scan-agent[api]` or `langchain-anthropic`."
                ) from e
            return ChatAnthropic(model=cfg.model, temperature=cfg.temperature, timeout=cfg.timeout_s)

        raise ValueError(
            f"Unsupported AGENT_LANGCHAIN_PROVIDER={cfg.provider!r}. "
            "Supported: openai, anthropic."
        )

    @staticmethod
    def _extract_token_usage(msg: Any) -> Tuple[int, int]:
        """Best-effort token extraction from LangChain AIMessage."""
        prompt = 0
        completion = 0
        try:
            usage = getattr(msg, "usage_metadata", None) or {}
            prompt = int(usage.get("input_tokens") or 0)
            completion = int(usage.get("output_tokens") or 0)
            if prompt or completion:
                return prompt, completion
        except Exception:
            pass

        try:
            md = getattr(msg, "response_metadata", None) or {}
            usage = md.get("token_usage") or md.get("usage") or {}
            prompt = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
            completion = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
        except Exception:
            prompt, completion = 0, 0
        return prompt, completion

    @staticmethod
    def _coerce_json(text: str, *, want: str) -> Any:
        """Parse JSON from model output.

        want: "object" or "array"
        """
        text = (text or "").strip()
        if not text:
            raise ValueError("Empty model output")

        # Fast path: already valid JSON
        try:
            parsed = json.loads(text)
            return parsed
        except Exception:
            pass

        # Slow path: extract a JSON blob
        if want == "object":
            m = _JSON_OBJECT_RE.search(text)
        else:
            m = _JSON_ARRAY_RE.search(text)
        if not m:
            raise ValueError("Could not locate JSON in model output")
        return json.loads(m.group(0))

    def _metadata(self, *, latency_ms: int, tokens_prompt: int, tokens_completion: int,
                  cached: bool = False, fallback: bool = False,
                  error_message: Optional[str] = None, retry_count: int = 0) -> ProviderMetadata:
        return ProviderMetadata(
            model_name=self.config.model,
            provider_name=f"langchain-{self.config.provider}",
            latency_ms=latency_ms,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            cached=cached,
            fallback=fallback,
            error_message=error_message,
            retry_count=retry_count,
            temperature=self.config.temperature,
            timestamp=datetime.now().isoformat(),
        )

    def summarize(
        self,
        reductions: Reductions,
        correlations: List[Correlation],
        actions: List[ActionItem],
        *,
        skip: bool = False,
        previous: Optional[Summaries] = None,
        skip_reason: Optional[str] = None,
        baseline_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Summaries, ProviderMetadata]:
        start = time.time()

        if skip and previous is not None:
            reused = previous.model_copy(deep=True)
            note = "No material change: reused previous summary"
            reused.executive_summary = f"{reused.executive_summary} | {note}" if reused.executive_summary else note
            reused.metrics = (reused.metrics or {}) | {
                "tokens_prompt": 0,
                "tokens_completion": 0,
                "latency_ms": 0,
                "skipped": True,
                "skip_reason": skip_reason or "low_change",
            }
            return reused, self._metadata(latency_ms=0, tokens_prompt=0, tokens_completion=0, cached=True)

        # Keep input small and privacy-conscious.
        try:
            red_red = redaction.redact_reductions(reductions)
        except Exception:  # pragma: no cover
            red_red = reductions

        # For correlations/actions, send only minimal structured fields.
        corr_payload = [
            {
                "id": c.id,
                "title": c.title,
                "severity": c.severity,
                "rationale": c.rationale,
                "related_finding_ids": c.related_finding_ids,
                "tags": c.tags,
            }
            for c in correlations
        ]
        actions_payload = [
            {
                "priority": a.priority,
                "action": a.action,
                "correlation_refs": a.correlation_refs,
            }
            for a in actions
        ]

        try:
            reductions_payload = red_red.model_dump()  # type: ignore[attr-defined]
        except Exception:
            reductions_payload = red_red

        prompt = {
            "reductions": reductions_payload,
            "correlations": corr_payload,
            "actions": actions_payload,
            "baseline_context_present": bool(baseline_context),
        }

        system = (
            "You are a security analysis assistant. "
            "Return ONLY JSON with keys matching this schema: "
            "{executive_summary: string, analyst: object, triage_summary: object, action_narrative: string, "
            "consistency_findings: array|null, metrics: object|null}. "
            "Keep the executive_summary concise and actionable. Do not include markdown."
        )

        try:
            from langchain_core.messages import SystemMessage, HumanMessage  # type: ignore
        except Exception as e:  # pragma: no cover
            raise ImportError(
                "langchain-core is required for the LangChain API provider. "
                "Install `sys-scan-agent[api]`."
            ) from e

        msg = self._chat.invoke([
            SystemMessage(content=system),
            HumanMessage(content=json.dumps(prompt, ensure_ascii=False)),
        ])

        elapsed_ms = int((time.time() - start) * 1000)
        pt, ct = self._extract_token_usage(msg)

        parsed = self._coerce_json(getattr(msg, "content", ""), want="object")
        summaries = Summaries.model_validate(parsed)
        summaries.metrics = (summaries.metrics or {}) | {
            "tokens_prompt": pt,
            "tokens_completion": ct,
            "latency_ms": elapsed_ms,
            "provider": f"langchain-{self.config.provider}",
        }

        return summaries, self._metadata(latency_ms=elapsed_ms, tokens_prompt=pt, tokens_completion=ct)

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]:
        start = time.time()

        try:
            red_red = redaction.redact_reductions(reductions)
        except Exception:  # pragma: no cover
            red_red = reductions

        corr_payload = [{"id": c.id, "title": c.title, "severity": c.severity} for c in correlations]

        try:
            reductions_payload = red_red.model_dump()  # type: ignore[attr-defined]
        except Exception:
            reductions_payload = red_red

        prompt = {
            "reductions": reductions_payload,
            "correlations": corr_payload,
        }

        system = (
            "Return ONLY JSON with keys: {top_findings: array, correlation_count: number}. "
            "top_findings should be a small list of objects with at least {title}."
        )

        from langchain_core.messages import SystemMessage, HumanMessage  # type: ignore

        msg = self._chat.invoke([
            SystemMessage(content=system),
            HumanMessage(content=json.dumps(prompt, ensure_ascii=False)),
        ])

        elapsed_ms = int((time.time() - start) * 1000)
        pt, ct = self._extract_token_usage(msg)

        parsed = self._coerce_json(getattr(msg, "content", ""), want="object")
        if not isinstance(parsed, dict):
            raise ValueError("Expected JSON object for triage")

        return parsed, self._metadata(latency_ms=elapsed_ms, tokens_prompt=pt, tokens_completion=ct)

    def refine_rules(
        self,
        suggestions: List[Dict[str, Any]],
        examples: Optional[Dict[str, List[str]]] = None,
    ) -> Tuple[List[Dict[str, Any]], ProviderMetadata]:
        start = time.time()

        prompt = {
            "suggestions": suggestions,
            "examples": examples or {},
        }

        system = (
            "You are helping refine detection rules. "
            "Return ONLY a JSON array of rule objects. "
            "Constraints: keep existing rule ids, do not invent new ids, "
            "only adjust conditions/rationale/tags for clarity and specificity."
        )

        from langchain_core.messages import SystemMessage, HumanMessage  # type: ignore

        msg = self._chat.invoke([
            SystemMessage(content=system),
            HumanMessage(content=json.dumps(prompt, ensure_ascii=False)),
        ])

        elapsed_ms = int((time.time() - start) * 1000)
        pt, ct = self._extract_token_usage(msg)

        parsed = self._coerce_json(getattr(msg, "content", ""), want="array")
        if not isinstance(parsed, list):
            raise ValueError("Expected JSON array for refine_rules")

        # Return as-is; schema validation happens elsewhere in the pipeline.
        return parsed, self._metadata(latency_ms=elapsed_ms, tokens_prompt=pt, tokens_completion=ct)


__all__ = ["LangChainAPIProvider", "LangChainAPIConfig"]
