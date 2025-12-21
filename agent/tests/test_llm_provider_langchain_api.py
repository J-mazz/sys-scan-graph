from __future__ import annotations

import os

import pytest


def _reset_provider():
    # Reset global provider to force env-based init path.
    import sys_scan_agent.llm_provider as lp

    lp.set_llm_provider(lp.NullLLMProvider())


@pytest.mark.unit
def test_langchain_api_provider_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("AGENT_LLM_PROVIDER", "langchain-api")
    monkeypatch.delenv("AGENT_EXTERNAL_LLM_ENABLED", raising=False)

    _reset_provider()

    import sys_scan_agent.llm_provider as lp

    provider = lp.get_llm_provider()

    # Must NOT select external provider without explicit opt-in.
    assert provider.__class__.__name__ in {"LocalLLMProvider", "NullLLMProvider"}


@pytest.mark.unit
def test_langchain_api_provider_falls_back_when_deps_missing(monkeypatch):
    monkeypatch.setenv("AGENT_LLM_PROVIDER", "langchain-api")
    monkeypatch.setenv("AGENT_EXTERNAL_LLM_ENABLED", "1")
    # Use a provider that would require an extra integration package.
    monkeypatch.setenv("AGENT_LANGCHAIN_PROVIDER", "openai")
    monkeypatch.setenv("AGENT_LANGCHAIN_MODEL", "gpt-4o-mini")

    _reset_provider()

    import sys_scan_agent.llm_provider as lp

    provider = lp.get_llm_provider()

    # In CI/local-dev without optional deps installed, we should fall back safely.
    assert provider.__class__.__name__ in {"LocalLLMProvider", "NullLLMProvider"}
