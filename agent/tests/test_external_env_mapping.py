from __future__ import annotations

import os

import pytest


def _reset_provider():
    # Reset global provider to force env-based init path.
    import sys_scan_agent.llm_provider as lp

    lp.set_llm_provider(lp.NullLLMProvider())


@pytest.mark.unit
def test_external_env_variables_map_to_agent_env(monkeypatch):
    # Clear any AGENT_* settings and set legacy EXTERNAL_* variables
    monkeypatch.delenv("AGENT_EXTERNAL_LLM_ENABLED", raising=False)
    monkeypatch.delenv("AGENT_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("AGENT_LANGCHAIN_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    monkeypatch.setenv("EXTERNAL_LLM_PROVIDER", "openai")
    monkeypatch.setenv("EXTERNAL_OPENAI_API_KEY", "test-openai-key-xyz")

    _reset_provider()

    import sys_scan_agent.llm_provider as lp

    # Trigger provider initialization which should map legacy vars
    _ = lp.get_llm_provider()

    assert os.environ.get("AGENT_EXTERNAL_LLM_ENABLED") == "1"
    assert os.environ.get("AGENT_LLM_PROVIDER") == "langchain-api"
    assert os.environ.get("AGENT_LANGCHAIN_PROVIDER") == "openai"
    assert os.environ.get("OPENAI_API_KEY") == "test-openai-key-xyz"
