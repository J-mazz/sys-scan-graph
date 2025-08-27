from __future__ import annotations
"""LangChain-based LLM Provider (experimental) INT-FUT-LLM

This provider adapts the ILLMProvider interface onto LangChain Expression Language.
It supports only summarize() initially; other methods fall back to heuristics.

Environment Variables:
  AGENT_OPENAI_API_KEY          - API key (DO NOT commit; load via .env / secrets)
  AGENT_OPENAI_MODEL            - Model name (default gpt-4o-mini)
  AGENT_LLM_TIMEOUT_S           - Optional request timeout seconds (default 30)

Safety:
  All inputs are redacted via DataGovernor before leaving process boundary.
"""
import os, time
from typing import List, Optional, Dict, Any
from ..models import Reductions, Correlation, Summaries, ActionItem
from ..llm_provider import ILLMProvider, NullLLMProvider
from ..data_governance import get_data_governor

try:  # Lazy import to avoid hard dependency if user doesn't enable
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
except Exception:  # pragma: no cover - missing optional deps
    ChatOpenAI = None
    ChatPromptTemplate = None


SUMMARY_TEMPLATE = (
    "You are a security analyst. Produce a concise executive summary (<=120 words) "
    "highlighting module stats, notable SUID anomalies, listening ports, and any correlations. "
    "Focus on risk-relevant changes.\n"
    "Top Findings (redacted JSON): {top_findings}\n"
    "Module Summary: {module_summary}\n"
    "SUID Summary: {suid_summary}\n"
    "Network Summary: {network_summary}\n"
    "Correlations: {correlation_titles}\n"
    "Return only the summary paragraph." 
)


class LangChainLLMProvider(ILLMProvider):
    def __init__(self):
        if ChatOpenAI is None:
            raise RuntimeError("LangChain / openai extra not installed. pip install langchain-openai")
        api_key = os.environ.get('AGENT_OPENAI_API_KEY') or os.environ.get('OPENAI_API_KEY')
        if not api_key:
            raise RuntimeError("Missing AGENT_OPENAI_API_KEY/OPENAI_API_KEY for LangChain provider")
        model = os.environ.get('AGENT_OPENAI_MODEL','gpt-4o-mini')
        timeout = float(os.environ.get('AGENT_LLM_TIMEOUT_S','30') or 30)
        self.llm = ChatOpenAI(model=model, api_key=api_key, timeout=timeout)
        self.prompt = ChatPromptTemplate.from_template(SUMMARY_TEMPLATE)
        self.null_fallback = NullLLMProvider()
        self.governor = get_data_governor()

    # -------- ILLMProvider methods --------
    def summarize(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem], *,
                  skip: bool = False, previous: Optional[Summaries] = None,
                  skip_reason: Optional[str] = None, baseline_context: Optional[Dict[str, Any]] = None) -> Summaries:
        if skip:
            return self.null_fallback.summarize(reductions, correlations, actions, skip=skip, previous=previous, skip_reason=skip_reason)
        # Redact reductions top findings only (already redacted fields inside pipeline earlier for titles)
        red_top = self.governor.redact_for_llm(reductions.top_findings) if reductions.top_findings else []
        mod = reductions.module_summary or {}
        suid = reductions.suid_summary or {}
        net = reductions.network_summary or {}
        corr_titles = [c.title for c in correlations]
        start = time.time()
        try:
            chain = self.prompt | self.llm
            summary_text = chain.invoke({
                'top_findings': red_top,
                'module_summary': mod,
                'suid_summary': suid,
                'network_summary': net,
                'correlation_titles': corr_titles
            }).content.strip()
        except Exception:
            # Fallback to heuristic provider on error
            return self.null_fallback.summarize(reductions, correlations, actions, previous=previous)
        elapsed = int((time.time()-start)*1000)
        # Approximate token counts (very rough heuristic); real impl could call tiktoken
        pt = 200 + len(red_top)*20
        ct = len(summary_text.split()) // 0.75  # approx tokens ~ words/0.75
        metrics = {
            'provider': 'langchain-openai',
            'tokens_prompt': int(pt),
            'tokens_completion': int(ct),
            'latency_ms': elapsed,
            'findings_count': len(red_top)
        }
        if baseline_context:
            summary_text += f"\nBaseline references: {len(baseline_context)} findings checked."
        return Summaries(executive_summary=summary_text, metrics=metrics, explanation_provenance={
            'executive_summary': [f.get('id') for f in red_top]
        })

    def refine_rules(self, suggestions: List[Dict[str, Any]], examples: Optional[Dict[str, List[str]]] = None) -> List[Dict[str, Any]]:  # pragma: no cover
        return self.null_fallback.refine_rules(suggestions, examples)

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Dict[str, Any]:  # pragma: no cover
        return self.null_fallback.triage(reductions, correlations)

__all__ = ['LangChainLLMProvider']