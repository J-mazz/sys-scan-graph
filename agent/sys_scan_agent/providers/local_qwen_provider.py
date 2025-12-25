from __future__ import annotations
"""Local Qwen provider for zero-trust, offline inference using GGUF/llama.cpp.

This provider uses a quantized GGUF model downloaded via the Hugging Face Hub.
It falls back to the heuristic provider if the model cannot be loaded.
"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import logging
import os
from pathlib import Path

# Import the model loader we created earlier
from .. import get_model_path, models
from ..llm_provider import ILLMProvider, ProviderMetadata, NullLLMProvider

logger = logging.getLogger(__name__)

Reductions = models.Reductions
Correlation = models.Correlation
Summaries = models.Summaries
ActionItem = models.ActionItem

class LocalQwenLLMProvider(ILLMProvider):
    """Local Qwen model wrapper using llama.cpp for GGUF inference."""

    def __init__(self, *, model_dir: Optional[str] = None, device: str = "auto"):
        # 'device' is largely automatic in llama.cpp but we keep the signature compatible
        self.device = device
        self.model_path_override = model_dir
        self._model = None
        self._delegate = NullLLMProvider()
        self._load_error: Optional[Exception] = None
        self.model_name = "qwen-local-gguf"
        self.provider_name = "local-agent"
        self._model_initialized = False

    def _lazy_load(self) -> None:
        if self._model_initialized:
            return
        self._model_initialized = True
        
        try:
            # Import here to avoid hard dependency at module level
            from llama_cpp import Llama 

            # 1. Determine the model path
            if self.model_path_override and Path(self.model_path_override).exists():
                final_model_path = str(self.model_path_override)
            else:
                # Use the utility to fetch/cache the 10GB GGUF file
                final_model_path = get_model_path()

            # 2. Initialize the Llama backend
            self._model = Llama(
                model_path=final_model_path,
                n_ctx=8192,         # Context window size
                n_gpu_layers=-1,    # Offload all layers to GPU if available
                verbose=False       # Reduce noise in logs
            )
            
            logger.info("✓ Loaded local Qwen GGUF from %s", final_model_path)

        except Exception as exc:
            self._load_error = exc
            self._model = None
            logger.warning("Local Qwen load failed, using heuristic fallback: %s", exc)

    def _retag_metadata(self, metadata: ProviderMetadata) -> ProviderMetadata:
        data = metadata._asdict()
        data.update({
            "model_name": self.model_name,
            "provider_name": self.provider_name,
            "timestamp": data.get("timestamp") or datetime.now().isoformat(),
            "error_message": self._load_error and str(self._load_error),
        })
        return ProviderMetadata(**data)

    def _maybe_generate(self, prompt: str, *, max_new_tokens: int = 512, temperature: float = 0.1) -> Optional[str]:
        """Generates text using the llama.cpp instance."""
        self._lazy_load()
        if not self._model:
            return None
        
        try:
            # llama-cpp-python API differs from transformers
            output = self._model(
                prompt,
                max_tokens=max_new_tokens,
                temperature=temperature,
                stop=["<|im_end|>", "<|endoftext|>"], # Standard Qwen stops
                echo=False 
            )
            return output['choices'][0]['text']
        except Exception as exc:
            logger.warning("Local Qwen generation failed, falling back: %s", exc)
            return None

    def _summary_prompt(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem]) -> str:
        # Simplified prompt for the chat model
        return (
            "<|im_start|>system\n"
            "You are a local security analyst. Summarize these security findings.\n"
            "<|im_end|>\n"
            "<|im_start|>user\n"
            f"Findings: {reductions}\n"
            f"Correlations: {correlations}\n"
            f"Actions: {actions}\n"
            "<|im_end|>\n"
            "<|im_start|>assistant\n"
        )

    # ... (Rest of the class methods: summarize, refine_rules, triage remain the same) ...
    # You can copy the exact same implementations of summarize, refine_rules, 
    # and triage from your original file as they just call _maybe_generate.

    def summarize(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem], *,
                  skip: bool = False, previous: Optional[Summaries] = None,
                  skip_reason: Optional[str] = None, baseline_context: Optional[Dict[str, Any]] = None) -> Tuple[Summaries, ProviderMetadata]:
        result, metadata = self._delegate.summarize(
            reductions, correlations, actions,
            skip=skip, previous=previous, skip_reason=skip_reason,
            baseline_context=baseline_context
        )
        if not skip:
            prompt = self._summary_prompt(reductions, correlations, actions)
            generated = self._maybe_generate(prompt)
            if generated:
                result.executive_summary = generated
        return result, self._retag_metadata(metadata)

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], ProviderMetadata]:
        result, metadata = self._delegate.refine_rules(suggestions, examples)
        return result, self._retag_metadata(metadata)

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]:
        result, metadata = self._delegate.triage(reductions, correlations)
        return result, self._retag_metadata(metadata)
