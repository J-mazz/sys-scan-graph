from __future__ import annotations
import os
import glob
import shutil
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

# Core Interfaces
from ..llm_provider import ILLMProvider, ProviderMetadata, NullLLMProvider
from .. import models

logger = logging.getLogger(__name__)

class LocalQwenLLMProvider(ILLMProvider):
    """
    Zero-trust local provider using GGUF (Llama.cpp).
    Automatically reassembles chunked model files from the Python package.
    """
    def __init__(self, *, model_dir: Optional[str] = None, n_ctx: int = 4096, device: str = "auto"):
        self.model_dir = self._resolve_model_dir(model_dir)
        self.n_ctx = n_ctx
        self._llm = None
        self._model_initialized = False
        self._load_error = None
        self.provider_name = "local-agent"
        self.model_name = "qwen-local-gguf"
        
        # Fallback delegate if loading fails
        self._delegate = NullLLMProvider()

    def _resolve_model_dir(self, override: Optional[str]) -> Path:
        if override: return Path(override)
        # 1. Env Var Override
        if os.environ.get("AGENT_LOCAL_QWEN_MODEL_DIR"):
            return Path(os.environ["AGENT_LOCAL_QWEN_MODEL_DIR"])
        
        # 2. Debian/System Path (Production)
        sys_path = Path("/usr/share/sys-scan/models/qwen_security_agent.gguf")
        if sys_path.exists(): return sys_path.parent
            
        # 3. Wheel/Package Path (Default)
        # Looks for: sys_scan_agent/models/local_qwen
        return Path(__file__).parent.parent / "models" / "local_qwen"

    def _reassemble_if_needed(self, target_gguf: Path) -> Path:
        """Stitches split GGUF chunks (file.gguf.part.aa) back together."""
        if target_gguf.exists():
            return target_gguf

        # Look for chunks in ./shards/ or ./
        shards = sorted(target_gguf.parent.glob("shards/*.part.*")) or \
                 sorted(target_gguf.parent.glob("*.part.*"))

        if not shards:
            raise FileNotFoundError(f"No GGUF or shards found at {target_gguf}")

        # Assemble into user cache to avoid permission errors in site-packages
        cache_dir = Path.home() / ".cache" / "sys-scan-agent" / "models"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached_model = cache_dir / target_gguf.name

        if cached_model.exists():
            # Check size roughly matches sum of shards? (Optional optimization)
            return cached_model

        logger.info(f"🔨 Reassembling model from {len(shards)} chunks...")
        try:
            with open(cached_model, 'wb') as outfile:
                for shard in shards:
                    with open(shard, 'rb') as infile:
                        shutil.copyfileobj(infile, outfile)
            logger.info(f"✅ Model reassembled: {cached_model}")
            return cached_model
        except Exception as e:
            if cached_model.exists(): cached_model.unlink()
            raise RuntimeError(f"Reassembly failed: {e}")

    def _lazy_load(self):
        if self._model_initialized: return
        self._model_initialized = True

        try:
            from llama_cpp import Llama
            
            base_path = self.model_dir / "qwen_security_agent.gguf"
            final_path = self._reassemble_if_needed(base_path)

            logger.info(f"Loading local Qwen: {final_path}")
            self._llm = Llama(
                model_path=str(final_path),
                n_ctx=self.n_ctx,
                n_gpu_layers=-1, # Auto-offload to Vulkan/CUDA
                verbose=False
            )
        except Exception as e:
            self._load_error = e
            logger.warning(f"Failed to load Local Qwen: {e}")

    def _maybe_generate(self, prompt: str, **kwargs) -> Optional[str]:
        self._lazy_load()
        if not self._llm: return None
        
        try:
            # Qwen Chat Template
            formatted = f"<|im_start|>system\nYou are a security analyst.<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
            
            output = self._llm(
                formatted, 
                max_tokens=kwargs.get('max_new_tokens', 512),
                stop=["<|im_end|>"],
                temperature=kwargs.get('temperature', 0.1)
            )
            return output['choices'][0]['text'].strip()
        except Exception as e:
            logger.error(f"Inference error: {e}")
            return None

    # Implement Interface Methods using _maybe_generate
    def summarize(self, reductions, correlations, actions, **kwargs):
        # ... logic to build prompt string ...
        prompt = f"Summarize these findings: {reductions}" 
        text = self._maybe_generate(prompt)
        # ... wrap in result object ...
        return models.Summaries(executive_summary=text or ""), ProviderMetadata(model_name=self.model_name)

    # (Add other required interface methods like refine_rules, triage here, deferring to _delegate on failure)
    def refine_rules(self, *args, **kwargs): return self._delegate.refine_rules(*args, **kwargs)
    def triage(self, *args, **kwargs): return self._delegate.triage(*args, **kwargs)