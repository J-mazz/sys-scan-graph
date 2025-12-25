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
        from ..config import MODEL_FILENAME
        sys_dir = Path("/usr/share/sys-scan-agent/models")
        if (sys_dir / MODEL_FILENAME).exists():
            return sys_dir

        # 3. Wheel/Package Path (Default)
        # Looks for: sys_scan_agent/models/local_qwen
        return Path(__file__).parent.parent / "models" / "local_qwen"

    def _reassemble_if_needed(self, target_gguf: Path) -> Path:
        """Stitches split GGUF chunks (file.gguf.part.**) back together.

        Assembles into user cache (~/.cache/sys-scan-agent/models) and returns the
        cache path for loading. Raises FileNotFoundError if no shards found.

        Optimizations:
         - Check cache first and verify against shard metadata (size + mtime)
         - Use a larger buffer and atomic replace to minimize I/O overhead and races
        """
        if target_gguf.exists():
            return target_gguf

        # Efficiently enumerate candidate shards using os.scandir to reduce syscall overhead
        shards_dir = target_gguf.parent / "shards"
        candidate_prefix = f"{target_gguf.name}.part"

        def _collect_from_dir(d: Path) -> List[Path]:
            if not d.exists():
                return []
            results: List[Path] = []
            for entry in os.scandir(d):
                if not entry.is_file():
                    continue
                name = entry.name
                # Accept patterns like: <name>.part.001, <name>.part.aa, or <name>.partXX (split default)
                if name.startswith(candidate_prefix) or ".part." in name or name.endswith(".part"):
                    results.append(Path(entry.path))
            return results

        shards = _collect_from_dir(shards_dir)
        if not shards:
            shards = _collect_from_dir(target_gguf.parent)

        if not shards:
            raise FileNotFoundError(f"No GGUF or shards found at {target_gguf}")

        # Robust ordering: prefer numeric suffix ordering when present, else lexicographic
        def _sort_key(p: Path):
            name = p.name
            # look for suffix after last '.' (e.g., '.001' or '.aa')
            parts = name.rsplit('.', 1)
            if len(parts) == 2:
                suffix = parts[1]
                try:
                    return (0, int(suffix))
                except Exception:
                    return (1, suffix)
            # fallback to the full name
            return (2, name)

        shards = sorted(shards, key=_sort_key)

        if not shards:
            raise FileNotFoundError(f"No GGUF or shards found at {target_gguf}")

        # Collect shard metadata in a single pass
        shard_meta = []  # list of (Path, size, mtime)
        total_size = 0
        latest_mtime = 0
        for s in shards:
            st = s.stat()
            shard_meta.append((s, st.st_size, st.st_mtime))
            total_size += st.st_size
            if st.st_mtime > latest_mtime:
                latest_mtime = st.st_mtime

        # Assemble into user cache to avoid permission errors in site-packages
        cache_dir = Path.home() / ".cache" / "sys-scan-agent" / "models"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached_model = cache_dir / target_gguf.name

        if cached_model.exists():
            cst = cached_model.stat()
            # If cached model size matches and it's newer than shards, assume valid
            if cst.st_size == total_size and cst.st_mtime >= latest_mtime:
                return cached_model
            try:
                cached_model.unlink()
            except Exception:
                pass

        logger.info(f"🔨 Reassembling model from {len(shards)} chunks into {cached_model}...")
        tmp = cached_model.with_suffix(cached_model.suffix + ".part_tmp")
        try:
            # Use optimized buffered copy
            from ..models.assemble import assemble_shards
            assemble_shards([p for p,_,_ in shard_meta], tmp, buffer_size=4 * 1024 * 1024)
            # atomic replace
            tmp.replace(cached_model)
            logger.info(f"✅ Model reassembled: {cached_model}")
            return cached_model
        except Exception as e:
            if tmp.exists():
                tmp.unlink()
            if cached_model.exists():
                try:
                    cached_model.unlink()
                except Exception:
                    pass
            raise RuntimeError(f"Reassembly failed: {e}")

    def _lazy_load(self):
        if self._model_initialized: return
        self._model_initialized = True

        try:
            from llama_cpp import Llama
            from ..config import MODEL_FILENAME, get_model_path

            # Fast path: if an assembled model exists in system/user/cache paths, use it
            found = get_model_path()
            if found:
                final_path = found
            else:
                base_path = self.model_dir / MODEL_FILENAME
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