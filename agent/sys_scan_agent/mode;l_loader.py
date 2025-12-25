import os
import sys
from huggingface_hub import hf_hub_download

def get_model_path(model_filename="qwen3_analyst.gguf", repo_id="J-mazz/sys-scan-graph"):
    """
    Ensures the model is available locally. Downloads from HF if missing.
    Returns the absolute path to the model file.
    """
    # Standard cache location: ~/.cache/huggingface/hub/...
    # You can customize this, but the default is best for standard tools.
    
    print(f"[*] Verifying model availability: {model_filename}...", file=sys.stderr)
    
    try:
        model_path = hf_hub_download(
            repo_id=repo_id,
            filename=model_filename,
            # force_download=False, # Default is False (uses cache if exists)
            # resume_download=True  # Helpful for large files
        )
        print(f"[*] Model located at: {model_path}", file=sys.stderr)
        return model_path
    except Exception as e:
        print(f"[!] CRITICAL: Failed to download model weights.\nError: {e}", file=sys.stderr)
        raise
