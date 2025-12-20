import torch
import os
import shutil
from transformers import AutoModelForCausalLM
from peft import PeftModel

def merge_and_chunk_custom_assets(base_path, adapter_path, output_path, max_shard_size="28MB"):
    """
    Merges SFT adapter into Base Qwen3, prioritizing SFT-specific tokenizer
    and template files (e.g., SFTchat_template.jinja), and saving output 
    in strict <30MiB safetensors chunks.
    """
    print(f"Base Source:    {base_path}")
    print(f"Adapter Source: {adapter_path}")
    print(f"Output Target:  {output_path}")

    # 1. Load Base Model
    print("Loading base model...")
    try:
        base_model = AutoModelForCausalLM.from_pretrained(
            base_path,
            torch_dtype=torch.bfloat16,
            device_map="cpu",
            trust_remote_code=True
        )
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to load base model. {e}")
        return

    # 2. Merge Adapter
    print("Merging SFT adapter...")
    try:
        model = PeftModel.from_pretrained(base_model, adapter_path)
        model = model.merge_and_unload()
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to merge adapter. {e}")
        return

    # 3. Save Merged Model with Chunking
    print(f"Saving model to {output_path} (max shard: {max_shard_size})...")
    model.save_pretrained(
        output_path,
        max_shard_size=max_shard_size,
        safe_serialization=True
    )

    # 4. Handle Tokenizer and Template Files
    print("Handling tokenizer and template files...")
    
    # Maps output filename -> list of source candidates (in priority order)
    # Now includes SFTchat_template.jinja priority
    file_mappings = {
        "tokenizer.json": ["tokenizerSFT.json", "tokenizer.json"],
        "tokenizer_config.json": ["tokenizerSFT_config.json", "tokenizer_config.json"],
        "chat_template.jinja": ["SFTchat_template.jinja", "chat_template.jinja"],
        "vocab.json": ["vocab.json"],
        "merges.txt": ["merges.txt"],
        "special_tokens_map.json": ["special_tokens_map.json"],
        "added_tokens.json": ["added_tokens.json"]
    }

    for output_name, source_candidates in file_mappings.items():
        src_file = None
        # Search for the highest priority candidate existing in base_path
        for candidate in source_candidates:
            candidate_path = os.path.join(base_path, candidate)
            if os.path.exists(candidate_path):
                src_file = candidate_path
                print(f"  Found source for {output_name}: {candidate}")
                break
        
        # Copy and rename to output directory
        if src_file:
            dst_file = os.path.join(output_path, output_name)
            try:
                shutil.copy(src_file, dst_file)
            except Exception as e:
                print(f"  Error copying {src_file}: {e}")
        else:
            # Inform user if standard files are missing (non-critical for some)
            if output_name in ["tokenizer.json", "vocab.json", "chat_template.jinja"]:
                print(f"  WARNING: Could not find any source for {output_name}")

    print(f"Process complete. Output saved to {output_path}")

if __name__ == "__main__":
    # Absolute paths based on your environment
    ROOT_DIR = "/home/joseph-mazzini/sys-scan-graph/agent/sys_scan_agent/models/local_qwen"
    
    BASE_DIR = os.path.join(ROOT_DIR, "base_qwen")
    ADAPTER_DIR = os.path.join(ROOT_DIR, "sft_adapter")
    OUTPUT_DIR = os.path.join(ROOT_DIR, "shards")

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    merge_and_chunk_custom_assets(BASE_DIR, ADAPTER_DIR, OUTPUT_DIR)