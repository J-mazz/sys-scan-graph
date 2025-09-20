"""
Quantization and packaging script for fine-tuned models.

This script merges LoRA adapters, converts models to GGUF format,
and quantizes them for efficient inference.
"""

import os
import subprocess
import shutil
from pathlib import Path
from peft import AutoPeftModelForCausalLM
from transformers import AutoTokenizer


def setup_llama_cpp():
    """Clone and build llama.cpp if not already available."""
    if not os.path.exists("llama.cpp"):
        print("Cloning llama.cpp repository...")
        subprocess.run(["git", "clone", "https://github.com/ggerganov/llama.cpp.git"],
                      check=True)

    os.chdir("llama.cpp")

    if not os.path.exists("build"):
        print("Building llama.cpp...")
        os.makedirs("build", exist_ok=True)
        os.chdir("build")
        subprocess.run(["cmake", ".."], check=True)
        subprocess.run(["make", "-j$(nproc)"], check=True, shell=True)
        os.chdir("..")

    os.chdir("..")
    print("✅ llama.cpp setup complete.")


def merge_lora_adapters(adapter_path: str, output_path: str):
    """
    Merge LoRA adapters with the base model.

    Args:
        adapter_path: Path to LoRA adapters
        output_path: Path to save merged model
    """
    print(f"Merging LoRA adapters from {adapter_path}...")

    # Load the model with LoRA adapters
    merged_model = AutoPeftModelForCausalLM.from_pretrained(
        adapter_path,
        low_cpu_mem_usage=True,
        torch_dtype="auto",  # Use float16 for merging
    )

    # Merge and unload
    merged_model = merged_model.merge_and_unload()

    # Save the merged model
    os.makedirs(output_path, exist_ok=True)
    merged_model.save_pretrained(output_path, safe_serialization=True)

    # Save tokenizer
    tokenizer = AutoTokenizer.from_pretrained(adapter_path)
    tokenizer.save_pretrained(output_path)

    print(f"✅ Merged model saved to {output_path}")


def convert_to_gguf(model_path: str, output_file: str):
    """
    Convert PyTorch model to GGUF format using llama.cpp.

    Args:
        model_path: Path to the PyTorch model
        output_file: Output GGUF file path
    """
    print(f"Converting model to GGUF: {model_path} -> {output_file}")

    # Ensure we're in the llama.cpp directory
    original_dir = os.getcwd()
    os.chdir("llama.cpp")

    try:
        # Run the conversion script
        cmd = [
            "python", "convert.py",
            f"../{model_path}",
            "--outfile", f"../{output_file}",
            "--outtype", "q4_K_M"
        ]

        subprocess.run(cmd, check=True)
        print(f"✅ Model converted and quantized to {output_file}")

    finally:
        os.chdir(original_dir)


def quantize_specialist_model():
    """Quantize the specialist model."""
    specialist_model_path = "models/specialist_model_fine_tuned"
    specialist_gguf_path = "models/specialist_model_q4km.gguf"

    if not os.path.exists(specialist_model_path):
        print(f"❌ Specialist model not found at {specialist_model_path}")
        return

    print("🔄 Quantizing Specialist model...")
    convert_to_gguf(specialist_model_path, specialist_gguf_path)


def quantize_generalist_model():
    """Quantize the generalist model."""
    generalist_adapter_path = "models/generalist_model_lora_adapters"
    generalist_merged_path = "models/generalist_model_merged"
    generalist_gguf_path = "models/generalist_model_q4km.gguf"

    if not os.path.exists(generalist_adapter_path):
        print(f"❌ Generalist LoRA adapters not found at {generalist_adapter_path}")
        return

    print("🔄 Merging and quantizing Generalist model...")

    # First merge the LoRA adapters
    merge_lora_adapters(generalist_adapter_path, generalist_merged_path)

    # Then convert to GGUF
    convert_to_gguf(generalist_merged_path, generalist_gguf_path)


def create_model_package():
    """Create a package with both quantized models."""
    package_dir = "models/package"
    os.makedirs(package_dir, exist_ok=True)

    models_to_package = [
        "models/specialist_model_q4km.gguf",
        "models/generalist_model_q4km.gguf"
    ]

    for model_file in models_to_package:
        if os.path.exists(model_file):
            shutil.copy2(model_file, package_dir)
            print(f"✅ Copied {model_file} to package")
        else:
            print(f"⚠️  Model file not found: {model_file}")

    # Create a README for the package
    readme_content = """# Fine-Tuned Model Package

This package contains two quantized models for the Sys-Scan-Graph intelligence layer:

## Models

### Specialist Model (specialist_model_q4km.gguf)
- Base: Llama 3 8B
- Fine-tuned on: Security-specific data
- Use case: Security analysis, threat detection, compliance checking
- Quantization: Q4_K_M (4-bit with medium quality)

### Generalist Model (generalist_model_q4km.gguf)
- Base: Mixtral 8x7B Instruct
- Fine-tuned on: General knowledge data
- Use case: General analysis, context understanding, report generation
- Quantization: Q4_K_M (4-bit with medium quality)

## Usage

Load these models using llama.cpp or compatible inference engines for efficient CPU/GPU inference.

## Performance

Both models are optimized for:
- Low memory footprint
- Fast inference
- High accuracy on their respective domains
"""

    with open(os.path.join(package_dir, "README.md"), "w") as f:
        f.write(readme_content)

    print(f"✅ Model package created at {package_dir}")


def main():
    """Main function to run quantization and packaging."""
    print("🚀 Starting Model Quantization and Packaging")

    try:
        # Setup llama.cpp
        setup_llama_cpp()

        # Quantize models
        quantize_specialist_model()
        quantize_generalist_model()

        # Create package
        create_model_package()

        print("✅ All models quantized and packaged successfully!")
        print("📦 Package available at: models/package/")

    except Exception as e:
        print(f"❌ Error during quantization: {e}")
        raise


if __name__ == "__main__":
    main()