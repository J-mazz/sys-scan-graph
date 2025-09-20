"""
Main training orchestrator for fine-tuning models on TPU.

This script coordinates the entire fine-tuning pipeline:
1. Setup environment and dependencies
2. Authenticate with Hugging Face
3. Prepare training data
4. Fine-tune Specialist model (Llama 3 8B)
5. Fine-tune Generalist model (Mixtral 8x7B with LoRA)
6. Quantize and package models

Designed for Google Colab TPU environment.
"""

import os
import sys
import subprocess
from pathlib import Path


def install_dependencies():
    """Install required dependencies for TPU training."""
    print("📦 Installing dependencies...")

    # Install PyTorch/XLA for TPU support
    subprocess.run([
        "pip", "install", "cloud-tpu-client",
        "https://storage.googleapis.com/tpu-pytorch/wheels/colab/torch_xla-2.1-cp310-cp310-linux_x86_64.whl",
        "-q"
    ], check=True)

    # Install ML libraries
    ml_packages = [
        "transformers==4.40.1",
        "peft==0.10.0",
        "accelerate==0.29.3",
        "llama-cpp-python==0.2.77",
        "trl==0.8.6",
        "datasets",
        "huggingface_hub"
    ]

    for package in ml_packages:
        subprocess.run(["pip", "install", package, "-q"], check=True)

    print("✅ Dependencies installed successfully.")


def setup_authentication():
    """Setup Hugging Face authentication."""
    import getpass

    if 'HF_TOKEN' not in os.environ:
        hf_token = getpass.getpass('Enter your Hugging Face Hub token: ')
        os.environ['HF_TOKEN'] = hf_token

    # Verify token
    from huggingface_hub import HfApi
    api = HfApi()
    try:
        user = api.whoami()
        print(f"✅ Authenticated as: {user['name']}")
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        sys.exit(1)


def verify_dataset():
    """Verify that the dataset is available."""
    dataset_path = "massive_datasets.tar.gz"
    if not os.path.exists(dataset_path):
        print("❌ Dataset not found!")
        print("Please upload your 'massive_datasets.tar.gz' file to the current directory.")
        print("You can do this by:")
        print("1. Clicking the folder icon in the left sidebar")
        print("2. Navigating to the sys-scan-graph directory")
        print("3. Uploading your dataset file")
        sys.exit(1)
    else:
        print("✅ Dataset found.")


def prepare_data():
    """Prepare training data from the dataset."""
    print("📊 Preparing training data...")

    # Import and run data preparation
    sys.path.append('agent/ml_pipeline')
    from data_loader import create_training_files

    create_training_files()


def fine_tune_specialist():
    """Fine-tune the Specialist model."""
    print("🎯 Fine-tuning Specialist model...")

    # Run specialist training
    result = subprocess.run([
        "python", "agent/ml_pipeline/train_specialist.py"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Specialist model training failed:")
        print(result.stderr)
        sys.exit(1)

    print("✅ Specialist model fine-tuned successfully.")


def fine_tune_generalist():
    """Fine-tune the Generalist model."""
    print("🌐 Fine-tuning Generalist model...")

    # Run generalist training
    result = subprocess.run([
        "python", "agent/ml_pipeline/train_generalist.py"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Generalist model training failed:")
        print(result.stderr)
        sys.exit(1)

    print("✅ Generalist model fine-tuned successfully.")


def quantize_models():
    """Quantize and package the models."""
    print("⚡ Quantizing models...")

    # Run quantization
    result = subprocess.run([
        "python", "agent/ml_pipeline/quantize_models.py"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Model quantization failed:")
        print(result.stderr)
        sys.exit(1)

    print("✅ Models quantized and packaged successfully.")


def main():
    """Main orchestration function."""
    print("🚀 Starting Sys-Scan-Graph Model Fine-Tuning Pipeline")
    print("=" * 60)

    try:
        # Step 1: Install dependencies
        install_dependencies()

        # Step 2: Setup authentication
        setup_authentication()

        # Step 3: Verify dataset
        verify_dataset()

        # Step 4: Prepare data
        prepare_data()

        # Step 5: Fine-tune Specialist model
        fine_tune_specialist()

        # Step 6: Fine-tune Generalist model
        fine_tune_generalist()

        # Step 7: Quantize models
        quantize_models()

        print("=" * 60)
        print("🎉 Pipeline completed successfully!")
        print("📦 Your quantized models are available in: models/package/")
        print("   - specialist_model_q4km.gguf")
        print("   - generalist_model_q4km.gguf")
        print("\nDownload these files for integration into your application.")

    except KeyboardInterrupt:
        print("\n⚠️  Pipeline interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Pipeline failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
