#!/usr/bin/env python3
"""
Google Colab TPU Training Script for Security ML Models
This script handles the complete TPU setup and training pipeline for both Specialist and Generalist models.
"""

import os
import sys
import torch
import torch_xla.core.xla_model as xm
from transformers import AutoTokenizer
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_colab_tpu():
    """Setup Google Colab TPU environment."""
    print("🚀 Setting up Google Colab TPU environment...")

    # Check if running on TPU
    try:
        import torch_xla.core.xla_model as xm
        device = xm.xla_device()
        print(f"✅ TPU device detected: {device}")
        return True
    except ImportError:
        print("❌ torch_xla not available. Please install torch_xla for TPU support.")
        return False
    except:
        print("❌ TPU not detected. This script requires TPU runtime.")
        print("   Please change runtime to TPU in Google Colab.")
        return False

def install_dependencies():
    """Install required dependencies for Colab TPU."""
    print("📦 Installing ML dependencies...")

    # Install torch_xla for TPU support
    os.system("pip install torch_xla[tpu] -f https://storage.googleapis.com/libtpu-releases/index.html")

    # Install other dependencies
    dependencies = [
        "torch>=2.0.0",
        "transformers>=4.35.0",
        "peft>=0.6.0",
        "trl>=0.7.0",
        "datasets>=2.14.0",
        "accelerate>=0.24.0",
        "bitsandbytes>=0.41.0",
        "scipy>=1.11.0",
        "scikit-learn>=1.3.0",
        "wandb>=0.15.0",
        "tensorboard>=2.14.0"
    ]

    for dep in dependencies:
        os.system(f"pip install {dep}")

    print("✅ Dependencies installed")

def verify_tpu_setup():
    """Verify TPU setup and print configuration."""
    print("🔍 Verifying TPU setup...")

    try:
        # Check TPU availability
        tpu_device = xm.xla_device()
        print(f"✅ TPU Device: {tpu_device}")

        # Check TPU cores
        num_cores = xm.xrt_world_size()
        print(f"✅ TPU Cores: {num_cores}")

        # Check memory
        if hasattr(torch, 'xla'):
            print("✅ torch_xla available")
        else:
            print("❌ torch_xla not properly configured")

        return True

    except Exception as e:
        print(f"❌ TPU setup verification failed: {e}")
        return False

def prepare_data_for_colab():
    """Prepare training data for Colab environment."""
    print("📊 Preparing training data...")

    # Check if data exists
    data_archive = Path("../../massive_datasets.tar.gz")
    if not data_archive.exists():
        print(f"❌ Data archive not found at {data_archive}")
        print("   Please upload massive_datasets.tar.gz to the project root")
        return False

    # Create training data directory
    training_dir = Path("training_data")
    training_dir.mkdir(exist_ok=True)

    # Run data preparation
    print("🔄 Running data preparation pipeline...")
    os.system("python ml_pipeline/data_loader.py")

    # Verify data was created
    specialist_data = training_dir / "specialist_data.jsonl"
    generalist_data = training_dir / "generalist_data.jsonl"

    if specialist_data.exists() and generalist_data.exists():
        print("✅ Training data prepared successfully")
        return True
    else:
        print("❌ Training data preparation failed")
        return False

def train_specialist_model(hf_token=None):
    """Train the Specialist model on TPU."""
    print("🎯 Training Specialist Model...")

    cmd = "python ml_pipeline/train_specialist.py"
    if hf_token:
        cmd += f" --huggingface-token {hf_token}"

    print(f"Running: {cmd}")
    result = os.system(cmd)

    if result == 0:
        print("✅ Specialist model training completed")
        return True
    else:
        print("❌ Specialist model training failed")
        return False

def train_generalist_model(hf_token=None):
    """Train the Generalist model on TPU with LoRA."""
    print("🧠 Training Generalist Model (LoRA)...")

    cmd = "python ml_pipeline/train_generalist.py"
    if hf_token:
        cmd += f" --huggingface-token {hf_token}"

    print(f"Running: {cmd}")
    result = os.system(cmd)

    if result == 0:
        print("✅ Generalist model training completed")
        return True
    else:
        print("❌ Generalist model training failed")
        return False

def main():
    parser = argparse.ArgumentParser(description="Colab TPU Training Pipeline")
    parser.add_argument(
        "--huggingface-token",
        type=str,
        help="HuggingFace token for accessing gated models (can also be set via HF_TOKEN env var)"
    )
    parser.add_argument(
        "--skip-setup",
        action="store_true",
        help="Skip dependency installation and TPU setup"
    )
    parser.add_argument(
        "--data-only",
        action="store_true",
        help="Only prepare data, don't train models"
    )
    parser.add_argument(
        "--specialist-only",
        action="store_true",
        help="Only train specialist model"
    )
    parser.add_argument(
        "--generalist-only",
        action="store_true",
        help="Only train generalist model"
    )

    args = parser.parse_args()

    # Handle HuggingFace token from environment variable or argument
    hf_token = args.huggingface_token or os.getenv('HF_TOKEN') or os.getenv('HUGGINGFACE_TOKEN')

    if not hf_token:
        print("⚠️  WARNING: No HuggingFace token provided!")
        print("   Set via --huggingface-token argument or HF_TOKEN environment variable")
        print("   Some models may not be accessible without authentication")
        print()

    print("🤖 Security ML Training Pipeline for Google Colab TPU")
    print("=" * 60)
    if hf_token:
        print("🔐 HuggingFace token: Configured ✓")
    else:
        print("🔐 HuggingFace token: Not configured ⚠️")
    print()

    # Setup phase
    if not args.skip_setup:
        if not setup_colab_tpu():
            sys.exit(1)

        install_dependencies()

        if not verify_tpu_setup():
            sys.exit(1)

    # Data preparation
    if not prepare_data_for_colab():
        sys.exit(1)

    if args.data_only:
        print("📊 Data preparation completed. Exiting.")
        return

    # Training phase
    success = True

    if not args.generalist_only:
        if not train_specialist_model(hf_token):
            success = False

    if not args.specialist_only:
        if not train_generalist_model(hf_token):
            success = False

    if success:
        print("\n🎉 All training completed successfully!")
        print("📁 Models saved in:")
        print("   - models/specialist_model/")
        print("   - models/generalist_model_lora/")
        print("\n🚀 Next steps:")
        print("   1. Run quantization: python ml_pipeline/quantize_and_deploy.py")
        print("   2. Integrate with LangGraph: Update agent/providers/")
        print("   3. Test the complete pipeline")
    else:
        print("\n❌ Training failed. Check logs above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()