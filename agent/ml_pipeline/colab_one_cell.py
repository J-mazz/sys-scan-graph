"""
Complete Fine-Tuning Pipeline for Colab TPU
Copy and paste this entire cell into Google Colab and run it.
Make sure to:
1. Change runtime to TPU
2. Upload massive_datasets.tar.gz to your Colab workspace (or update download_dataset.py with your URL)
3. Have your Hugging Face token ready

NOTE: To avoid uploading large files repeatedly, update the download_dataset.py script
with your dataset URL (GitHub releases, Google Drive, etc.) and the script will
download it automatically.
"""

# Install dependencies (robust installation with fallbacks)
print("📦 Installing dependencies...")

# Install PyTorch first (CPU version for compatibility)
try:
    !pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu -q
    print("✅ PyTorch installed successfully")
except Exception as e:
    print(f"⚠️ PyTorch installation issue: {e}")
    !pip install torch torchvision torchaudio -q

# Try to install torch_xla (with multiple fallback methods)
torch_xla_installed = False
try:
    print("🔄 Attempting torch_xla installation...")
    !pip install torch_xla[tpu] -f https://storage.googleapis.com/libtpu-wheels/index.html -q
    torch_xla_installed = True
    print("✅ torch_xla installed successfully")
except Exception as e:
    print(f"⚠️ torch_xla installation failed: {e}")
    print("🔄 Trying alternative installation method...")

    try:
        # Try installing from PyPI directly
        !pip install torch_xla -q
        torch_xla_installed = True
        print("✅ torch_xla installed via PyPI")
    except Exception as e2:
        print(f"⚠️ PyPI torch_xla installation failed: {e2}")
        print("🔄 Trying nightly build...")
        try:
            !pip install torch_xla --pre -q
            torch_xla_installed = True
            print("✅ torch_xla installed via nightly build")
        except Exception as e3:
            print(f"⚠️ Nightly torch_xla installation failed: {e3}")
            print("⚠️ TPU support will not be available - falling back to CPU training")
            torch_xla_installed = False

# Install other ML libraries
try:
    !pip install transformers==4.40.1 peft==0.10.0 accelerate==0.29.3 llama-cpp-python==0.2.77 trl==0.8.6 datasets huggingface_hub -q
    print("✅ ML libraries installed successfully")
except Exception as e:
    print(f"❌ Failed to install ML libraries: {e}")
    print("🔄 Installing with fallback versions...")
    !pip install transformers peft accelerate trl datasets huggingface_hub -q
    print("✅ ML libraries installed with fallback versions")

# Store TPU availability for later use
TPU_AVAILABLE = torch_xla_installed
print(f"🔧 TPU Available: {TPU_AVAILABLE}")

# Clone and setup repo (fixed path handling)
import os
if not os.path.exists("sys-scan-graph"):
    !git clone https://github.com/Mazzlabs/sys-scan-graph.git

# Change to the correct directory (avoid nested cd issues)
if os.path.exists("sys-scan-graph"):
    os.chdir("sys-scan-graph")
else:
    print("⚠️ Repository directory not found after cloning")
print(f"Current directory: {os.getcwd()}")

# Authentication
import os
from huggingface_hub import HfApi

# Try to get token from Colab secrets first
hf_token = None
try:
    from google.colab import userdata
    hf_token = userdata.get('HF_TOKEN')
    if hf_token:
        print("✅ HF_TOKEN loaded from Colab secrets")
    else:
        print("⚠️ HF_TOKEN not found in Colab secrets")
except ImportError:
    print("⚠️ Not running in Colab, checking environment variable")
    hf_token = os.environ.get('HF_TOKEN')

# If no token, try to get it interactively
if not hf_token:
    try:
        from google.colab import userdata
        print("🔑 Please add your Hugging Face token to Colab secrets with name 'HF_TOKEN'")
        print("   Go to: Settings → Secrets → Add new secret")
        print("   Name: HF_TOKEN, Value: your_token_here")
        print("   Then restart the runtime and run this cell again.")
        hf_token = input("Or enter your token here (leave empty to use anonymous access): ").strip()
    except ImportError:
        import getpass
        hf_token = getpass.getpass('Enter your Hugging Face Hub token (leave empty for anonymous): ').strip()

# Set up authentication
if hf_token:
    try:
        from huggingface_hub import login
        login(token=hf_token)
        print("✅ Logged into Hugging Face Hub")

        # Test the token by trying to access user info
        api = HfApi()
        user_info = api.whoami()
        print(f"✅ Authenticated as: {user_info['name']}")
    except Exception as e:
        print(f"⚠️ Token login failed: {e}")
        print("🔄 Falling back to anonymous access")
        hf_token = None
else:
    print("🔄 Using anonymous access (limited to public models)")

# Set environment variable for transformers
if hf_token:
    os.environ['HF_TOKEN'] = hf_token
    os.environ['HUGGINGFACE_HUB_TOKEN'] = hf_token
else:
    # Clear any invalid tokens
    os.environ.pop('HF_TOKEN', None)
    os.environ.pop('HUGGINGFACE_HUB_TOKEN', None)
    print("⚠️ No valid token - only public models will be accessible")

# Test token with a simple public model first
print("🔍 Testing authentication with a public model...")
try:
    test_tokenizer = AutoTokenizer.from_pretrained("gpt2")
    print("✅ Public model access works - token configuration is correct")
except Exception as e:
    print(f"❌ Even public model access failed: {e}")
    print("🔄 Clearing any problematic authentication...")
    # Clear all HF-related environment variables
    for key in list(os.environ.keys()):
        if 'HF_' in key or 'HUGGINGFACE' in key:
            del os.environ[key]
    print("✅ Cleared authentication - retrying...")
    try:
        test_tokenizer = AutoTokenizer.from_pretrained("gpt2")
        print("✅ Public model access works after clearing auth")
    except Exception as e2:
        print(f"❌ Still failing: {e2}")
        print("⚠️ There may be a network or environment issue")
        exit(1)
import os
possible_paths = [
    "/content/massive_datasets.tar.gz",  # Colab root
    "../massive_datasets.tar.gz",       # Parent directory
    "./massive_datasets.tar.gz",        # Current directory
    "massive_datasets.tar.gz",          # Relative path
    "/content/sys-scan-graph/massive_datasets.tar.gz"  # Inside repo
]

dataset_path = None
for path in possible_paths:
    if os.path.exists(path):
        dataset_path = path
        break

if dataset_path is None:
    print("❌ Dataset not found!")
    print("Please upload 'massive_datasets.tar.gz' to your Colab workspace.")
    print("It should be in the root directory (/content/) or the sys-scan-graph directory.")
    print(f"Current directory: {os.getcwd()}")
    print("Files in current directory:")
    !ls -la
    print("Files in /content/:")
    !ls -la /content/
    exit(1)
else:
    print(f"✅ Dataset found at: {dataset_path}")

# Data preparation
import tarfile
import gzip
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

def create_training_files():
    print("📊 Preparing training data...")

    # Unpack dataset
    with tarfile.open(dataset_path, 'r:gz') as tar:
        tar.extractall("massive_datasets")
    print("✅ Dataset unpacked.")

    specialist_data = []
    generalist_data = []

    # Process files
    for root, dirs, files in os.walk("massive_datasets"):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)

                    if isinstance(data, list):
                        for item in data:
                            processed = process_item(item)
                            if processed:
                                if is_security_related(processed):
                                    specialist_data.append(processed)
                                else:
                                    generalist_data.append(processed)
                    elif isinstance(data, dict):
                        processed = process_item(data)
                        if processed:
                            if is_security_related(processed):
                                specialist_data.append(processed)
                            else:
                                generalist_data.append(processed)
                except Exception as e:
                    print(f"Error processing {file}: {e}")

    # Save files
    os.makedirs("training_data", exist_ok=True)
    with open("training_data/specialist_data.jsonl", 'w') as f:
        for item in specialist_data:
            f.write(json.dumps(item) + '\n')
    with open("training_data/generalist_data.jsonl", 'w') as f:
        for item in generalist_data:
            f.write(json.dumps(item) + '\n')

    print(f"✅ Prepared {len(specialist_data)} specialist, {len(generalist_data)} generalist samples")

def process_item(item: Dict[str, Any]) -> Optional[Dict[str, str]]:
    text_parts = []
    if 'title' in item:
        text_parts.append(f"Title: {item['title']}")
    if 'description' in item:
        text_parts.append(f"Description: {item['description']}")
    if 'content' in item:
        text_parts.append(f"Content: {item['content']}")
    if 'findings' in item:
        text_parts.append(f"Findings: {json.dumps(item['findings'])}")

    return {"text": "\n".join(text_parts)} if text_parts else None

def is_security_related(item: Dict[str, str]) -> bool:
    text = item.get('text', '').lower()
    keywords = ['security', 'vulnerability', 'exploit', 'attack', 'malware', 'threat', 'risk', 'compliance', 'audit', 'scan', 'intrusion']
    return any(k in text for k in keywords)

create_training_files()

# Train Specialist Model
print("🎯 Training Specialist Model...")
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from trl import SFTTrainer
from datasets import load_dataset
import torch_xla.core.xla_model as xm

# Setup device (TPU if available, otherwise CPU)
if TPU_AVAILABLE:
    try:
        import torch_xla.core.xla_model as xm
        device = xm.xla_device()
        print(f"✅ Using TPU: {device}")
        USING_TPU = True
    except Exception as e:
        print(f"⚠️ TPU setup failed: {e}")
        print("🔄 Falling back to CPU...")
        import torch
        device = torch.device('cpu')
        USING_TPU = False
else:
    print("⚠️ TPU not available - using CPU")
    import torch
    device = torch.device('cpu')
    USING_TPU = False

print(f"🔧 Using device: {device}")
print(f"🔧 TPU mode: {USING_TPU}")

# Load models (with fallback options)
specialist_tokenizer = None
specialist_model = None

try:
    print("Trying to load Llama 3 8B...")
    specialist_tokenizer = AutoTokenizer.from_pretrained("meta-llama/Meta-Llama-3-8B", use_auth_token=hf_token if hf_token else None)
    specialist_model = AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B", torch_dtype=torch.bfloat16, use_auth_token=hf_token if hf_token else None)
    print("✅ Successfully loaded Llama 3 8B")
except Exception as e:
    print(f"❌ Failed to load Llama 3 8B: {e}")
    print("🔄 Falling back to alternative model...")

    # Fallback to a model that doesn't require special access
    print("Trying to load Microsoft Phi-3...")
    try:
        specialist_tokenizer = AutoTokenizer.from_pretrained("microsoft/Phi-3-mini-4k-instruct", use_auth_token=hf_token if hf_token else None)
        specialist_model = AutoModelForCausalLM.from_pretrained("microsoft/Phi-3-mini-4k-instruct", torch_dtype=torch.bfloat16, use_auth_token=hf_token if hf_token else None)
        print("✅ Successfully loaded Phi-3 as fallback")
    except Exception as e2:
        print(f"❌ Failed to load Phi-3: {e2}")
        print("🔄 Final fallback to GPT-2...")
        try:
            # GPT-2 is public, so don't use auth token
            specialist_tokenizer = AutoTokenizer.from_pretrained("gpt2")
            specialist_model = AutoModelForCausalLM.from_pretrained("gpt2", torch_dtype=torch.bfloat16)
            print("✅ Loaded GPT-2 as final fallback")
        except Exception as e3:
            print(f"❌ Failed to load GPT-2: {e3}")
            print("⚠️ Could not load a suitable model for the specialist training.")
            print("❌ Skipping specialist model training due to model loading failure.")

if specialist_tokenizer is None or specialist_model is None:
    print("⚠️ Skipping specialist training - no model loaded")
else:
    specialist_tokenizer.pad_token = specialist_tokenizer.eos_token

    # Prepare data
    train_dataset = load_dataset('json', data_files="training_data/specialist_data.jsonl", split='train')

    # Training args (optimized for available hardware)
    if USING_TPU:
        training_args = TrainingArguments(
            output_dir="models/specialist_model_fine_tuned",
            num_train_epochs=1,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=2,
            learning_rate=2e-5,
            save_strategy="epoch",
            logging_steps=10,
            bf16=True,
            dataloader_pin_memory=False,
            dataloader_num_workers=0,
            remove_unused_columns=False,
            evaluation_strategy="no",
            save_total_limit=1,
        )
    else:
        # CPU-optimized settings
        training_args = TrainingArguments(
            output_dir="models/specialist_model_fine_tuned",
            num_train_epochs=1,
            per_device_train_batch_size=1,  # Smaller batch size for CPU
            gradient_accumulation_steps=8,  # More accumulation for effective batch size
            learning_rate=2e-5,
            save_strategy="epoch",
            logging_steps=10,
            fp16=True,  # Use FP16 instead of BF16 for CPU
            dataloader_pin_memory=False,
            dataloader_num_workers=0,
            remove_unused_columns=False,
            evaluation_strategy="no",
            save_total_limit=1,
        )

    # Train
    trainer = SFTTrainer(
        model=specialist_model,
        args=training_args,
        train_dataset=train_dataset,
        dataset_text_field="text",
        max_seq_length=4096,
        tokenizer=specialist_tokenizer,
        packing=False,
    )

    trainer.train()
    trainer.save_model("models/specialist_model_fine_tuned")
    print("✅ Specialist model trained!")

# Train Generalist Model
print("🌐 Training Generalist Model...")
from peft import LoraConfig, get_peft_model

# Load model (with fallback options)
generalist_tokenizer = None
generalist_model = None

try:
    print("Trying to load Mixtral 8x7B...")
    generalist_tokenizer = AutoTokenizer.from_pretrained("mistralai/Mixtral-8x7B-Instruct-v0.1", use_auth_token=hf_token if hf_token else None)
    generalist_model = AutoModelForCausalLM.from_pretrained("mistralai/Mixtral-8x7B-Instruct-v0.1", torch_dtype=torch.bfloat16, use_auth_token=hf_token if hf_token else None)
    print("✅ Successfully loaded Mixtral 8x7B")
except Exception as e:
    print(f"❌ Failed to load Mixtral 8x7B: {e}")
    print("🔄 Falling back to alternative model...")

    # Fallback to a smaller model
    print("Trying to load Microsoft Phi-3...")
    try:
        generalist_tokenizer = AutoTokenizer.from_pretrained("microsoft/Phi-3-mini-4k-instruct", use_auth_token=hf_token if hf_token else None)
        generalist_model = AutoModelForCausalLM.from_pretrained("microsoft/Phi-3-mini-4k-instruct", torch_dtype=torch.bfloat16, use_auth_token=hf_token if hf_token else None)
        print("✅ Successfully loaded Phi-3 as fallback")
    except Exception as e2:
        print(f"❌ Failed to load Phi-3: {e2}")
        print("🔄 Final fallback to GPT-2...")
        try:
            # GPT-2 is public, so don't use auth token
            generalist_tokenizer = AutoTokenizer.from_pretrained("gpt2")
            generalist_model = AutoModelForCausalLM.from_pretrained("gpt2", torch_dtype=torch.bfloat16)
            print("✅ Loaded GPT-2 as final fallback")
        except Exception as e3:
            print(f"❌ Failed to load GPT-2: {e3}")
            print("⚠️ Could not load a suitable model for the generalist training.")
            print("❌ Skipping generalist model training due to model loading failure.")

if generalist_tokenizer is None or generalist_model is None:
    print("⚠️ Skipping generalist training - no model loaded")
else:
    generalist_tokenizer.pad_token = generalist_tokenizer.eos_token

    # Prepare data
    train_dataset = load_dataset('json', data_files="training_data/generalist_data.jsonl", split='train')

    # LoRA config
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        lora_dropout=0.1,
        bias="none",
        task_type="CAUSAL_LM"
    )

    # Apply LoRA
    generalist_model = get_peft_model(generalist_model, lora_config)

    # Training args (optimized for available hardware)
    if USING_TPU:
        training_args = TrainingArguments(
            output_dir="models/generalist_model_lora_adapters",
            num_train_epochs=1,
            per_device_train_batch_size=2,
            gradient_accumulation_steps=4,
            learning_rate=1e-4,
            save_strategy="epoch",
            logging_steps=10,
            bf16=True,
            dataloader_pin_memory=False,
            dataloader_num_workers=0,
            remove_unused_columns=False,
            evaluation_strategy="no",
            save_total_limit=1,
        )
    else:
        # CPU-optimized settings
        training_args = TrainingArguments(
            output_dir="models/generalist_model_lora_adapters",
            num_train_epochs=1,
            per_device_train_batch_size=1,  # Smaller batch size for CPU
            gradient_accumulation_steps=8,  # More accumulation for effective batch size
            learning_rate=1e-4,
            save_strategy="epoch",
            logging_steps=10,
            fp16=True,  # Use FP16 instead of BF16 for CPU
            dataloader_pin_memory=False,
            dataloader_num_workers=0,
            remove_unused_columns=False,
            evaluation_strategy="no",
            save_total_limit=1,
        )

    # Train
    trainer = SFTTrainer(
        model=generalist_model,
        args=training_args,
        train_dataset=train_dataset,
        peft_config=lora_config,
        dataset_text_field="text",
        max_seq_length=2048,
        tokenizer=generalist_tokenizer,
        packing=False,
    )

    trainer.train()
    trainer.save_model("models/generalist_model_lora_adapters")
    print("✅ Generalist model trained!")

# Quantize models
print("⚡ Quantizing models...")

# Setup llama.cpp
!git clone https://github.com/ggerganov/llama.cpp.git
%cd llama.cpp

# Use CMake build instead of deprecated Makefile
!mkdir -p build
%cd build
!cmake .. -DLLAMA_BUILD_COMMON=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_TESTS=OFF
!cmake --build . --config Release
%cd ../..

# Merge LoRA and quantize (only if models were trained)
if specialist_model is not None:
    print("🔄 Converting specialist model to GGUF...")
    !python llama.cpp/convert.py models/specialist_model_fine_tuned --outfile models/specialist_model_q4km.gguf --outtype q4_K_M
    print("✅ Specialist model quantized")
else:
    print("⚠️ Skipping specialist quantization - model not trained")

if generalist_model is not None:
    print("🔄 Merging and converting generalist model to GGUF...")
    # Merge LoRA
    from peft import AutoPeftModelForCausalLM
    merged_model = AutoPeftModelForCausalLM.from_pretrained("models/generalist_model_lora_adapters", low_cpu_mem_usage=True, torch_dtype=torch.float16)
    merged_model = merged_model.merge_and_unload()
    merged_model.save_pretrained("models/generalist_model_merged", safe_serialization=True)
    if generalist_tokenizer is not None:
        generalist_tokenizer.save_pretrained("models/generalist_model_merged")
    
    !python llama.cpp/convert.py models/generalist_model_merged --outfile models/generalist_model_q4km.gguf --outtype q4_K_M
    print("✅ Generalist model quantized")
else:
    print("⚠️ Skipping generalist quantization - model not trained")

# Package
import shutil
os.makedirs("models/package", exist_ok=True)

if specialist_model is not None:
    try:
        shutil.copy2("models/specialist_model_q4km.gguf", "models/package/")
        print("✅ Specialist model packaged")
    except FileNotFoundError:
        print("⚠️ Specialist GGUF file not found, skipping packaging")

if generalist_model is not None:
    try:
        shutil.copy2("models/generalist_model_q4km.gguf", "models/package/")
        print("✅ Generalist model packaged")
    except FileNotFoundError:
        print("⚠️ Generalist GGUF file not found, skipping packaging")

if os.path.exists("models/package") and os.listdir("models/package"):
    with open("models/package/README.md", "w") as f:
        f.write("""# Fine-Tuned Model Package

## Models
""")
        if specialist_model is not None:
            f.write("- specialist_model_q4km.gguf: Llama 3 8B fine-tuned for security analysis\n")
        if generalist_model is not None:
            f.write("- generalist_model_q4km.gguf: Mixtral 8x7B fine-tuned for general analysis\n")
        f.write("""
## Usage
Load with llama-cpp-python for efficient inference.
""")

    print("🎉 Pipeline complete!")
    print("📦 Download models from: models/package/")
    if specialist_model is not None:
        print("- specialist_model_q4km.gguf")
    if generalist_model is not None:
        print("- generalist_model_q4km.gguf")
else:
    print("⚠️ No models were successfully trained and packaged")