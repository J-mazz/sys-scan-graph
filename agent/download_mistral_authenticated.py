from huggingface_hub import login
import os

# Login to Hugging Face
# You need to set HF_TOKEN environment variable or run huggingface-cli login
token = os.getenv('HF_TOKEN')
if token:
    login(token)
else:
    print("Please set HF_TOKEN environment variable or run 'huggingface-cli login'")
    exit(1)

# Now download the model
from huggingface_hub import snapshot_download
from pathlib import Path

mistral_models_path = Path.home().joinpath('mistral_models', '7B-Instruct-v0.3')
mistral_models_path.mkdir(parents=True, exist_ok=True)

snapshot_download(repo_id="mistralai/Mistral-7B-Instruct-v0.3", allow_patterns=["params.json", "consolidated.safetensors", "tokenizer.model.v3"], local_dir=mistral_models_path)

print(f"Model downloaded to {mistral_models_path}")