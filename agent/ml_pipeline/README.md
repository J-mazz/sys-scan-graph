# Security ML Training Pipeline

This directory contains the complete ML pipeline for training specialized security analysis models using Google Colab's TPU infrastructure.

## Overview

The pipeline trains two models:
- **Specialist Model**: Transforms raw sys-scan output into enriched security reports
- **Generalist Model**: Performs agentic reasoning and tool calling for security analysis

## Key Features

- ✅ **TPU-Optimized**: Designed for Google Colab TPU runtime
- ✅ **Proper Loss Functions**: CrossEntropyLoss with TPU-specific optimizations
- ✅ **LoRA Fine-Tuning**: Parameter-efficient training for the Generalist model
- ✅ **Distributed Training**: Handles TPU core parallelism automatically
- ✅ **Memory Efficient**: Gradient accumulation and bfloat16 precision

## Prerequisites

### Google Colab Setup
1. Open [Google Colab](https://colab.research.google.com/)
2. Change runtime to **TPU** (Runtime → Change runtime type → TPU)
3. Mount Google Drive (optional, for data persistence)

### Data Preparation
Ensure `massive_datasets.tar.gz` is available in the project root directory.

## Quick Start

### 1. Setup and Data Preparation
```bash
# Clone the repository
!git clone https://github.com/your-username/sys-scan-graph.git
%cd sys-scan-graph/agent

# Install dependencies
!pip install -r requirements.txt

# Run the complete Colab pipeline
!python ml_pipeline/colab_train.py --huggingface-token YOUR_HF_TOKEN
```

### 2. Secure Token Setup (Recommended)
For security, set your tokens as environment variables:

```python
import os
os.environ['HF_TOKEN'] = 'your_huggingface_token_here'
os.environ['HUGGINGFACE_TOKEN'] = 'your_huggingface_token_here'  # Alternative
```

Then run without exposing tokens:
```bash
!python ml_pipeline/colab_train.py
```

### 3. Individual Training Steps

#### Data Preparation Only
```bash
!python ml_pipeline/colab_train.py --data-only
```

#### Train Specialist Model Only
```bash
!python ml_pipeline/train_specialist.py --huggingface-token YOUR_HF_TOKEN
```

#### Train Generalist Model Only
```bash
!python ml_pipeline/train_generalist.py --huggingface-token YOUR_HF_TOKEN
```

## Loss Function Details

### Specialist Model (Full Fine-Tune)
- **Loss Function**: `CrossEntropyLoss` with TPU optimizations
- **Key Features**:
  - Proper label shifting for causal language modeling
  - TPU device handling
  - Distributed loss computation across TPU cores

### Generalist Model (LoRA Fine-Tune)
- **Loss Function**: `CrossEntropyLoss` with causal LM shifting
- **Key Features**:
  - Optimized for LoRA parameter updates
  - Reduced memory footprint
  - Faster training convergence

## Training Configuration

### TPU-Specific Settings
```python
# Training arguments optimized for TPU
training_args = TrainingArguments(
    per_device_train_batch_size=2,      # Small batch size for TPU memory
    gradient_accumulation_steps=8,      # Accumulate for effective batch size
    bf16=True,                          # bfloat16 for TPU efficiency
    dataloader_pin_memory=False,        # TPU doesn't use pinned memory
    dataloader_num_workers=0,           # TPU handles parallelism internally
)
```

### LoRA Configuration
```python
lora_config = LoraConfig(
    r=16,                               # LoRA rank
    lora_alpha=32,                      # Scaling parameter
    target_modules=["q_proj", "v_proj"], # Attention layers
    lora_dropout=0.05,                  # Regularization
)
```

## Model Specifications

### Specialist Model
- **Base Model**: Llama-3-8B (or similar 8B parameter model)
- **Training**: Full fine-tuning
- **Purpose**: Raw scan → Enriched report transformation
- **Output**: `models/specialist_model/`

### Generalist Model
- **Base Model**: Mixtral-8x7B-Instruct-v0.1 (or similar MoE model)
- **Training**: LoRA fine-tuning
- **Purpose**: Agentic reasoning and tool calling
- **Output**: `models/generalist_model_lora/`

## Memory Optimization

### For TPU Training
- Use `bfloat16` precision (automatically enabled)
- Gradient accumulation to simulate larger batch sizes
- LoRA for parameter-efficient training on larger models
- Proper data collation to minimize padding

### Memory Requirements
- **Specialist (8B)**: ~16GB TPU memory
- **Generalist (46B effective)**: ~24GB TPU memory with LoRA

## Troubleshooting

### Common Issues

#### TPU Not Detected
```bash
# Ensure you're using TPU runtime in Colab
Runtime → Change runtime type → TPU
```

#### Out of Memory
```python
# Reduce batch size and increase gradient accumulation
per_device_train_batch_size=1
gradient_accumulation_steps=16
```

#### Import Errors
```bash
# Install torch_xla for TPU support
!pip install torch_xla[tpu] -f https://storage.googleapis.com/libtpu-releases/index.html
```

#### HuggingFace Authentication
```python
# Set your token
import os
os.environ["HF_TOKEN"] = "your_token_here"
```

## Output Structure

```
models/
├── specialist_model/
│   ├── pytorch_model.bin
│   ├── tokenizer.json
│   └── config.json
└── generalist_model_lora/
    ├── adapter_model.bin
    ├── adapter_config.json
    └── tokenizer.json
```

## Next Steps

After training:

1. **Quantization**: Run `python ml_pipeline/quantize_and_deploy.py`
2. **Integration**: Update `agent/providers/` with local LLM provider
3. **Testing**: Test the complete LangGraph pipeline
4. **Deployment**: Deploy quantized models for inference

## Performance Expectations

### Training Time (TPU v3-8)
- **Specialist**: ~4-6 hours for 3 epochs
- **Generalist**: ~8-12 hours for 3 epochs with LoRA

### Model Performance
- **Specialist**: High accuracy on enrichment tasks
- **Generalist**: Effective tool calling and reasoning

## Support

For issues specific to:
- **TPU Training**: Check torch_xla documentation
- **Model Training**: Refer to transformers/PEFT documentation
- **Data Format**: Check the synthetic data generation scripts

---

**Note**: This pipeline is optimized for Google Colab's TPU environment. For local training, modify the device handling and batch sizes accordingly.