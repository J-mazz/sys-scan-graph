# ML Pipeline for Sys-Scan-Graph

This directory contains the machine learning pipeline for fine-tuning models used in the Sys-Scan-Graph intelligence layer. The pipeline implements a dual-model approach with a Specialist model for security-specific tasks and a Generalist model for broader analysis.

## Overview

The ML pipeline consists of two fine-tuned models:

### Specialist Model
- **Base Model**: Llama 3 8B
- **Purpose**: Security-specific analysis, threat detection, compliance checking
- **Training Data**: Security-related content from the dataset
- **Fine-tuning Method**: Full fine-tuning on TPU

### Generalist Model
- **Base Model**: Mixtral 8x7B Instruct
- **Purpose**: General analysis, context understanding, report generation
- **Training Data**: General knowledge content from the dataset
- **Fine-tuning Method**: LoRA (Low-Rank Adaptation) on TPU

## Prerequisites

### Hardware Requirements
- **TPU Environment**: Google Colab Pro+ with TPU v2/v3 or Cloud TPU
- **Memory**: At least 32GB RAM for model loading
- **Storage**: 100GB+ for datasets and models

### Software Requirements
- Python 3.10+
- PyTorch 2.0+
- CUDA-compatible GPU (optional, for non-TPU environments)
- Hugging Face account with access to required models

### Required Models Access
- `meta-llama/Meta-Llama-3-8B` (requires Hugging Face approval)
- `mistralai/Mixtral-8x7B-Instruct-v0.1`

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Mazzlabs/sys-scan-graph.git
   cd sys-scan-graph
   ```

2. **Install dependencies**:
   ```bash
   cd agent
   pip install -r requirements.txt
   ```

3. **Set up Hugging Face authentication**:
   ```bash
   export HF_TOKEN=your_hugging_face_token
   ```

## Data Preparation

### Dataset Format
The pipeline expects a `massive_datasets.tar.gz` file containing training data. The data should be in JSON format with the following structure:

```json
{
  "title": "Security Finding Title",
  "description": "Detailed description of the finding",
  "content": "Full content of the security report",
  "findings": ["finding1", "finding2"]
}
```

### Data Processing
The `data_loader.py` script automatically:
1. Unpacks the dataset archive
2. Processes JSON files
3. Categorizes content as security-related (Specialist) or general (Generalist)
4. Creates JSONL files for training

## Training Pipeline

### Option 1: Colab TPU Training (Recommended)

1. **Upload to Colab**:
   - Open Google Colab
   - Upload `massive_datasets.tar.gz` to the workspace
   - Change runtime to TPU

2. **Run the orchestrator**:
   ```python
   !python agent/ml_pipeline/colab_train.py
   ```

### Option 2: Local Training

1. **Prepare data**:
   ```bash
   python agent/ml_pipeline/data_loader.py
   ```

2. **Train Specialist model**:
   ```bash
   python agent/ml_pipeline/train_specialist.py
   ```

3. **Train Generalist model**:
   ```bash
   python agent/ml_pipeline/train_generalist.py
   ```

4. **Quantize models**:
   ```bash
   python agent/ml_pipeline/quantize_models.py
   ```

## Model Configuration

### Specialist Model (Llama 3 8B)
```python
# Key parameters
MODEL_ID = "meta-llama/Meta-Llama-3-8B"
MAX_SEQ_LENGTH = 4096
BATCH_SIZE = 4
LEARNING_RATE = 2e-5
EPOCHS = 1
```

### Generalist Model (Mixtral 8x7B)
```python
# Key parameters
MODEL_ID = "mistralai/Mixtral-8x7B-Instruct-v0.1"
MAX_SEQ_LENGTH = 2048
BATCH_SIZE = 2
LEARNING_RATE = 1e-4
EPOCHS = 1

# LoRA configuration
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.1
```

## Quantization

Models are quantized using llama.cpp for efficient inference:

- **Format**: GGUF (GPT-Generated Unified Format)
- **Quantization**: Q4_K_M (4-bit with medium quality)
- **Benefits**: Reduced memory footprint, faster inference, CPU compatibility

## Output Structure

```
models/
├── specialist_model_fine_tuned/     # Full fine-tuned Specialist model
├── generalist_model_lora_adapters/  # LoRA adapters for Generalist
├── generalist_model_merged/         # Merged Generalist model
├── specialist_model_q4km.gguf       # Quantized Specialist model
├── generalist_model_q4km.gguf       # Quantized Generalist model
└── package/                         # Packaged models for deployment
    ├── specialist_model_q4km.gguf
    ├── generalist_model_q4km.gguf
    └── README.md
```

## Integration

### Loading Quantized Models

```python
from llama_cpp import Llama

# Load Specialist model
specialist = Llama(
    model_path="models/package/specialist_model_q4km.gguf",
    n_ctx=4096,
    n_threads=8
)

# Load Generalist model
generalist = Llama(
    model_path="models/package/generalist_model_q4km.gguf",
    n_ctx=2048,
    n_threads=8
)
```

### Using in Sys-Scan-Graph

The fine-tuned models enhance the intelligence layer by providing:

1. **Specialist Model**: Deep security analysis, threat correlation, compliance validation
2. **Generalist Model**: Contextual understanding, report generation, general analysis

Models are integrated into the LangGraph pipeline for enhanced analysis capabilities.

## Performance Optimization

### TPU-Specific Optimizations
- **bfloat16 precision**: Native TPU format for optimal performance
- **XLA compilation**: Automatic graph optimization
- **Large batch sizes**: Efficient TPU core utilization

### Memory Management
- **Gradient checkpointing**: Reduced memory for large models
- **LoRA for Generalist**: Parameter-efficient fine-tuning
- **Quantization**: 75% memory reduction for inference

## Troubleshooting

### Authentication Issues

If you're getting 401 Unauthorized errors even for public models like GPT-2:

1. **Test Authentication Locally**:
   ```bash
   python agent/ml_pipeline/test_auth.py
   ```

2. **Check Token Validity**:
   - Visit [Hugging Face Settings](https://huggingface.co/settings/tokens)
   - Verify your token is active and has read permissions
   - Regenerate token if expired

3. **Clear Environment Variables**:
   ```bash
   unset HF_TOKEN
   unset HUGGINGFACE_HUB_TOKEN
   ```

4. **Colab-Specific Setup**:
   - Go to Settings → Secrets → Add new secret
   - Name: `HF_TOKEN`, Value: your_token_here
   - Restart runtime after adding secret

5. **Model Access Requests**:
   - For Llama 3: Visit [Meta Llama 3 Access](https://huggingface.co/meta-llama/Meta-Llama-3-8B)
   - For Mixtral: Visit [Mistral Mixtral Access](https://huggingface.co/mistralai/Mixtral-8x7B-Instruct-v0.1)
   - Accept terms and wait for approval

### Common Issues

1. **TPU Not Available**:
   - Ensure Colab Pro+ subscription
   - Check TPU runtime selection
   - Verify TPU availability with `import torch_xla.core.xla_model as xm; print(xm.xla_device_count())`

2. **Model Loading Errors**:
   - Verify Hugging Face token has access to required models
   - Check available disk space (models require 50GB+)
   - Ensure sufficient RAM (32GB+ recommended)

3. **Out of Memory**:
   - Reduce batch size in training arguments
   - Enable gradient checkpointing
   - Use smaller sequence lengths

4. **Quantization Failures**:
   - Ensure llama.cpp is properly built
   - Check model paths are correct
   - Verify sufficient disk space for conversion

### Performance Tuning

- **Training Speed**: Monitor TPU utilization (>90% ideal)
- **Memory Usage**: Track with `nvidia-smi` or TPU metrics
- **Convergence**: Adjust learning rates based on loss curves

## Contributing

When contributing to the ML pipeline:

1. Test changes on TPU environment
2. Update documentation for any parameter changes
3. Validate model performance on test datasets
4. Ensure compatibility with existing Sys-Scan-Graph integration

## License

See main repository LICENSE file for licensing information. Note that the intelligence layer uses Business Source License 1.1 for commercial use.
