"""
Fine-tuning script for the Generalist model (Mixtral 8x7B).

This script performs LoRA fine-tuning of the Mixtral 8x7B model
on general data using TPU acceleration.
"""

import os
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments
)
from trl import SFTTrainer
from datasets import load_dataset
from peft import LoraConfig, get_peft_model
import torch_xla.core.xla_model as xm


def setup_tpu():
    """Initialize TPU device."""
    if xm.xla_device_count() == 0:
        raise RuntimeError("No TPU devices found. Make sure you're running on a TPU-enabled environment.")

    device = xm.xla_device()
    print(f"✅ Using TPU device: {device}")
    return device


def load_model_and_tokenizer(model_id: str = "mistralai/Mixtral-8x7B-Instruct-v0.1"):
    """
    Load the model and tokenizer.

    Args:
        model_id: Hugging Face model ID

    Returns:
        Tuple of (model, tokenizer)
    """
    print(f"Loading model: {model_id}")

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    tokenizer.pad_token = tokenizer.eos_token

    # Load model with bfloat16 for TPU efficiency
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        device_map="auto"  # Let accelerate handle device placement
    )

    print("✅ Model and tokenizer loaded successfully")
    return model, tokenizer


def prepare_dataset(data_path: str, tokenizer):
    """
    Load and prepare the training dataset.

    Args:
        data_path: Path to the JSONL training data
        tokenizer: The tokenizer to use

    Returns:
        Dataset object
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Training data not found: {data_path}")

    print(f"Loading dataset from: {data_path}")
    dataset = load_dataset('json', data_files=data_path, split='train')

    # Add tokenization if needed
    def tokenize_function(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            padding="max_length",
            max_length=2048
        )

    # Tokenize dataset
    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    print(f"✅ Dataset prepared with {len(tokenized_dataset)} samples")
    return tokenized_dataset


def setup_lora_config():
    """
    Set up LoRA configuration for efficient fine-tuning.

    Returns:
        LoraConfig object
    """
    return LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        lora_dropout=0.1,
        bias="none",
        task_type="CAUSAL_LM"
    )


def setup_training_args(output_dir: str = "models/generalist_model_lora_adapters"):
    """
    Set up training arguments optimized for TPU with LoRA.

    Args:
        output_dir: Directory to save the LoRA adapters

    Returns:
        TrainingArguments object
    """
    return TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=1,
        per_device_train_batch_size=2,  # Smaller batch size for larger model
        gradient_accumulation_steps=4,
        learning_rate=1e-4,
        save_strategy="epoch",
        logging_steps=10,
        bf16=True,  # Use bfloat16 for TPU
        dataloader_pin_memory=False,  # Not needed for TPU
        # TPU-specific settings
        dataloader_num_workers=0,  # TPU doesn't benefit from multiple workers
        remove_unused_columns=False,
        # Evaluation
        evaluation_strategy="no",
        save_total_limit=1,
    )


def apply_lora_to_model(model, lora_config):
    """
    Apply LoRA configuration to the model.

    Args:
        model: The base model
        lora_config: LoRA configuration

    Returns:
        Model with LoRA applied
    """
    print("Applying LoRA configuration to model...")
    lora_model = get_peft_model(model, lora_config)
    lora_model.print_trainable_parameters()
    return lora_model


def fine_tune_generalist(
    model,
    tokenizer,
    train_dataset,
    training_args,
    lora_config,
    max_seq_length: int = 2048
):
    """
    Fine-tune the generalist model with LoRA.

    Args:
        model: The model to fine-tune
        tokenizer: The tokenizer
        train_dataset: Training dataset
        training_args: Training arguments
        lora_config: LoRA configuration
        max_seq_length: Maximum sequence length
    """
    print("--> Starting PEFT (LoRA) fine-tuning of the Generalist model on TPU...")

    # Apply LoRA
    model = apply_lora_to_model(model, lora_config)

    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        peft_config=lora_config,
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        tokenizer=tokenizer,
        packing=False,  # Disable packing for TPU
    )

    # Start training
    trainer.train()

    print("--> Fine-tuning complete.")
    return trainer


def save_model(trainer, output_dir: str):
    """
    Save the LoRA adapters.

    Args:
        trainer: The trained trainer
        output_dir: Output directory
    """
    os.makedirs(output_dir, exist_ok=True)

    trainer.save_model(output_dir)
    print(f"--> Generalist LoRA adapters saved to {output_dir}")


def main():
    """Main function to run the generalist model fine-tuning."""
    print("🚀 Starting Generalist Model Fine-Tuning on TPU")

    # Configuration
    MODEL_ID = "mistralai/Mixtral-8x7B-Instruct-v0.1"
    DATASET_PATH = "training_data/generalist_data.jsonl"
    OUTPUT_DIR = "models/generalist_model_lora_adapters"

    try:
        # Setup TPU
        device = setup_tpu()

        # Load model and tokenizer
        model, tokenizer = load_model_and_tokenizer(MODEL_ID)

        # Prepare dataset
        train_dataset = prepare_dataset(DATASET_PATH, tokenizer)

        # Setup LoRA config
        lora_config = setup_lora_config()

        # Setup training arguments
        training_args = setup_training_args(OUTPUT_DIR)

        # Fine-tune the model
        trainer = fine_tune_generalist(
            model, tokenizer, train_dataset, training_args, lora_config
        )

        # Save the model
        save_model(trainer, OUTPUT_DIR)

        print("✅ Generalist model fine-tuning completed successfully!")

    except Exception as e:
        print(f"❌ Error during fine-tuning: {e}")
        raise


if __name__ == "__main__":
    main()
