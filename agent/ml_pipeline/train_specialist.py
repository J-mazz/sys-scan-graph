"""
Fine-tuning script for the Specialist model (Llama 3 8B).

This script fine-tunes the Llama 3 8B model on security-specific data
using TPU acceleration for optimal performance.
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
from peft import prepare_model_for_kbit_training
import torch_xla.core.xla_model as xm


def setup_tpu():
    """Initialize TPU device."""
    if xm.xla_device_count() == 0:
        raise RuntimeError("No TPU devices found. Make sure you're running on a TPU-enabled environment.")

    device = xm.xla_device()
    print(f"✅ Using TPU device: {device}")
    return device


def load_model_and_tokenizer(model_id: str = "meta-llama/Meta-Llama-3-8B"):
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
            max_length=4096
        )

    # Tokenize dataset
    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    print(f"✅ Dataset prepared with {len(tokenized_dataset)} samples")
    return tokenized_dataset


def setup_training_args(output_dir: str = "models/specialist_model_fine_tuned"):
    """
    Set up training arguments optimized for TPU.

    Args:
        output_dir: Directory to save the fine-tuned model

    Returns:
        TrainingArguments object
    """
    return TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=1,
        per_device_train_batch_size=4,  # TPUs can handle larger batches
        gradient_accumulation_steps=2,
        learning_rate=2e-5,
        save_strategy="epoch",
        logging_steps=10,
        bf16=True,  # Enable bfloat16 mixed precision for TPUs
        dataloader_pin_memory=False,  # Not needed for TPU
        # TPU-specific settings
        dataloader_num_workers=0,  # TPU doesn't benefit from multiple workers
        remove_unused_columns=False,
        # Evaluation
        evaluation_strategy="no",
        save_total_limit=1,
    )


def fine_tune_specialist(
    model,
    tokenizer,
    train_dataset,
    training_args,
    max_seq_length: int = 4096
):
    """
    Fine-tune the specialist model.

    Args:
        model: The model to fine-tune
        tokenizer: The tokenizer
        train_dataset: Training dataset
        training_args: Training arguments
        max_seq_length: Maximum sequence length
    """
    print("--> Starting full fine-tune of the Specialist model on TPU...")

    # Prepare model for training
    model = prepare_model_for_kbit_training(model)

    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
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
    Save the fine-tuned model.

    Args:
        trainer: The trained trainer
        output_dir: Output directory
    """
    os.makedirs(output_dir, exist_ok=True)

    trainer.save_model(output_dir)
    print(f"--> Specialist model saved to {output_dir}")


def main():
    """Main function to run the specialist model fine-tuning."""
    print("🚀 Starting Specialist Model Fine-Tuning on TPU")

    # Configuration
    MODEL_ID = "meta-llama/Meta-Llama-3-8B"
    DATASET_PATH = "training_data/specialist_data.jsonl"
    OUTPUT_DIR = "models/specialist_model_fine_tuned"

    try:
        # Setup TPU
        device = setup_tpu()

        # Load model and tokenizer
        model, tokenizer = load_model_and_tokenizer(MODEL_ID)

        # Prepare dataset
        train_dataset = prepare_dataset(DATASET_PATH, tokenizer)

        # Setup training arguments
        training_args = setup_training_args(OUTPUT_DIR)

        # Fine-tune the model
        trainer = fine_tune_specialist(
            model, tokenizer, train_dataset, training_args
        )

        # Save the model
        save_model(trainer, OUTPUT_DIR)

        print("✅ Specialist model fine-tuning completed successfully!")

    except Exception as e:
        print(f"❌ Error during fine-tuning: {e}")
        raise


if __name__ == "__main__":
    main()
