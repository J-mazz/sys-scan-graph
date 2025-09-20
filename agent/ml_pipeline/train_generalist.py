#!/usr/bin/env python3
"""
Train the Generalist model for agentic reasoning and tool calling.
Uses LoRA for parameter-efficient fine-tuning, optimized for TPU.
"""

import os
import torch
import torch_xla.core.xla_model as xm
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    DataCollatorForLanguageModeling
)
from trl import SFTTrainer
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TPUCrossEntropyLoss(torch.nn.CrossEntropyLoss):
    """TPU-optimized CrossEntropyLoss with proper distributed handling."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def forward(self, input, target):
        # Ensure input and target are on the same device
        if input.device != target.device:
            target = target.to(input.device)

        # Handle TPU-specific tensor operations
        return super().forward(input.view(-1, input.size(-1)), target.view(-1))

class TPUGeneralistTrainer:
    """TPU-optimized trainer for the Generalist model with LoRA."""

    def __init__(self, model_name: str, dataset_path: str, output_dir: str):
        self.model_name = model_name
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.device = xm.xla_device()

    def load_model_and_tokenizer(self):
        """Load model and tokenizer with TPU and LoRA optimizations."""
        logger.info(f"Loading model: {self.model_name}")

        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        # Load model with TPU optimizations
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            torch_dtype=torch.bfloat16,  # TPU optimized dtype
            device_map="auto",
            trust_remote_code=True
        )

        # Prepare model for TPU training
        self.model = prepare_model_for_kbit_training(self.model)

        # Configure LoRA
        self.lora_config = LoraConfig(
            r=16,  # LoRA rank
            lora_alpha=32,  # LoRA scaling
            target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],  # Attention layers
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM"
        )

        # Apply LoRA to the model
        self.model = get_peft_model(self.model, self.lora_config)

        # Move to TPU device
        self.model.to(self.device)

        # Print trainable parameters info
        self.model.print_trainable_parameters()

        logger.info("Model and tokenizer loaded with LoRA configuration")

    def load_dataset(self):
        """Load and preprocess the training dataset."""
        logger.info(f"Loading dataset from {self.dataset_path}")

        # Load the JSONL dataset
        dataset = load_dataset("json", data_files=self.dataset_path)

        def preprocess_function(examples):
            # Combine prompt and completion for training
            texts = []
            for prompt, completion in zip(examples["prompt"], examples["completion"]):
                # Format as instruction-response pair
                text = f"<s>[INST] {prompt} [/INST] {completion}</s>"
                texts.append(text)

            # Tokenize
            tokenized = self.tokenizer(
                texts,
                truncation=True,
                padding="max_length",
                max_length=2048,  # Adjust based on your data
                return_tensors="pt"
            )

            return {
                "input_ids": tokenized["input_ids"],
                "attention_mask": tokenized["attention_mask"],
                "labels": tokenized["input_ids"].clone()  # For causal LM, labels = input_ids
            }

        # Apply preprocessing
        self.dataset = dataset.map(
            preprocess_function,
            batched=True,
            remove_columns=dataset["train"].column_names,
            num_proc=4  # Adjust based on available CPU cores
        )

        logger.info(f"Dataset loaded with {len(self.dataset['train'])} examples")

    def create_data_collator(self):
        """Create TPU-optimized data collator."""
        return DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=False  # Causal LM, not masked LM
        )

    def get_training_arguments(self) -> TrainingArguments:
        """Get TPU-optimized training arguments for LoRA."""
        return TrainingArguments(
            output_dir=self.output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=2,  # Small batch size for TPU memory with LoRA
            per_device_eval_batch_size=2,
            gradient_accumulation_steps=4,  # Less accumulation needed with LoRA
            learning_rate=5e-5,  # Higher learning rate for LoRA
            weight_decay=0.01,
            warmup_steps=50,
            logging_steps=10,
            save_steps=500,
            save_total_limit=3,
            evaluation_strategy="steps",
            eval_steps=500,
            load_best_model_at_end=True,
            metric_for_best_model="loss",
            greater_is_better=False,

            # TPU-specific settings
            dataloader_pin_memory=False,  # TPU doesn't use pinned memory
            dataloader_num_workers=0,     # TPU handles parallelism internally

            # Distributed training
            local_rank=-1,  # Let torch_xla handle rank
            ddp_find_unused_parameters=False,

            # Memory optimization
            fp16=False,  # TPU uses bfloat16
            bf16=True,   # Enable bfloat16 for TPU
            gradient_checkpointing=False,  # Less needed with LoRA

            # Logging and monitoring
            report_to=["tensorboard"],
            run_name=f"generalist_lora_{self.model_name.split('/')[-1]}"
        )

    def create_trainer(self):
        """Create the SFT trainer with TPU and LoRA optimizations."""
        training_args = self.get_training_arguments()
        data_collator = self.create_data_collator()

        # Custom loss function for TPU
        def compute_loss(model, inputs, return_outputs=False):
            outputs = model(**inputs)
            loss_fct = TPUCrossEntropyLoss()

            # Compute loss - handle LoRA outputs properly
            logits = outputs.logits
            labels = inputs["labels"]

            # Shift for causal LM
            shift_logits = logits[..., :-1, :].contiguous()
            shift_labels = labels[..., 1:].contiguous()

            # Compute loss
            loss = loss_fct(shift_logits.view(-1, shift_logits.size(-1)), shift_labels.view(-1))

            return (loss, outputs) if return_outputs else loss

        self.trainer = SFTTrainer(
            model=self.model,
            args=training_args,
            train_dataset=self.dataset["train"],
            eval_dataset=self.dataset["train"].select(range(min(1000, len(self.dataset["train"])))),  # Small eval set
            data_collator=data_collator,
            compute_loss_func=compute_loss,  # Use our TPU-optimized loss
            tokenizer=self.tokenizer,
        )

        logger.info("Trainer created with TPU and LoRA optimizations")

    def train(self):
        """Execute the training loop."""
        logger.info("Starting LoRA training...")

        # Start training
        self.trainer.train()

        # Save the LoRA adapters and tokenizer
        logger.info(f"Saving LoRA model to {self.output_dir}")
        self.trainer.save_model(self.output_dir)

        # Save tokenizer
        self.tokenizer.save_pretrained(self.output_dir)

        # Save LoRA config
        self.lora_config.save_pretrained(self.output_dir)

        logger.info("LoRA training completed successfully!")

def main():
    parser = argparse.ArgumentParser(description="Train Generalist model with LoRA on TPU")
    parser.add_argument(
        "--model-name",
        type=str,
        default="mistralai/Mixtral-8x7B-Instruct-v0.1",
        help="HuggingFace model name"
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default="training_data/generalist_data.jsonl",
        help="Path to training dataset"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models/generalist_model_lora",
        help="Output directory for trained LoRA model"
    )
    parser.add_argument(
        "--huggingface-token",
        type=str,
        help="HuggingFace token for accessing gated models"
    )
    parser.add_argument(
        "--lora-r",
        type=int,
        default=16,
        help="LoRA rank"
    )
    parser.add_argument(
        "--lora-alpha",
        type=int,
        default=32,
        help="LoRA scaling parameter"
    )

    args = parser.parse_args()

    # Set HuggingFace token if provided
    if args.huggingface_token:
        os.environ["HF_TOKEN"] = args.huggingface_token
    elif os.getenv('HF_TOKEN') or os.getenv('HUGGINGFACE_TOKEN'):
        # Token already set in environment
        pass
    else:
        logger.warning("No HuggingFace token provided. Some models may not be accessible.")

    # Initialize TPU trainer
    trainer = TPUGeneralistTrainer(
        model_name=args.model_name,
        dataset_path=args.dataset_path,
        output_dir=args.output_dir
    )

    # Update LoRA config if specified
    if hasattr(trainer, 'lora_config'):
        trainer.lora_config.r = args.lora_r
        trainer.lora_config.lora_alpha = args.lora_alpha

    # Execute training pipeline
    trainer.load_model_and_tokenizer()
    trainer.load_dataset()
    trainer.create_trainer()
    trainer.train()

if __name__ == "__main__":
    main()