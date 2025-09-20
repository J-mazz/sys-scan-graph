#!/usr/bin/env python3
"""
Train the Specialist model for security data enrichment.
Optimized for TPU training with proper loss functions.
"""

import os
import torch
import torch_xla.core.xla_model as xm
import torch_xla.distributed.parallel_loader as pl
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    DataCollatorForLanguageModeling
)
from trl import SFTTrainer
from datasets import load_dataset
from peft import prepare_model_for_kbit_training
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

class TPUSpecialistTrainer:
    """TPU-optimized trainer for the Specialist model."""

    def __init__(self, model_name: str, dataset_path: str, output_dir: str):
        self.model_name = model_name
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.device = xm.xla_device()

    def load_model_and_tokenizer(self):
        """Load model and tokenizer with TPU optimizations."""
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

        # Move to TPU device
        self.model.to(self.device)

        logger.info("Model and tokenizer loaded successfully")

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
        """Get TPU-optimized training arguments."""
        return TrainingArguments(
            output_dir=self.output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=2,  # Small batch size for TPU memory
            per_device_eval_batch_size=2,
            gradient_accumulation_steps=8,  # Accumulate gradients for effective batch size
            learning_rate=2e-5,
            weight_decay=0.01,
            warmup_steps=100,
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
            gradient_checkpointing=True,

            # Logging and monitoring
            report_to=["tensorboard"],
            run_name=f"specialist_{self.model_name.split('/')[-1]}"
        )

    def create_trainer(self):
        """Create the SFT trainer with TPU optimizations."""
        training_args = self.get_training_arguments()
        data_collator = self.create_data_collator()

        # Custom loss function for TPU
        def compute_loss(model, inputs, return_outputs=False):
            outputs = model(**inputs)
            loss_fct = TPUCrossEntropyLoss()

            # Compute loss
            loss = loss_fct(outputs.logits, inputs["labels"])

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

        logger.info("Trainer created with TPU optimizations")

    def train(self):
        """Execute the training loop."""
        logger.info("Starting training...")

        # Start training
        self.trainer.train()

        # Save the final model
        logger.info(f"Saving model to {self.output_dir}")
        self.trainer.save_model(self.output_dir)

        # Save tokenizer
        self.tokenizer.save_pretrained(self.output_dir)

        logger.info("Training completed successfully!")

def main():
    parser = argparse.ArgumentParser(description="Train Specialist model on TPU")
    parser.add_argument(
        "--model-name",
        type=str,
        default="meta-llama/Llama-3-8B",
        help="HuggingFace model name"
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default="training_data/specialist_data.jsonl",
        help="Path to training dataset"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models/specialist_model",
        help="Output directory for trained model"
    )
    parser.add_argument(
        "--huggingface-token",
        type=str,
        help="HuggingFace token for accessing gated models"
    )

    args = parser.parse_args()

    # Set HuggingFace token if provided
    if args.huggingface_token:
        os.environ["HF_TOKEN"] = args.huggingface_token

    # Initialize TPU trainer
    trainer = TPUSpecialistTrainer(
        model_name=args.model_name,
        dataset_path=args.dataset_path,
        output_dir=args.output_dir
    )

    # Execute training pipeline
    trainer.load_model_and_tokenizer()
    trainer.load_dataset()
    trainer.create_trainer()
    trainer.train()

if __name__ == "__main__":
    main()