# ╔══════════════════════════════════╗
# ║             MazzLabs             ║
# ╟──────────────────────────────────╢
# ║           Joseph Mazzini         ║
# ╚══════════════════════════════════╝

# ==============================================================================
"""
ML Model Training Pipeline

Fine-tunes language models on security scanner data for intelligent analysis
and anomaly detection in the sys-scan-graph intelligence layer.
"""

import os
import argparse
import keras
from keras import layers, ops
from transformers import AutoTokenizer, TFAutoModelForCausalLM
from datasets import load_from_disk
import numpy as np

# Set Keras backend to TensorFlow
os.environ['KERAS_BACKEND'] = 'tensorflow'
import tensorflow as tf

def preprocess_function(examples, tokenizer):
    """
    Preprocesses text data with dynamic padding.
    """
    inputs = tokenizer(
        examples["text"],
        truncation=True,
        padding="longest",
        return_tensors="tf"
    )
    inputs["labels"] = inputs["input_ids"]
    return inputs

def create_tf_dataset(dataset, tokenizer, batch_size):
    """
    Creates a TensorFlow dataset from a Hugging Face dataset.
    """
    def generator():
        for example in dataset:
            processed = preprocess_function({"text": example["text"]}, tokenizer)
            yield {
                "input_ids": processed["input_ids"],
                "attention_mask": processed["attention_mask"],
                "labels": processed["labels"]
            }

    output_signature = {
        "input_ids": tf.TensorSpec(shape=(None,), dtype=tf.int32),
        "attention_mask": tf.TensorSpec(shape=(None,), dtype=tf.int32),
        "labels": tf.TensorSpec(shape=(None,), dtype=tf.int32)
    }

    tf_dataset = tf.data.Dataset.from_generator(
        generator,
        output_signature=output_signature
    )

    tf_dataset = tf_dataset.shuffle(1000).batch(batch_size).prefetch(tf.data.AUTOTUNE)
    return tf_dataset

def train_with_keras():
    """
    Fine-tunes the Llama 3 model using TensorFlow's MirroredStrategy for multi-GPU training.
    """
    strategy = tf.distribute.MirroredStrategy()
    print(f"✅ Found {strategy.num_replicas_in_sync} GPUs. Using MirroredStrategy.")

    parser = argparse.ArgumentParser()
    parser.add_argument('--epochs', type=int, default=1)
    parser.add_argument('--learning_rate', type=float, default=2e-4)
    parser.add_argument('--beta_1', type=float, default=0.9)
    parser.add_argument('--beta_2', type=float, default=0.99)
    parser.add_argument('--weight_decay', type=float, default=0.01)
    args = parser.parse_args()

    dataset_path = "./processed_dataset"
    print(f"Loading pre-processed dataset from {dataset_path}...")
    split_dataset = load_from_disk(dataset_path)

    model_name = "meta-llama/Meta-Llama-3-8B"
    new_model_name = "sys-scan-llama-agent-keras3-lion"

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    batch_size_per_replica = 8
    global_batch_size = batch_size_per_replica * strategy.num_replicas_in_sync

    print(f"Batch size per GPU: {batch_size_per_replica}")
    print(f"Global batch size: {global_batch_size}")

    train_dataset = create_tf_dataset(split_dataset['train'], tokenizer, global_batch_size)
    val_dataset = create_tf_dataset(split_dataset['validation'], tokenizer, global_batch_size)

    with strategy.scope():
        print(f"Loading model {model_name} for Keras 3...")
        model = TFAutoModelForCausalLM.from_pretrained(
            model_name,
            return_dict=True
        )

        print("Creating Lion optimizer with configured parameters...")
        optimizer = keras.optimizers.Lion(
            learning_rate=args.learning_rate,
            beta_1=args.beta_1,
            beta_2=args.beta_2,
            weight_decay=args.weight_decay
        )

        model.compile(
            optimizer=optimizer,
            loss=keras.losses.SparseCategoricalCrossentropy(from_logits=True),
            metrics=[keras.metrics.SparseCategoricalAccuracy()]
        )

    callbacks = [
        keras.callbacks.ModelCheckpoint(
            filepath=f"./checkpoints/{new_model_name}_epoch_{{epoch:02d}}",
            save_freq='epoch',
            save_weights_only=True
        ),
        keras.callbacks.TensorBoard(log_dir="./logs"),
        keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True),
        keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=2, min_lr=1e-6)
    ]

    os.makedirs("./checkpoints", exist_ok=True)
    os.makedirs("./logs", exist_ok=True)

    print("\n🚀 Starting fine-tuning with Keras, Lion, and MirroredStrategy...")
    
    history = model.fit(
        train_dataset,
        validation_data=val_dataset,
        epochs=args.epochs,
        callbacks=callbacks,
        verbose=1
    )

    print("✅ Fine-tuning completed!")

    print(f"Saving model to {new_model_name}...")
    model.save_pretrained(new_model_name)
    tokenizer.save_pretrained(new_model_name)

    print(f"🎉 Model and tokenizer saved to {new_model_name}")

    return history

if __name__ == "__main__":
    train_with_keras()