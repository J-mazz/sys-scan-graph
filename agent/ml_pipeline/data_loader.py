"""
Data preparation utilities for fine-tuning models.

This module handles unpacking the massive datasets and preparing
training data for specialist and generalist models.
"""

import tarfile
import gzip
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional


def unpack_massive_datasets(tar_path: str, extract_to: str = "massive_datasets") -> None:
    """
    Unpack the massive_datasets.tar.gz file.

    Args:
        tar_path: Path to the tar.gz file
        extract_to: Directory to extract to
    """
    if not os.path.exists(tar_path):
        raise FileNotFoundError(f"Dataset file not found: {tar_path}")

    os.makedirs(extract_to, exist_ok=True)

    print(f"Unpacking {tar_path} to {extract_to}...")
    with tarfile.open(tar_path, 'r:gz') as tar:
        tar.extractall(extract_to)
    print("✅ Dataset unpacked successfully.")


def prepare_training_data(dataset_dir: str, output_dir: str = "training_data") -> None:
    """
    Prepare training data for specialist and generalist models.

    This function processes the unpacked dataset and creates JSONL files
    for fine-tuning.

    Args:
        dataset_dir: Directory containing unpacked dataset
        output_dir: Directory to save prepared data
    """
    os.makedirs(output_dir, exist_ok=True)

    specialist_data = []
    generalist_data = []

    # Process files in the dataset directory
    for root, dirs, files in os.walk(dataset_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)

                    # Process data based on content type
                    if isinstance(data, list):
                        for item in data:
                            processed_item = process_data_item(item)
                            if processed_item:
                                # Categorize as specialist or generalist
                                if is_security_related(processed_item):
                                    specialist_data.append(processed_item)
                                else:
                                    generalist_data.append(processed_item)
                    elif isinstance(data, dict):
                        processed_item = process_data_item(data)
                        if processed_item:
                            if is_security_related(processed_item):
                                specialist_data.append(processed_item)
                            else:
                                generalist_data.append(processed_item)

                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    continue

    # Save to JSONL files
    save_to_jsonl(specialist_data, os.path.join(output_dir, "specialist_data.jsonl"))
    save_to_jsonl(generalist_data, os.path.join(output_dir, "generalist_data.jsonl"))

    print(f"✅ Prepared {len(specialist_data)} specialist samples")
    print(f"✅ Prepared {len(generalist_data)} generalist samples")


def process_data_item(item: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Process a single data item into training format.

    Args:
        item: Raw data item

    Returns:
        Processed item with 'text' field for training
    """
    # This is a placeholder - adapt based on actual data structure
    # Assuming the data has fields that can be converted to text

    text_parts = []

    # Extract relevant fields
    if 'title' in item:
        text_parts.append(f"Title: {item['title']}")
    if 'description' in item:
        text_parts.append(f"Description: {item['description']}")
    if 'content' in item:
        text_parts.append(f"Content: {item['content']}")
    if 'findings' in item:
        text_parts.append(f"Findings: {json.dumps(item['findings'])}")

    if text_parts:
        return {"text": "\n".join(text_parts)}
    return None


def is_security_related(item: Dict[str, str]) -> bool:
    """
    Determine if a data item is security-related for specialist model.

    Args:
        item: Processed data item

    Returns:
        True if security-related
    """
    text = item.get('text', '').lower()
    security_keywords = [
        'security', 'vulnerability', 'exploit', 'attack', 'malware',
        'threat', 'risk', 'compliance', 'audit', 'scan', 'intrusion'
    ]

    return any(keyword in text for keyword in security_keywords)


def save_to_jsonl(data: List[Dict[str, Any]], filepath: str) -> None:
    """
    Save data to JSONL format.

    Args:
        data: List of data items
        filepath: Output file path
    """
    with open(filepath, 'w') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')


def create_training_files(dataset_path: str = "massive_datasets.tar.gz",
                         extract_dir: str = "massive_datasets",
                         output_dir: str = "training_data") -> None:
    """
    Main function to create training files from dataset.

    Args:
        dataset_path: Path to the dataset tar.gz file
        extract_dir: Directory to extract dataset
        output_dir: Directory to save training data
    """
    print("🚀 Starting data preparation...")

    # Unpack dataset
    unpack_massive_datasets(dataset_path, extract_dir)

    # Prepare training data
    prepare_training_data(extract_dir, output_dir)

    print("✅ Data preparation complete!")


if __name__ == "__main__":
    create_training_files()
