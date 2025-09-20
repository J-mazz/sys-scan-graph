#!/usr/bin/env python3
"""
Dataset downloader for Colab environment.
Automatically downloads the dataset if not found locally.
"""

import os
import urllib.request
from pathlib import Path

def download_dataset():
    """Download the massive datasets file if not found locally."""
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

    # If dataset not found, try to download it automatically
    if dataset_path is None:
        print("❌ Dataset not found locally")
        print("🔄 Attempting automatic download...")

        # Try multiple download sources (update these URLs as needed)
        download_urls = [
            "https://github.com/Mazzlabs/sys-scan-graph/releases/download/v1.0/massive_datasets.tar.gz",
            # Add alternative URLs here:
            # "https://drive.google.com/uc?export=download&id=YOUR_FILE_ID",
            # "https://your-cdn.com/massive_datasets.tar.gz",
        ]

        for dataset_url in download_urls:
            try:
                print(f"📥 Downloading dataset from: {dataset_url}")
                urllib.request.urlretrieve(dataset_url, "massive_datasets.tar.gz")
                dataset_path = "massive_datasets.tar.gz"
                print("✅ Dataset downloaded successfully")
                break
            except Exception as e:
                print(f"❌ Download from {dataset_url} failed: {e}")
                continue

        if dataset_path is None:
            print("🔄 All download attempts failed")
            print("🔄 Please upload 'massive_datasets.tar.gz' to your Colab workspace manually")
            print("   Or update the download_urls list in this script with correct links")
            print(f"   Current directory: {os.getcwd()}")
            print("   Files in current directory:")
            os.system("ls -la")
            print("   Files in /content/:")
            os.system("ls -la /content/")
            return None
    else:
        print(f"✅ Dataset found at: {dataset_path}")

    return dataset_path

if __name__ == "__main__":
    dataset_path = download_dataset()
    if dataset_path:
        print(f"Dataset ready at: {dataset_path}")
    else:
        print("Failed to obtain dataset")
        exit(1)