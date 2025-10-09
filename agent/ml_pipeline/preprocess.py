# ╔══════════════════════════════════╗
# ║             MazzLabs             ║
# ╟──────────────────────────────────╢
# ║           Joseph Mazzini         ║
# ╚══════════════════════════════════╝

# ==============================================================================
"""
ML Data Preprocessing Pipeline

Processes raw security scanner data into formatted datasets for model training,
including compression handling and dataset preparation for the intelligence layer.
"""

import json
import os
import gzip
from datasets import Dataset, DatasetDict
from tqdm import tqdm

def preprocess_and_save_data():
    """
    Finds, processes, and saves raw JSON findings to a persistent GDrive location.
    """
    # --- Define Correct Absolute Paths ---
    # Path to the directory containing your raw data files
    dataset_dir = "../massive_datasets"
    
    # Path where the final processed dataset will be saved
    output_dir = "."
    output_path = os.path.join(output_dir, "processed_dataset")

    if not os.path.isdir(dataset_dir):
        print(f"❌ ERROR: Input directory not found at '{dataset_dir}'.")
        return
        
    print(f"Starting pre-processing from: {dataset_dir}")

    # (The rest of the script remains the same)
    file_paths = []
    for root, _, files in os.walk(dataset_dir):
        for file in files:
            if file.startswith("batch_") and file.endswith(".json"):
                file_paths.append(os.path.join(root, file))

    all_findings = []
    for file_path in tqdm(file_paths, desc="Processing raw files"):
        try:
            with open(file_path, 'r', encoding='utf-8') as infile:
                content = json.load(infile)
                if content.get('compressed'):
                    hex_string = content['data']
                    compressed_bytes = bytes.fromhex(hex_string)
                    decompressed_json_string = gzip.decompress(compressed_bytes).decode('utf-8')
                    decompressed_data = json.loads(decompressed_json_string)
                    if 'data' in decompressed_data and 'findings' in decompressed_data['data']:
                        findings_by_category = decompressed_data['data']['findings']
                        for category, severity_levels in findings_by_category.items():
                            if isinstance(severity_levels, dict):
                                for severity, findings_list in severity_levels.items():
                                    if isinstance(findings_list, list):
                                        all_findings.extend(findings_list)
        except Exception as e:
            print(f"Skipping file {file_path} due to error: {e}")
            continue
    
    print(f"\n✅ Extracted {len(all_findings)} total findings.")
    print("\nFormatting findings for training...")
    formatted_records = []
    for record in tqdm(all_findings, desc="Formatting"):
        formatted_text = f"Analyze the following security finding and provide an assessment:\n\n{json.dumps(record, indent=2)}"
        formatted_records.append({"text": formatted_text})

    print(f"Formatted {len(formatted_records)} findings for training.")
    print("\nCreating, splitting, and saving the dataset...")
    if not formatted_records:
        print("❌ No records found to create a dataset. Exiting.")
        return

    full_dataset = Dataset.from_list(formatted_records)
    train_test_split = full_dataset.train_test_split(test_size=0.2, seed=42)
    split_dataset = DatasetDict({'train': train_test_split['train'], 'validation': train_test_split['test']})
    
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    split_dataset.save_to_disk(output_path)

    print(f"\n✅ SUCCESS! Dataset saved to persistent location: {output_path}")

if __name__ == "__main__":
    preprocess_and_save_data()