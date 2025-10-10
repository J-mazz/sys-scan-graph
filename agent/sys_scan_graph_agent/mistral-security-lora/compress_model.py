#!/usr/bin/env python3
"""
Script to split adapter_model.safetensors into 3-4 safetensors files for better packagability.
This script splits the tensors by layer ranges without compression.
"""

import torch
from safetensors.torch import load_file, save_file
import os
import re

def get_layer_num(key):
    """Extract layer number from tensor key."""
    match = re.search(r'layers\.(\d+)\.', key)
    return int(match.group(1)) if match else -1

def split_into_groups(tensors, num_groups=4):
    """Split tensors into groups based on layer number."""
    # Group by layer
    layer_groups = {}
    for key, tensor in tensors.items():
        layer = get_layer_num(key)
        if layer not in layer_groups:
            layer_groups[layer] = {}
        layer_groups[layer][key] = tensor
    
    # Sort layers
    sorted_layers = sorted(layer_groups.keys())
    total_layers = len(sorted_layers)
    group_size = (total_layers + num_groups - 1) // num_groups  # Ceiling division
    
    groups = []
    for i in range(num_groups):
        start = i * group_size
        end = min((i + 1) * group_size, total_layers)
        group_layers = sorted_layers[start:end]
        group_tensors = {}
        for layer in group_layers:
            group_tensors.update(layer_groups[layer])
        groups.append(group_tensors)
    
    return groups

def main():
    output_dir = "/home/joseph-mazzini/sys-scan-graph/agent/sys_scan_graph_agent/mistral-security-lora"

    # Process each part
    parts = [f"adapter_part{i}.safetensors" for i in range(1, 5)]
    for part in parts:
        adapter_path = os.path.join(output_dir, part)
        print(f"Loading {part}...")
        adapter_tensors = load_file(adapter_path)

        # Split into 2 groups
        print(f"Splitting {part} into 2 groups...")
        adapter_groups = split_into_groups(adapter_tensors, num_groups=2)

        for j, group in enumerate(adapter_groups):
            # Save group
            output_path = os.path.join(output_dir, f"{part.replace('.safetensors', '')}_{j+1}.safetensors")
            print(f"Saving {output_path}...")
            save_file(group, output_path)
            
            size = os.path.getsize(output_path) / (1024 * 1024)  # MB
            print(f"Size: {size:.2f} MB")

    print("Success: All parts split into ~20MB pieces.")

if __name__ == "__main__":
    main()