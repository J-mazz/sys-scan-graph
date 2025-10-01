#!/usr/bin/env python3
"""Split LoRA adapter into smaller safetensors files for Debian packaging.

This splits the 161MB adapter_model.safetensors into 4 chunks of ~40MB each,
organized by transformer layers, for easier packaging and distribution.
"""
import os
from pathlib import Path
from safetensors import safe_open
from safetensors.torch import save_file
import torch

def split_lora_adapter(
    input_path: str,
    output_dir: str,
    num_chunks: int = 4
):
    """Split LoRA adapter into multiple safetensors files.
    
    Args:
        input_path: Path to adapter_model.safetensors
        output_dir: Directory to write split files
        num_chunks: Number of chunks to create (default: 4)
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading LoRA adapter from: {input_path}")
    print(f"Output directory: {output_dir}")
    print(f"Splitting into {num_chunks} chunks...")
    
    # Load all tensors
    all_tensors = {}
    with safe_open(input_path, framework='pt') as f:
        for key in f.keys():
            all_tensors[key] = f.get_tensor(key)
    
    # Group tensors by layer number
    layer_groups = {}
    other_tensors = {}
    
    for key, tensor in all_tensors.items():
        if 'layers.' in key:
            layer_num = int(key.split('layers.')[1].split('.')[0])
            if layer_num not in layer_groups:
                layer_groups[layer_num] = {}
            layer_groups[layer_num][key] = tensor
        else:
            other_tensors[key] = tensor
    
    # Calculate layers per chunk
    total_layers = len(layer_groups)
    layers_per_chunk = total_layers // num_chunks
    
    print(f"\nTotal layers: {total_layers}")
    print(f"Layers per chunk: {layers_per_chunk}")
    
    # Split into chunks
    for chunk_idx in range(num_chunks):
        start_layer = chunk_idx * layers_per_chunk
        end_layer = start_layer + layers_per_chunk if chunk_idx < num_chunks - 1 else total_layers
        
        chunk_tensors = {}
        
        # Add layers for this chunk
        for layer_num in range(start_layer, end_layer):
            if layer_num in layer_groups:
                chunk_tensors.update(layer_groups[layer_num])
        
        # Add other tensors to first chunk only
        if chunk_idx == 0:
            chunk_tensors.update(other_tensors)
        
        # Calculate chunk size
        chunk_size = sum(t.numel() * t.element_size() for t in chunk_tensors.values()) / 1024 / 1024
        
        # Save chunk
        output_file = output_path / f"adapter_model_{chunk_idx + 1:02d}_of_{num_chunks:02d}.safetensors"
        save_file(chunk_tensors, str(output_file))
        
        print(f"  Chunk {chunk_idx + 1}/{num_chunks}: layers {start_layer}-{end_layer - 1}, "
              f"{len(chunk_tensors)} tensors, {chunk_size:.2f} MB -> {output_file.name}")
    
    print(f"\n✓ Split complete: {num_chunks} files in {output_dir}")
    print(f"  Total size: {sum(t.numel() * t.element_size() for t in all_tensors.values()) / 1024 / 1024:.2f} MB")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Split LoRA adapter for packaging')
    parser.add_argument('--input', default='mistral-security-lora/adapter_model.safetensors',
                        help='Input adapter_model.safetensors file')
    parser.add_argument('--output', default='mistral-security-lora/shards',
                        help='Output directory for split files')
    parser.add_argument('--chunks', type=int, default=4,
                        help='Number of chunks to create (default: 4)')
    
    args = parser.parse_args()
    split_lora_adapter(args.input, args.output, args.chunks)
