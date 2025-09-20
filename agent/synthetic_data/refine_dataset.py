#!/usr/bin/env python3
"""
Dataset Refinement - Combine and streamline batch tarballs into high signal/low noise data
"""

import argparse
import json
import tarfile
import sys
from pathlib import Path
from collections import defaultdict
import hashlib

def combine_batches(input_paths, output_path):
    """Combine tarballs into streamlined dataset"""
    all_findings = []
    seen_signatures = set()

    for path in input_paths:
        print(f"Processing {path}...")
        path_obj = Path(path)

        if path_obj.is_file() and (path.endswith('.tar.gz') or path.endswith('.tgz')):
            with tarfile.open(path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith('.json'):
                        f = tar.extractfile(member)
                        if f is not None:
                            with f:
                                batch_data = json.load(f)
                                findings = batch_data.get('findings', [])

                                for finding in findings:
                                    # Create signature for deduplication
                                    sig = create_signature(finding)
                                    if sig not in seen_signatures:
                                        seen_signatures.add(sig)
                                        all_findings.append(finding)

        elif path_obj.is_file() and path.endswith('.json'):
            with open(path, 'r') as f:
                batch_data = json.load(f)
                findings = batch_data.get('findings', [])

                for finding in findings:
                    sig = create_signature(finding)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        all_findings.append(finding)

        elif path_obj.is_dir():
            for json_file in path_obj.glob('**/*.json'):
                try:
                    with open(json_file, 'r') as f:
                        batch_data = json.load(f)
                        findings = batch_data.get('findings', [])

                        for finding in findings:
                            sig = create_signature(finding)
                            if sig not in seen_signatures:
                                seen_signatures.add(sig)
                                all_findings.append(finding)
                except Exception as e:
                    print(f"Error loading {json_file}: {e}")

    # Create streamlined output
    streamlined_data = {
        'metadata': {
            'total_findings': len(all_findings),
            'deduplication_applied': True,
            'source_batches': len(input_paths)
        },
        'findings': all_findings
    }

    with open(output_path, 'w') as f:
        json.dump(streamlined_data, f, separators=(',', ':'))

    print(f"Combined {len(input_paths)} sources into {len(all_findings)} unique findings")
    print(f"Saved to {output_path}")

def create_signature(finding):
    """Create deduplication signature"""
    key_parts = [
        finding.get('type', ''),
        finding.get('process_name', finding.get('name', '')),
        finding.get('file_path', finding.get('path', '')),
        finding.get('local_address', ''),
        finding.get('remote_address', ''),
        str(finding.get('port', 0))
    ]
    return hashlib.md5('|'.join(key_parts).encode()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Combine batch tarballs into streamlined dataset")
    parser.add_argument("input_paths", nargs="+", help="Input tarballs or directories")
    parser.add_argument("--output", "-o", default="combined_dataset.json", help="Output file")

    args = parser.parse_args()
    combine_batches(args.input_paths, args.output)

if __name__ == "__main__":
    main()