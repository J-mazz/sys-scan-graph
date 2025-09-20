#!/usr/bin/env python3
"""
Data preparation pipeline for ML training.
Loads synthetic data from massive_datasets.tar.gz and creates training datasets.
"""

import tarfile
import gzip
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataLoader:
    """Handles loading and processing of synthetic training data."""

    def __init__(self, archive_path: Path):
        self.archive_path = archive_path
        self.training_data_dir = Path("training_data")
        self.specialist_file = self.training_data_dir / "specialist_data.jsonl"
        self.generalist_file = self.training_data_dir / "generalist_data.jsonl"

    def decompress_and_load_data(self):
        """Generator that yields decompressed JSON records from the archive."""
        if not self.archive_path.exists():
            raise FileNotFoundError(f"Dataset archive not found at {self.archive_path}")

        logger.info(f"Loading data from {self.archive_path}")

        with tarfile.open(self.archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith(".json"):
                    logger.debug(f"Processing batch: {member.name}")
                    file_content = tar.extractfile(member).read()

                    try:
                        # The data inside might be gzipped
                        if file_content.startswith(b'\x1f\x8b'):  # gzip magic bytes
                            decompressed = gzip.decompress(file_content)
                            record = json.loads(decompressed)
                        else:
                            record = json.loads(file_content)

                        yield record
                    except Exception as e:
                        logger.warning(f"Failed to process {member.name}: {e}")
                        continue

    def extract_raw_scan_from_ground_truth(self, ground_truth: dict) -> dict:
        """Extract raw scanner output from enriched ground truth."""
        # This simulates the "before" state for the Specialist model
        # Remove enrichment fields and keep only basic findings
        raw_scan = {
            "timestamp": ground_truth.get("timestamp"),
            "version": ground_truth.get("version", "5.0.0"),
            "hostname": ground_truth.get("hostname", "localhost"),
            "data": {
                "findings": ground_truth.get("data", {}).get("findings", []),
                "summary": {
                    "total_findings": len(ground_truth.get("data", {}).get("findings", [])),
                    "severity_breakdown": ground_truth.get("data", {}).get("summary", {}).get("severity_breakdown", {})
                }
            }
        }
        return raw_scan

    def create_agentic_training_example(self, enriched_report: dict) -> tuple[str, str]:
        """Create a training example for the Generalist model."""
        # Generate a prompt based on the enriched report
        prompt = f"""Given the following enriched security report, determine the next logical step for an agent to take:

REPORT:
{json.dumps(enriched_report, indent=2)}

What is the most appropriate next action? Consider:
- Additional data collection needed
- Tool execution required
- Analysis refinement
- Risk assessment updates

NEXT ACTION:
"""

        # Generate a completion based on the report content
        completion = self._generate_completion_from_report(enriched_report)

        return prompt, completion

    def _generate_completion_from_report(self, report: dict) -> str:
        """Generate a realistic completion based on report analysis."""
        findings = report.get("data", {}).get("findings", [])
        correlations = report.get("data", {}).get("correlations", [])

        # Analyze findings to determine next action
        high_severity = [f for f in findings if f.get("severity") == "high"]
        critical_findings = [f for f in findings if f.get("severity") == "critical"]

        if critical_findings:
            return '{"tool_call": "get_file_hash", "parameters": {"path": "/etc/shadow"}, "reason": "Critical finding requires immediate file integrity check"}'
        elif high_severity:
            return '{"tool_call": "check_process_details", "parameters": {"pid": "1234"}, "reason": "High severity finding needs process investigation"}'
        elif correlations:
            return '{"action": "analyze_correlations", "parameters": {"correlation_ids": ["corr_001"]}, "reason": "Correlations detected requiring deeper analysis"}'
        else:
            return '{"action": "generate_report", "parameters": {"format": "detailed"}, "reason": "Analysis complete, generate comprehensive report"}'

    def create_training_sets(self):
        """Main method to create both training datasets."""
        self.training_data_dir.mkdir(exist_ok=True)

        specialist_count = 0
        generalist_count = 0

        with open(self.specialist_file, "w", encoding="utf-8") as f_specialist, \
             open(self.generalist_file, "w", encoding="utf-8") as f_generalist:

            for record in self.decompress_and_load_data():
                # Create Specialist training example
                raw_scan = self.extract_raw_scan_from_ground_truth(record)

                specialist_prompt = f"""Analyze the following raw sys-scan JSON output and transform it into a fully enriched and correlated security report.

INPUT:
{json.dumps(raw_scan, indent=2)}

OUTPUT:
"""

                specialist_record = {
                    "prompt": specialist_prompt,
                    "completion": json.dumps(record, indent=2)
                }

                f_specialist.write(json.dumps(specialist_record, ensure_ascii=False) + "\n")
                specialist_count += 1

                # Create Generalist training example
                generalist_prompt, generalist_completion = self.create_agentic_training_example(record)

                generalist_record = {
                    "prompt": generalist_prompt,
                    "completion": generalist_completion
                }

                f_generalist.write(json.dumps(generalist_record, ensure_ascii=False) + "\n")
                generalist_count += 1

                if specialist_count % 100 == 0:
                    logger.info(f"Processed {specialist_count} training examples...")

        logger.info(f"Created {specialist_count} specialist training examples")
        logger.info(f"Created {generalist_count} generalist training examples")
        logger.info(f"Training data saved to {self.training_data_dir}")

def main():
    parser = argparse.ArgumentParser(description="Prepare training data from synthetic datasets")
    parser.add_argument(
        "--archive-path",
        type=Path,
        default=Path("../../massive_datasets.tar.gz"),
        help="Path to the massive datasets archive"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training_data"),
        help="Output directory for training data"
    )

    args = parser.parse_args()

    # Adjust archive path if running from ml_pipeline directory
    if not args.archive_path.exists():
        # Try relative to agent directory
        alt_path = Path(__file__).parent.parent / "massive_datasets.tar.gz"
        if alt_path.exists():
            args.archive_path = alt_path
        else:
            logger.error(f"Could not find archive at {args.archive_path} or {alt_path}")
            return 1

    loader = DataLoader(args.archive_path)
    loader.create_training_sets()

    return 0

if __name__ == "__main__":
    exit(main())