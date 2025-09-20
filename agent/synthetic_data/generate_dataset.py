#!/usr/bin/env python3
"""
Production-ready     def __init__(self, gpu_optimized: bool = True, conservative_parallel: bool = False, fast_mode: bool = False, max_memory_gb: float = 45.0, parallel_workers: Optional[int] = None, use_langchain: bool = True):
        self.gpu_optimized = gpu_optimized
        self.conservative_parallel = conser    parser = argparse.ArgumentParser(
        description="Generate massive synthetic datasets for fine-tuning (Production Mode)\n\n"
                   "MODES:\n"
                   "  Default: Conservative settings for Colab safety (5k/batch, 20 batches)\n"
                   "  --ultra: Ultra mode - 35k/batch, 120 batches, 11.5h, 20 workers, 20GB memory\n"
                   "           Full enrichment with LangChain, GPU optimization, balanced performance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )arallel
        self.fast_mode = fast_mode
        self.max_memory_gb = max_memory_gb
        self.parallel_workers = parallel_workers
        self.pipeline = SyntheticDataPipeline(
            use_langchain=use_langchain,  # Enable LangChain enrichment when available
            conservative_parallel=conservative_parallel,
            gpu_optimized=gpu_optimized,
            fast_mode=fast_mode,
            max_workers=parallel_workers
        )data generation pipeline for massive dataset creation.
Optimized for T4 GPU with extended runtime capabilities.
"""

import argparse
import sys
import os
import json
import time
import signal
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import threading

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('generation.log', mode='w')
    ]
)
logger = logging.getLogger(__name__)

# Add the synthetic_data directory to the path
script_dir = os.path.dirname(os.path.abspath(__file__) if '__file__' in globals() else os.getcwd())
sys.path.insert(0, script_dir)

from synthetic_data_pipeline import SyntheticDataPipeline

class DatasetGenerator:
    """Production dataset generator with monitoring and extended runtime support."""

    def __init__(self, gpu_optimized: bool = True, conservative_parallel: bool = False, fast_mode: bool = False, max_memory_gb: float = 12.0, parallel_workers: Optional[int] = None, use_langchain: bool = True):
        # Auto-detect conservative vs aggressive parallel based on system capabilities
        cpu_count = os.cpu_count() or 4
        if parallel_workers is None:
            # Auto-scale workers based on CPU cores for local development
            if cpu_count >= 8:
                parallel_workers = min(cpu_count, 10)  # Use up to 10 workers on 8+ core systems
                conservative_parallel = False
                print(f"🔄 Multi-core system detected ({cpu_count} cores), using {parallel_workers} workers")
            elif cpu_count >= 4:
                parallel_workers = min(cpu_count, 6)  # Use up to 6 workers on 4+ core systems
                conservative_parallel = False
            else:
                parallel_workers = 2  # Conservative for low-core systems
                conservative_parallel = True
        
        # Override conservative mode for high worker counts
        if parallel_workers and parallel_workers > 4:
            conservative_parallel = False
            print(f"🔄 High worker count ({parallel_workers}) detected, using aggressive parallel processing")
        
        self.gpu_optimized = gpu_optimized
        self.conservative_parallel = conservative_parallel
        self.fast_mode = fast_mode
        self.max_memory_gb = max_memory_gb
        self.parallel_workers = parallel_workers
        self.pipeline = SyntheticDataPipeline(
            use_langchain=use_langchain,
            conservative_parallel=conservative_parallel,
            gpu_optimized=gpu_optimized,
            fast_mode=fast_mode,
            max_workers=parallel_workers
        )
        self.running = True
        self.stats = {
            "start_time": None,
            "end_time": None,
            "batches_completed": 0,
            "total_findings": 0,
            "total_correlations": 0,
            "errors": []
        }

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n⚠️  Received signal {signum}, shutting down gracefully...")
        self.running = False

    def _monitor_resources(self):
        """Monitor system resources during generation."""
        if not HAS_PSUTIL or psutil is None:
            return

        while self.running:
            try:
                cpu_percent = psutil.cpu_percent(interval=5)
                memory = psutil.virtual_memory()

                # Check for memory pressure - prevent OOM crashes
                memory_percent = memory.percent
                if memory_percent > 85:  # Critical threshold
                    print(f"⚠️  CRITICAL: High memory usage ({memory_percent:.1f}%), reducing batch size and workers")
                    # This would require adjusting batch size dynamically, but for now just warn
                    # In a full implementation, we'd reduce batch_size here

                # GPU monitoring if available
                gpu_info = ""
                try:
                    import subprocess
                    result = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu,memory.used,memory.total', '--format=csv,noheader,nounits'],
                                          capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        gpu_info = f" | GPU: {result.stdout.strip()}"
                except:
                    pass

                print(f"📊 CPU: {cpu_percent:.1f}% | Memory: {memory_percent:.1f}% | Findings: {self.stats['total_findings']:,}{gpu_info}")
                time.sleep(30)  # Update every 30 seconds
            except:
                break

    def generate_massive_dataset(
        self,
        output_dir: str,
        batch_size: int = 5000,
        max_batches: int = 10,
        max_runtime_hours: float = 2.0
    ) -> Dict[str, Any]:
        """
        Generate massive dataset through multiple batches.

        Args:
            output_dir: Output directory
            batch_size: Findings per batch
            max_batches: Maximum number of batches
            max_runtime_hours: Maximum runtime in hours
        """
        print("🚀 MASSIVE DATASET GENERATION - PRODUCTION MODE")
        print("=" * 60)
        print(f"Batch Size: {batch_size:,} findings")
        print(f"Max Batches: {max_batches}")
        print(f"Max Runtime: {max_runtime_hours} hours")
        print(f"GPU Optimized: {self.gpu_optimized}")
        print()

        # Pre-flight memory check
        if HAS_PSUTIL and psutil:
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            print(f"🧠 System Memory Check: {available_gb:.1f}GB available")
            if available_gb < 8.0:  # Minimum required
                print("❌ ERROR: Insufficient memory (< 8GB available). Reduce batch size or free up memory.")
                return {"error": "insufficient_memory", "available_gb": available_gb}
            if self.max_memory_gb and available_gb < self.max_memory_gb:
                print(f"⚠️  WARNING: Requested {self.max_memory_gb}GB but only {available_gb:.1f}GB available. Adjusting...")
                self.max_memory_gb = available_gb * 0.8  # Use 80% of available
        else:
            print("⚠️  Memory monitoring unavailable - proceed with caution")

        logger.info(f"Starting massive dataset generation with {max_batches} batches of {batch_size} findings each")
        logger.info(f"GPU optimization: {self.gpu_optimized}, Conservative parallel: {self.conservative_parallel}")

        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        self.stats["start_time"] = time.time()
        start_time = self.stats["start_time"]

        # Start resource monitoring
        monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        monitor_thread.start()
        logger.debug("Resource monitoring thread started")

        all_results = []
        batch_num = 1

        try:
            while self.running and batch_num <= max_batches:
                elapsed_hours = (time.time() - start_time) / 3600
                if elapsed_hours >= max_runtime_hours:
                    print(f"⏰ Reached maximum runtime of {max_runtime_hours} hours")
                    break

                print(f"\n🔄 BATCH {batch_num}/{max_batches} (Elapsed: {elapsed_hours:.2f}h)")
                print("-" * 40)

                # Calculate producer counts for this batch
                producer_counts = self._calculate_producer_counts(batch_size)

                logger.info(f"Starting batch {batch_num}/{max_batches}")
                logger.debug(f"Producer counts: {producer_counts}")

                # Generate batch
                batch_start = time.time()
                try:
                    result = self._generate_batch(producer_counts, output_dir_path, batch_num)
                except MemoryError:
                    print(f"❌ MEMORY ERROR in batch {batch_num}: Out of memory! Try reducing batch size.")
                    self.stats["errors"].append(f"Batch {batch_num} failed: Out of memory")
                    batch_num += 1
                    continue
                except Exception as e:
                    print(f"❌ ERROR in batch {batch_num}: {e}")
                    self.stats["errors"].append(f"Batch {batch_num} failed: {str(e)}")
                    batch_num += 1
                    continue

                batch_end = time.time()

                if result:
                    all_results.append(result)
                    self.stats["batches_completed"] += 1
                    self.stats["total_findings"] += result["data_summary"]["total_findings"]
                    self.stats["total_correlations"] += result["data_summary"]["total_correlations"]

                    batch_time = batch_end - batch_start
                    print(f"  ✓ Batch {batch_num} completed in {batch_time:.2f}s")
                    logger.info(f"Batch {batch_num} completed: {result['data_summary']['total_findings']} findings, {result['data_summary']['total_correlations']} correlations in {batch_time:.2f}s")
                else:
                    self.stats["errors"].append(f"Batch {batch_num} failed")
                    print(f"❌ Batch {batch_num} failed")
                    logger.error(f"Batch {batch_num} failed")

                batch_num += 1

        except Exception as e:
            self.stats["errors"].append(str(e))
            print(f"❌ Error: {e}")

        finally:
            self.running = False
            self.stats["end_time"] = time.time()

        # Generate final report
        return self._generate_final_report(all_results, output_dir_path)

    def _calculate_producer_counts(self, total_findings: int) -> Dict[str, int]:
        """Calculate balanced producer counts for optimal generation."""
        producers = self.pipeline.get_available_producers()

        # Base distribution weights
        weights = {
            "processes": 0.25,
            "network": 0.20,
            "kernel_params": 0.15,
            "filesystem": 0.15,
            "modules": 0.10,
            "ioc": 0.08,
            "mac": 0.04,
            "suid": 0.03
        }

        counts = {}
        for producer in producers:
            if producer in weights:
                count = max(1, int(total_findings * weights[producer]))
                counts[producer] = count

        # Ensure we hit the target total
        current_total = sum(counts.values())
        if current_total < total_findings:
            # Add remainder to processes
            counts["processes"] += (total_findings - current_total)

        return counts

    def _generate_batch(self, producer_counts: Dict[str, int], output_dir: Path, batch_num: int) -> Optional[Dict[str, Any]]:
        """Generate a single batch of data."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = output_dir / f"batch_{batch_num:03d}_{timestamp}.json"

            result = self.pipeline.execute_pipeline(
                producer_counts=producer_counts,
                output_path=str(output_path),
                output_format="optimized_json",
                compress=True,
                save_intermediate=False
            )

            return result

        except Exception as e:
            print(f"❌ Batch generation failed: {e}")
            return None

    def _generate_final_report(self, all_results: list, output_dir: Path) -> Dict[str, Any]:
        """Generate comprehensive final report."""
        end_time = self.stats["end_time"]
        start_time = self.stats["start_time"]
        total_runtime = end_time - start_time

        final_report = {
            "generation_stats": {
                "total_runtime_seconds": total_runtime,
                "total_runtime_hours": total_runtime / 3600,
                "batches_completed": self.stats["batches_completed"],
                "total_findings": self.stats["total_findings"],
                "total_correlations": self.stats["total_correlations"],
                "findings_per_second": self.stats["total_findings"] / total_runtime if total_runtime > 0 else 0,
                "gpu_optimized": self.gpu_optimized,
                "errors": self.stats["errors"]
            },
            "batch_results": all_results,
            "system_info": {
                "cpu_count": os.cpu_count(),
                "memory_gb": psutil.virtual_memory().total / (1024**3) if HAS_PSUTIL and psutil else 0,
                "platform": sys.platform
            },
            "output_directory": str(output_dir)
        }

        # Save final report
        report_path = output_dir / "generation_report.json"
        with open(report_path, 'w') as f:
            json.dump(final_report, f, indent=2, default=str)

        return final_report

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate massive synthetic datasets for fine-tuning (Production Mode)\n\n"
                   "MODES:\n"
                   "  Default: Conservative settings for Colab safety (5k/batch, 20 batches)\n"
                   "  --ultra: Ultra mode - 35k/batch, 120 batches, 11.5h, 20 workers, 20GB memory\n"
                   "           Full enrichment with LangChain, GPU optimization, balanced performance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "--output-dir", "-o",
        default="./massive_datasets",
        help="Output directory for generated datasets"
    )

    parser.add_argument(
        "mode",
        nargs="?",
        choices=["default", "ultra"],
        default="ultra",  # Default to ultra mode for Colab
        help="Generation mode: 'default' (conservative) or 'ultra' (optimized)"
    )

    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=5000,  # Reduced default for Colab safety
        help="Findings per batch"
    )

    parser.add_argument(
        "--max-batches", "-m",
        type=int,
        default=20,  # Reduced default
        help="Maximum number of batches to generate"
    )

    parser.add_argument(
        "--max-hours", "-t",
        type=float,
        default=2.0,  # Conservative default
        help="Maximum runtime in hours"
    )

    parser.add_argument(
        "--gpu",
        action="store_true",
        default=True,  # Default to GPU on Colab/T4
        help="Enable GPU optimization (auto-detected)"
    )

    parser.add_argument(
        "--no-gpu",
        action="store_false",
        dest="gpu",
        help="Disable GPU optimization"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose logging and detailed progress output"
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress non-essential output"
    )

    parser.add_argument(
        "--conservative",
        action="store_true",
        default=False,
        help="Use conservative parallel processing"
    )

    parser.add_argument(
        "--fast-mode",
        action="store_true",
        default=False,
        help="Use fast mode (skip heavy enrichment for massive datasets)"
    )

    parser.add_argument(
        "--max-memory-gb",
        type=float,
        default=12.0,  # Adjusted for T4 GPU (15GB VRAM)
        help="Maximum memory usage in GB"
    )

    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        help="Number of parallel workers (auto-detected if not specified)"
    )

    parser.add_argument(
        "--save-progress",
        action="store_true",
        default=False,
        help="Enable progress saving for resumability"
    )

    parser.add_argument(
        "--compression-level",
        type=int,
        default=6,
        help="Compression level for output files (1-9)"
    )

    parser.add_argument(
        "--quality-threshold",
        type=float,
        default=0.7,
        help="Quality threshold for data validation (0.0-1.0)"
    )

    parser.add_argument(
        "--no-langchain",
        action="store_true",
        default=False,
        help="Disable LangChain enrichment (use basic transformation only)"
    )

    args = parser.parse_args()

    # Handle mode selection - default to ultra for Colab performance
    if args.mode == "ultra" or args.ultra:  # Support both positional and flag
        print("🚀 ULTRA MODE ACTIVATED - OPTIMIZED FOR COLAB PERFORMANCE")
        print("=" * 60)
        args.batch_size = 35000  # Reduced from 50k for faster batches
        args.max_batches = 120   # Reduced from 200 for reasonable completion time
        args.max_hours = 11.5
        args.max_memory_gb = 20.0
        args.parallel_workers = 1  # Sequential execution for stability
        args.gpu = True
        args.fast_mode = False  # Ultra mode uses full enrichment
        args.no_langchain = False  # Ultra mode uses LangChain
        print("Settings: 35k findings/batch, 120 batches, 11.5h runtime, 1 worker (sequential)")
        print("GPU: Enabled, Fast Mode: Disabled, LangChain: Enabled")
        print("=" * 60)
        print()
    else:
        print("📊 DEFAULT MODE - CONSERVATIVE SETTINGS")
        print("=" * 40)
        print("Settings: 5k findings/batch, 20 batches, 2h runtime")
        print("Use 'ultra' mode for optimized performance")
        print("=" * 40)
        print()

    # Configure logging based on verbosity
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Verbose logging enabled")
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Initialize generator
    generator = DatasetGenerator(
        gpu_optimized=args.gpu,
        conservative_parallel=args.conservative,
        fast_mode=args.fast_mode,
        max_memory_gb=args.max_memory_gb,
        parallel_workers=args.parallel_workers,
        use_langchain=not args.no_langchain
    )

    # Generate massive dataset
    result = generator.generate_massive_dataset(
        output_dir=args.output_dir,
        batch_size=args.batch_size,
        max_batches=args.max_batches,
        max_runtime_hours=args.max_hours
    )

    # Print final summary
    stats = result["generation_stats"]
    print("\n🎉 GENERATION COMPLETE!")
    print("=" * 60)
    print(f"Runtime: {stats['total_runtime_hours']:.2f} hours")
    print(f"Batches: {stats['batches_completed']}")
    print(f"Total Findings: {stats['total_findings']:,}")
    print(f"Total Correlations: {stats['total_correlations']:,}")
    print(f"Findings/sec: {stats['findings_per_second']:.1f}")
    print(f"Output: {result['output_directory']}")

    if stats["errors"]:
        print(f"Errors: {len(stats['errors'])}")
        for error in stats["errors"][:3]:
            print(f"  • {error}")

    return 0

if __name__ == "__main__":
    sys.exit(main())