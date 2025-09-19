#!/bin/bash
# Massive Dataset Generation Script
# Optimized for Google Colab L4 GPU (12-25GB system RAM, 22.5GB VRAM)
# Conservative settings to prevent OOM crashes
ULTRA_OPTIMIZED_ARGS=(
    "--output-dir" "./massive_datasets_ultra"
    "--batch-size" "50000"   # Reduced for Colab RAM limits
    "--max-batches" "200"    # Extended for massive dataset
    "--max-hours" "11.5"     # Colab 12-hour limit with buffer
    "--gpu"                  # GPU optimization enabled
    "--verbose"              # Detailed logging
    "--max-memory-gb" "20.0" # Conservative for Colab (12-25GB available)
    "--save-progress"        # Enable resumability
    "--compression-level" "6" # Balanced compression
    "--quality-threshold" "0.7" # Higher quality threshold
    "--parallel-workers" "20"  # Aggressive parallel processing for ultra mode
    "--fast-mode"            # Skip heavy enrichment for speed
)

echo
echo "🚀 ULTRA-OPTIMIZED CONFIGURATION (Colab L4 GPU):"
echo "  Output Directory: ./massive_datasets_ultra"
echo "  Batch Size: 50,000 findings per batch"
echo "  Max Batches: 200 (ultra-scalable)"
echo "  Max Runtime: 11.5 hours"
echo "  GPU Optimization: Enabled"
echo "  Memory Limit: 20.0 GB (conservative)"
echo "  Parallel Workers: 8"
echo "  Verbose Logging: Enabled"
echo "  Progress Saving: Enabled"
echo "  Compression: Level 6 (balanced)"
echo "  Quality Threshold: 0.7"
echo "  Expected Output: ~10M+ findings"
echo "  Estimated Runtime: 8-11 hours"
echo "This script generates ultra-massive synthetic datasets for advanced fine-tuning"

# Maximum viable parameters for Colab L4 GPU (12-25GB system RAM, 22.5GB VRAM)
# Conservative settings to prevent OOM crashes
MAX_VIABLE_ARGS=(
    "--output-dir" "./massive_datasets_max"
    "--batch-size" "25000"   # Conservative batch size for Colab
    "--max-batches" "100"    # Extended for massive dataset
    "--max-hours" "11.5"     # Colab 12-hour limit with buffer
    "--gpu"                  # GPU optimization enabled
    "--verbose"              # Detailed logging
    "--max-memory-gb" "18.0" # Conservative for Colab
    "--save-progress"        # Enable resumability
    "--compression-level" "6" # Balanced compression
    "--quality-threshold" "0.6" # Higher quality threshold
    "--parallel-workers" "16" # Aggressive parallel processing
    "--fast-mode"            # Skip heavy enrichment for speed
)

echo
echo "🚀 MAXIMUM VIABLE CONFIGURATION (Colab L4 GPU):"
echo "  Output Directory: ./massive_datasets_max"
echo "  Batch Size: 25,000 findings per batch"
echo "  Max Batches: 100 (scalable)"
echo "  Max Runtime: 11.5 hours"
echo "  GPU Optimization: Enabled"
echo "  Memory Limit: 18.0 GB (conservative)"
echo "  Verbose Logging: Enabled"
echo "  Progress Saving: Enabled"
echo "  Compression: Level 6 (balanced)"
echo "  Quality Threshold: 0.6"
echo "  Expected Output: ~2.5M+ findings"
echo "  Estimated Runtime: 4-6 hours"
echo "This script generates large synthetic datasets for fine-tuning"

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/agent/synthetic_data/generate_dataset.py"

echo "🚀 MASSIVE DATASET GENERATION LAUNCHER"
echo "======================================"
echo "Project Root: $SCRIPT_DIR"
echo "Script: $PYTHON_SCRIPT"
echo

# Check if Python script exists
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "❌ Error: Dataset generation script not found at $PYTHON_SCRIPT"
    echo "Please ensure you're running this from the project root directory."
    exit 1
fi

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3.7+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Error: Python $PYTHON_VERSION detected. Minimum required: $REQUIRED_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Check GPU availability
check_gpu() {
    if command -v nvidia-smi &> /dev/null; then
        echo "🔍 Checking GPU status..."
        nvidia-smi --query-gpu=name,memory.total,memory.free,utilization.gpu --format=csv,noheader,nounits
        echo
    else
        echo "⚠️  nvidia-smi not found. GPU monitoring unavailable."
        echo
    fi
}

check_gpu

# Default parameters for massive generation (optimized for Colab L4 GPU with 12-25GB system RAM, 22.5GB VRAM)
DEFAULT_ARGS=(
    "--output-dir" "./massive_datasets"
    "--batch-size" "15000"   # Conservative batch size for Colab
    "--max-batches" "100"    # More batches for massive dataset
    "--max-hours" "11.5"     # Colab 12-hour limit with buffer
    "--gpu"
    "--verbose"              # Detailed logging
    "--max-memory-gb" "16.0" # Conservative memory usage for Colab
    "--parallel-workers" "12" # Aggressive parallel processing for high RAM
    "--fast-mode"            # Skip heavy enrichment for speed
)

echo
echo "📋 ENHANCED CONFIGURATION (Colab L4 GPU):"
echo "  Output Directory: ./massive_datasets"
echo "  Batch Size: 15,000 findings per batch"
echo "  Max Batches: 100 (scalable)"
echo "  Max Runtime: 11.5 hours"
echo "  GPU Optimization: Enabled"
echo "  Memory Limit: 16.0 GB"
echo "  Parallel Workers: 6"
echo "  Verbose Logging: Enabled"
echo "  Expected Output: ~1.5M+ findings"
echo

# Allow custom arguments or use enhanced configuration
if [ $# -eq 0 ]; then
    echo "🔄 Using ENHANCED configuration for L4 GPU..."
    echo "💡 This will generate ~15M+ findings in 4-6 hours"
    echo "💡 Use Ctrl+C to interrupt and resume later"
    echo
    ARGS=("${DEFAULT_ARGS[@]}")
elif [ "$1" = "max" ]; then
    echo "🔄 Using MAXIMUM VIABLE configuration (explicit)..."
    echo "💡 This will generate ~10M+ findings in 6-8 hours"
    echo
    ARGS=("${MAX_VIABLE_ARGS[@]}")
elif [ "$1" = "ultra" ]; then
    echo "🔄 Using ULTRA-OPTIMIZED configuration (explicit)..."
    echo "💡 This will generate ~50M+ findings in 8-12 hours"
    echo "⚠️  Requires stable L4 GPU environment and sufficient storage"
    echo
    ARGS=("${ULTRA_OPTIMIZED_ARGS[@]}")
else
    echo "🔧 Using custom configuration..."
    echo
    ARGS=("$@")
fi

echo "🚀 EXECUTING COMMAND:"
echo "cd $SCRIPT_DIR && python3 $PYTHON_SCRIPT ${ARGS[*]}"
echo

# Change to project directory and run
cd "$SCRIPT_DIR"
python3 "$PYTHON_SCRIPT" "${ARGS[@]}"

EXIT_CODE=$?
echo
echo "📊 EXIT CODE: $EXIT_CODE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ MASSIVE DATASET GENERATION COMPLETED SUCCESSFULLY!"
    echo
    echo "📁 Check your output directory: $SCRIPT_DIR/massive_datasets"
    echo "📄 Generation report: $SCRIPT_DIR/massive_datasets/generation_report.json"
    echo
    echo "🎯 Ready for fine-tuning with substantial synthetic dataset!"
else
    echo "❌ Dataset generation failed with exit code $EXIT_CODE"
    echo
    echo "🔍 Check the error messages above for details"
    echo "💡 Common issues:"
    echo "   - Ensure all dependencies are installed"
    echo "   - Check available disk space"
    echo "   - Verify GPU availability (if using --gpu)"
fi

exit $EXIT_CODE