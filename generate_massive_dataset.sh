#!/bin/bash
# Massive Dataset Generati# Maximum viable parameters for L4 GPU (51GB RAM, 22.5GB VRAM)
# Optimized for maximum throughput while maintaining stability
MAX_VIABLE_ARGS=(
    "--output-dir" "./massive_datasets_max"
    "--batch-size" "100000"  # Maximum batch size for L4
    "--max-batches" "100"    # Extended for massive dataset
    "--max-hours" "8.0"      # Extended runtime for completion
    "--gpu"                  # GPU optimization enabled
    "--verbose"              # Detailed logging
    "--max-memory-gb" "45.0" # Leave 6GB headroom
    "--save-progress"        # Enable resumability
    "--compression-level" "6" # Balanced compression
    "--quality-threshold" "0.6" # Higher quality threshold
)

echo
echo "🚀 MAXIMUM VIABLE CONFIGURATION (L4 GPU Optimized):"
echo "  Output Directory: ./massive_datasets_max"
echo "  Batch Size: 100,000 findings per batch"
echo "  Max Batches: 100 (scalable)"
echo "  Max Runtime: 8.0 hours"
echo "  GPU Optimization: Enabled"
echo "  Memory Limit: 45.0 GB (6GB headroom)"
echo "  Verbose Logging: Enabled"
echo "  Progress Saving: Enabled"
echo "  Compression: Level 6 (balanced)"
echo "  Quality Threshold: 0.6"
echo "  Expected Output: ~10M+ findings"
echo "  Estimated Runtime: 6-8 hours"
echois script to generate huge synthetic datasets for fine-tuning

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

# Default parameters for massive generation (optimized for L4 GPU with 51GB RAM, 22.5GB VRAM)
DEFAULT_ARGS=(
    "--output-dir" "./massive_datasets"
    "--batch-size" "15000"  # Increased for L4 GPU power
    "--max-batches" "50"    # More batches for massive dataset
    "--max-hours" "4.0"     # Extended runtime
    "--gpu"
    "--verbose"             # Detailed logging
)

echo
echo "📋 CONFIGURATION (L4 GPU Optimized):"
echo "  Output Directory: ./massive_datasets"
echo "  Batch Size: 15,000 findings per batch"
echo "  Max Batches: 50 (scalable)"
echo "  Max Runtime: 4.0 hours"
echo "  GPU Optimization: Enabled"
echo "  Verbose Logging: Enabled"
echo "  Expected Output: ~750K+ findings"
echo

# Allow custom arguments or use maximum viable configuration
if [ $# -eq 0 ]; then
    echo "🔄 Using MAXIMUM VIABLE configuration for L4 GPU..."
    echo "💡 This will generate ~10M+ findings in 6-8 hours"
    echo "💡 Use Ctrl+C to interrupt and resume later"
    echo
    ARGS=("${MAX_VIABLE_ARGS[@]}")
elif [ "$1" = "max" ]; then
    echo "🔄 Using MAXIMUM VIABLE configuration (explicit)..."
    echo "💡 This will generate ~10M+ findings in 6-8 hours"
    echo
    ARGS=("${MAX_VIABLE_ARGS[@]}")
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