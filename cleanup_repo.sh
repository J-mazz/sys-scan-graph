#!/bin/bash
# Repository Cleanup Script for sys-scan-graph
# Removes redundant directories and improves repository hygiene

set -e

echo "🧹 Starting repository cleanup..."

# Function to safely remove directory if it exists
safe_remove() {
    if [ -d "$1" ]; then
        echo "Removing: $1"
        rm -rf "$1"
    else
        echo "Not found: $1"
    fi
}

# Function to safely remove file if it exists
safe_remove_file() {
    if [ -f "$1" ]; then
        echo "Removing: $1"
        rm -f "$1"
    else
        echo "Not found: $1"
    fi
}

# Remove build directories (these should be gitignored anyway)
safe_remove "build/"
safe_remove "build_noebpf/"
safe_remove "cmake-build-debug/"

# Remove empty/redundant testing directory
safe_remove "Testing/"

# Remove IDE-specific directories (optional - comment out if needed)
# safe_remove ".vscode/"
# safe_remove ".idea/"

# Remove virtual environment
safe_remove ".venv/"

# Remove build artifacts that might have been committed
safe_remove_file "build_build.log"

# Clean up any __pycache__ directories that might have been committed
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Remove any .pytest_cache directories
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

# Remove any temporary files
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.bak" -delete 2>/dev/null || true
find . -name "*.backup" -delete 2>/dev/null || true

# Remove any log files that might have been committed
find . -name "*.log" -delete 2>/dev/null || true

echo "✅ Repository cleanup completed!"
echo ""
echo "📊 Cleanup Summary:"
echo "   - Removed build directories"
echo "   - Removed temporary testing directory"
echo "   - Cleaned up Python cache files"
echo "   - Removed temporary and log files"
echo ""
echo "💡 Recommendations:"
echo "   - Consider removing IDE-specific directories (.vscode/, .idea/) if not needed"
echo "   - Review image files for redundancy (multiple diagram/badge files)"
echo "   - Ensure .gitignore patterns are comprehensive"