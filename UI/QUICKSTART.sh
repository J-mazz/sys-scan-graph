#!/bin/bash
set -e

echo "=== sys-scan-UI Quick Start Build Script ==="
echo

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Must run from sys-scan-UI root directory"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."
for pkg in cmake pkg-config libgtk-4-dev libjson-glib-1.0-dev; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        echo "Missing: $pkg"
        echo "Install with: sudo apt-get install $pkg"
        exit 1
    fi
done
echo "All dependencies found!"
echo

# Build
echo "Building sys-scan-UI..."
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
echo
echo "Build complete!"
echo

# Instructions
echo "=== Next Steps ==="
echo
echo "1. Install the application:"
echo "   sudo make install"
echo
echo "2. Or run directly from build directory:"
echo "   ./sys-scan-ui"
echo
echo "3. To build a Debian package:"
echo "   cd .."
echo "   dpkg-buildpackage -us -uc -b"
echo
echo "4. Generate a test report:"
echo "   sys-scan --canonical --output /tmp/report.json"
echo "   sys-scan-graph analyze --report /tmp/report.json --out /tmp/enriched.json"
echo
echo "5. Open the report in the UI"
echo

