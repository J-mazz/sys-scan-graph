#!/bin/bash
echo "=== Sys-Scan Diagnostic Tool ==="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "System: $(uname -a)"
echo ""

echo "=== 1. Build Directory Check ==="
if [ -d "build" ]; then
    echo "✓ Build directory exists"
    if [ -f "build/sys-scan" ]; then
        echo "✓ Executable exists"
        ls -la build/sys-scan
        echo "File size: $(stat -c%s build/sys-scan) bytes"
    else
        echo "✗ Executable NOT found in build/"
        ls -la build/ 2>/dev/null || echo "Build directory empty"
    fi
else
    echo "✗ Build directory does not exist"
fi
echo ""

echo "=== 2. Dependencies Check ==="
echo "Checking for required libraries..."
for lib in libseccomp libcap zlib liblzma; do
    echo -n "$lib: "
    if pkg-config --exists $lib 2>/dev/null; then
        echo "FOUND ($(pkg-config --modversion $lib))"
    else
        echo "MISSING"
    fi
done
echo ""

echo "=== 3. System Access Check ==="
echo "Checking /proc filesystem access..."
if [ -r "/proc/1/cmdline" ]; then
    echo "✓ /proc filesystem accessible"
else
    echo "✗ /proc filesystem NOT accessible"
fi

echo "Checking /sys filesystem access..."
if [ -r "/sys/kernel/version" ]; then
    echo "✓ /sys filesystem accessible"
else
    echo "✗ /sys filesystem NOT accessible"
fi
echo ""

echo "=== 4. CMake Configuration Check ==="
if [ -f "CMakeLists.txt" ]; then
    echo "✓ CMakeLists.txt exists"
    grep -n "BUILD_TESTS" CMakeLists.txt || echo "BUILD_TESTS setting not found"
else
    echo "✗ CMakeLists.txt not found"
fi

if [ -f "build/CMakeCache.txt" ]; then
    echo "✓ CMakeCache.txt exists"
    grep -i "build_tests" build/CMakeCache.txt || echo "BUILD_TESTS not in cache"
else
    echo "✗ CMakeCache.txt not found"
fi
echo ""

echo "=== 5. Test Run (if executable exists) ==="
if [ -x "build/sys-scan" ]; then
    echo "Running basic test..."
    timeout 10 ./build/sys-scan --version 2>&1 || echo "✗ Version check failed"
    echo ""
    echo "Running with timeout (first 5 lines)..."
    timeout 5 ./build/sys-scan 2>&1 | head -5 || echo "✗ Execution failed"
else
    echo "✗ Executable not found or not executable"
fi
echo ""

echo "=== Diagnostic Complete ==="
echo "If you see any MISSING or ✗ items above, those are likely causing the null output issue."