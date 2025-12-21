#!/bin/bash
set -e

echo "[1/3] Building Python Environment..."
pip install -e .

echo "[2/3] Building C++ UI (Qt6/Vulkan)..."
# Ensure we are in the ui subdirectory
mkdir -p build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DGGML_VULKAN=ON -DCMAKE_CXX_COMPILER=clang++ ..
cmake --build build --parallel

echo "[3/3] Packaging..."
mkdir -p dist/bin
cp build/sys-scan-ui dist/bin/ || true
echo "Build Complete. Binary located in dist/bin/sys-scan-ui (if build succeeded)"
