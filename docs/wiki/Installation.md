# Installation Guide

This guide covers the recommended installation path for this repository.

## Build from Source

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake git python3 python3-venv python3-pip

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install cmake git python3 python3-devel
```

### Build Process

```bash
# Clone repository
git clone https://github.com/J-mazz/sys-scan-graph.git
cd sys-scan-graph

# Build core scanner
# Recommended: use a C++23-capable toolchain (Clang 17+/GCC 13+) and Ninja generator.
# Example (Linux, system Clang):
export CC=clang
export CXX=clang++
cmake -B build -S . -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=23 \
  -DCMAKE_CXX_STANDARD_REQUIRED=ON \
  -DCMAKE_CXX_EXTENSIONS=OFF
cmake --build build -j$(nproc)

# If you encounter module or C++23 errors, update your compiler toolchain to a newer release.
```

## Install the intelligence layer (Python, optional)

The intelligence layer is published as the `sys-scan-agent` Python package.

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install sys-scan-agent
```

Optional local-LLM dependencies:

```bash
pip install \
   langgraph langchain-core \
   torch transformers peft accelerate safetensors huggingface_hub
```

Optional external inference dependencies (LangChain API provider):

```bash
# IMPORTANT: You must provide your own provider credentials (not bundled with this project).
pip install langchain langchain-openai langchain-anthropic
```

### Run from Source

```bash
# Basic scan (core)
./build/sys-scan --canonical --output report.json

# With intelligence layer
source .venv/bin/activate
sys-scan-graph analyze --report report.json --out enriched_report.json
```

## Configuration

After installation, you may want to:

1. Review and tailor the configuration in `config.yaml` (the intelligence layer reads `./config.yaml` from the current working directory)
2. (Optional) Set up a baseline database for your environment (default: `agent_baseline.db` in the current directory; override via `AGENT_BASELINE_DB`)
3. (Optional) Configure local intelligence features (provider selection, offline flags, local model directory)
   - For external inference via LangChain, set `AGENT_LLM_PROVIDER=langchain-api` and **explicitly** opt in with `AGENT_EXTERNAL_LLM_ENABLED=1`.
   - Provide your own provider credentials (for example `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, depending on your provider).
4. Set up log aggregation and monitoring

## Troubleshooting

### Common Issues

**Import Errors**: If you encounter Python import errors, ensure you're using the correct Python environment and all dependencies are installed.

**Permission Errors**: The scanner may require elevated permissions to access system information. Run with `sudo` if needed.

**Local Intelligence Issues**: Ensure any required model files are available locally and your host has sufficient CPU/RAM/GPU resources.

### Getting Help

- Review the docs in `docs/wiki/` (start with the CLI guide and architecture overview)
- File an issue on [GitHub Issues](https://github.com/J-mazz/sys-scan-graph/issues)
- Ask questions in [GitHub Discussions](https://github.com/J-mazz/sys-scan-graph/discussions)

## Next Steps

Once installed, you can:

1. Run your first scan with `sys-scan --help`
2. Explore the intelligence layer with `sys-scan-graph --help`
3. Review the [CLI Guide](../CLI-Guide.md) for detailed usage
4. Set up automated scanning in your CI/CD pipeline
