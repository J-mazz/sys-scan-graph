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
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
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
pip install 'sys-scan-agent[ai]'
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

1. Review the default configuration in `/etc/sys-scan-graph/config.yaml`
2. Set up baseline databases for your environment
3. Configure local intelligence features (optional)
4. Set up log aggregation and monitoring

## Troubleshooting

### Common Issues

**Import Errors**: If you encounter Python import errors, ensure you're using the correct Python environment and all dependencies are installed.

**Permission Errors**: The scanner may require elevated permissions to access system information. Run with `sudo` if needed.

**Local Intelligence Issues**: If you installed `sys-scan-agent[ai]`, ensure any required model files are available locally and your host has sufficient CPU/RAM/GPU resources.

### Getting Help

- Check the [troubleshooting section](https://github.com/J-mazz/sys-scan-graph/wiki/Troubleshooting) in the GitHub Wiki
- File an issue on [GitHub Issues](https://github.com/J-mazz/sys-scan-graph/issues)
- Ask questions in [GitHub Discussions](https://github.com/J-mazz/sys-scan-graph/discussions)

## Next Steps

Once installed, you can:

1. Run your first scan with `sys-scan --help`
2. Explore the intelligence layer with `sys-scan-graph --help`
3. Review the [CLI Guide](../CLI-Guide.md) for detailed usage
4. Set up automated scanning in your CI/CD pipeline
