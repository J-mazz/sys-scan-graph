# sys-scan-graph Documentation Index

![sys-scan-graph Badge](../../assets/sys-scan-graph_badge.jpg)

Welcome to the comprehensive documentation for sys-scan-graph. This index provides quick access to detailed documentation pages covering all aspects of the project.

![sys-scan-graph Primary Logo](../../assets/sys-scan-graph_primary_logo.png)

## Quick Links

- **[GitHub Repository](https://github.com/J-mazz/sys-scan-graph)** - Main project repository
- **[GitHub Wiki](https://github.com/J-mazz/sys-scan-graph/wiki)** - Optional external wiki (may not mirror the in-repo docs)
- **[Issues](https://github.com/J-mazz/sys-scan-graph/issues)** - Report bugs and request features
- **[Discussions](https://github.com/J-mazz/sys-scan-graph/discussions)** - Community discussions and Q&A

## Core Documentation

### Architecture & Design

- **[Architecture Overview](Architecture.md)** - High-level system architecture, core vs intelligence layer responsibilities
- **[Architecture (Technical Details)](Architecture-Technical-Details.md)** - Data flow, invariants, and implementation notes
- **[Core Scanners](Core-Scanners.md)** - Scanner implementations, signals, output formats, and schemas
- **[Intelligence Layer](Intelligence-Layer.md)** - Pipeline stages, LangGraph orchestration, LLM providers, data governance

### Components & Features

- **[Rules Engine](Rules-Engine.md)** - Lightweight YAML/JSON correlation rules and CLI lint/dry-run helpers
- **[Risk Model](Risk-Model.md)** - Risk and probability modeling, weights, calibration, CLI helpers

### Operations & Performance

- **[CLI Guide](CLI-Guide.md)** - Command-line interface for core and agent functionality
- **[CI Integration](CI-and-SARIF-Integration.md)** - Running scans in CI pipelines and publishing JSON artifacts

### Development & Extensibility

- **[Extensibility](Extensibility.md)** - Supported extension points (rules, scanners, providers)

More deep-dive pages will be added over time. This index only links to documents that are currently present in `docs/wiki/`.

## Licensing & Legal

- **[License Overview](License-Overview.md)** - Complete licensing structure and terms
- **[Contributing Guide](../../CONTRIBUTING.md)** - How to contribute to the project
- **[Code of Conduct](../../CODE_OF_CONDUCT.md)** - Community standards and guidelines
- **[Security Policy](../../SECURITY.md)** - Security disclosure and vulnerability reporting

## Quick Start

If you're new to sys-scan-graph, start here:

1. **[Installation Guide](Installation.md)** - Complete installation instructions for all platforms
2. **[README](../../README.md)** - Project overview and basic setup
3. **[CLI Guide](CLI-Guide.md)** - Essential command-line usage
4. **[Core Scanners](Core-Scanners.md)** - Understanding scanner capabilities

## Release Management

- **[Release Notes Template](../Release-Notes-Template.md)** - Template for creating release notes
- **[Installation Guide](Installation.md)** - Installation instructions for all platforms

## Community Resources

**GitHub Wiki**: <https://github.com/J-mazz/sys-scan-graph/wiki>

If you maintain an external wiki, consider using it for high-churn notes and linking back to the authoritative docs in `docs/wiki/`.

- **Discussions**: <https://github.com/J-mazz/sys-scan-graph/discussions>
  - Ask questions
  - Share use cases
  - Discuss features and roadmap

## Support

- **Issues**: <https://github.com/J-mazz/sys-scan-graph/issues>
  - Bug reports
  - Feature requests
  - Technical support

- **Security**: See [Security Policy](../../SECURITY.md) for vulnerability disclosure

## License

This documentation is licensed under the Apache License 2.0 (see [`LICENSE`](../../LICENSE)).

---

![Mazzlabs Logo](../../assets/Mazzlabs.png)

Last updated: December 2025
