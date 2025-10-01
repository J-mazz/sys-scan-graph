# Architecture Overview

**sys-scan-graph** combines a high-performance C++20 scanning engine with an AI-powered intelligence layer to deliver comprehensive Linux system security analysis. The architecture emphasizes determinism, type safety, and zero-trust principles.

---

## System Design Philosophy

### Core Principles

- **Performance First**: C++20 core scanner optimized for minimal system impact
- **Type Safety**: Strict type-safe enums and modern dependency injection patterns  
- **Zero-Trust AI**: Embedded fine-tuned Mistral-7B LLM requires no external API calls
- **Deterministic Output**: RFC 8785 canonical JSON ensures reproducible results
- **Comprehensive Coverage**: 16 specialized scanners across all security domains

### Two-Layer Architecture

```
┌─────────────────────────────────────────┐
│   C++20 Core Scanner (Open-Core)        │
│   • 16-17 specialized scanners          │
│   • Type-safe severity system           │
│   • Thread-safe parallel execution      │
│   • RFC 8785 canonical JSON output      │
└──────────────┬──────────────────────────┘
               ↓ report.json
┌──────────────────────────────────────────┐
│   Python Intelligence Layer              │
│   • Embedded Mistral-7B LLM (168MB)      │
│   • LangGraph workflow orchestration     │
│   • MITRE ATT&CK correlation             │
│   • Baseline anomaly detection           │
└──────────────┬──────────────────────────┘
               ↓ enriched_report.json
```

---

## Core Scanner Architecture

The C++20 scanning engine performs fast, deterministic security enumeration across 16 specialized domains:

**Security Domains Covered:**

- Process enumeration with behavioral analysis
- Network socket & listener detection
- Kernel hardening parameters
- Loaded kernel modules
- SUID/SGID binary tracking
- Indicators of Compromise (IOC)
- MAC policy status (SELinux/AppArmor)
- Filesystem security (world-writable, mount options)
- Container runtime awareness
- Systemd service analysis
- Audit daemon configuration
- File integrity monitoring
- eBPF execution tracing
- PCI DSS 4.0 compliance checks

**Key Features:**

- **Dependency Injection**: `ScanContext` pattern eliminates global state
- **Thread Safety**: Mutex-protected `Report` class enables parallel scanner execution
- **Type-Safe Severity**: Enum-based system (Info/Low/Medium/High/Critical/Error) with numeric risk scores
- **Rule Engine**: Multi-condition matching with regex support and MITRE technique tagging
- **Deterministic Ordering**: Fixed scanner registration order ensures consistent output diffs

---

## Intelligence Layer Architecture

The Python layer transforms raw scan data into actionable security intelligence using an embedded AI model trained on 2.5M security findings.

**Zero-Trust AI Implementation:**

- **Local LLM**: Mistral-7B-Instruct-v0.3 with LoRA adapters (168MB)
- **Training Dataset**: 2.5M unique security findings with multi-stage validation
- **No External APIs**: Complete offline operation ensures data sovereignty
- **Deterministic Inference**: Temperature=0.1 for reproducible analysis

**LangGraph Workflow Orchestration:**

Two operational modes provide flexibility for different use cases:

1. **Enhanced Workflow** (Full AI Analysis)
   - **enrich**: Package origins, CVE correlation, severity adjustments
   - **correlate**: Cross-finding patterns, attack path construction
   - **risk_analyzer**: Weighted scoring (rarity × severity × MITRE chaining)
   - **compliance_checker**: PCI DSS 4.0, HIPAA, NIST CSF 2.0 mapping
   - **summarize**: Executive summary with prioritized recommendations

2. **Baseline Workflow** (Fast Statistical Analysis)
   - Rapid analysis without LLM inference
   - Ideal for resource-constrained environments or benchmarking

**Baseline Intelligence:**

- **SQLite Database**: Historical frequency distributions for rarity scoring
- **Process Embeddings**: 32-dimensional behavioral feature vectors
- **DBSCAN Clustering**: Groups similar processes for anomaly detection
- **MITRE Correlation**: Maps findings to ATT&CK techniques via knowledge base

---

## Data Pipeline & Quality Assurance

**Training Data Integrity:**

The 2.5M training dataset undergoes rigorous validation to ensure high-quality, realistic security scenarios:

- **8 Specialized Producers**: Generate findings for each scanner type
- **3 Correlation Producers**: Create realistic cross-finding relationships
- **Multi-Stage Verification**: Schema compliance, coherence checks, realism constraints, diversity validation
- **MLOps Pipeline**: Complete infrastructure at [sys-scan-agent-MLops](https://github.com/Mazzlabs/sys-scan-agent-MLops)

---

## Output Formats & Integration

**Multiple Output Modes:**

- **JSON**: Default canonical format (RFC 8785 JCS)
- **NDJSON**: Streaming format for large datasets
- **SARIF**: Static Analysis Results Interchange Format for CI/CD integration
- **HTML**: Human-readable reports with visualizations

**Security Features:**

- GPG signing support for report integrity
- PII redaction capabilities
- Configurable severity thresholds
- Exit code mapping for CI/CD pipelines

---

## Testing & Quality

**Comprehensive Test Coverage:**

- **919 Total Test Cases** (698 C++, 221 Python)
- **C++ Suite**: Google Test framework with unit, integration, and compliance tests
- **Python Suite**: pytest with asyncio for workflow validation
- **Performance Benchmarks**: Continuous monitoring of scanner execution times
- **Canonical Golden Tests**: Bit-for-bit reproducibility validation

---

## Extensibility & Roadmap

**Current Extension Points:**

- New scanners via `Scanner` interface
- Custom rule packs (YAML/JSON)
- Additional baseline metrics
- Extended MITRE ATT&CK mappings

**Future Architecture Goals:**

- Native module decompression (eliminate external `xz`/`gzip` calls)
- Structured warning channel separate from findings
- Formal provenance & SBOM correlation
- Enhanced iterative refinement capabilities

---

## Documentation Deep Dives

For detailed technical documentation, see the wiki pages:

- **[Core Scanners](docs/wiki/Core-Scanners.md)**: Individual scanner implementations and detection logic
- **[Intelligence Layer](docs/wiki/Intelligence-Layer.md)**: LangGraph workflows, embedding generation, and LLM architecture
- **[Architecture Details](docs/wiki/Architecture.md)**: Type system, data flow diagrams, and implementation specifics
- **[Rules Engine](docs/wiki/Rules-Engine.md)**: Rule syntax, condition matching, and MITRE mapping
- **[Risk Model](docs/wiki/Risk-Model.md)**: Risk scoring algorithms and baseline calibration

---

## Contact

For design proposals, open an issue tagged `design`. For security disclosures, follow `SECURITY.md`.
