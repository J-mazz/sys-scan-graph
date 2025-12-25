# Release Notes Template

## 📦 Packaging Changes

* **Version:** v7.0.0
* **Architecture:** Split-Distribution (Code on PyPI, Models via System Package)
* **PyPI Artifact:** `sys-scan-agent` (Pure Python, <1MB)

### ⚠️ Upgrading from v5.x
This release **removes** bundled model binaries to comply with PyPI limits. If you rely on the agent for AI analysis, you must ensure the model weights are present in your system paths:

* **Debian/Ubuntu:** `apt install sys-scan-models` (if available)
* **Manual:** Ensure `qwen3_analyst-q4_k_m.gguf` is in `/usr/share/sys-scan-agent/models/`

## Highlights

- Short bullets of key features, fixes, and performance changes.

## Changes

- Added: ...
- Changed: ...
- Fixed: ...
- Security: ...

## Determinism & Reproducibility

- Canonical JSON (stable ordering): `./sys-scan --canonical --output report.json`
- Hash: `sha256sum report.json` (stable under canonical mode on the same host/input)

## Assets

- sys-scan-graph-`<version>`-linux-x86_64.tar.gz
- sha256sums.txt [+ .asc signature if provided]

## Changelog

- Compare: <https://github.com/J-mazz/sys-scan-graph/compare/`prev`...`this`>
- See [CHANGELOG](./CHANGELOG.md) for structured changes and migration notes.

## Security

- Scanner is read-only; no system modifications.
- LLM provider is opt-in; redaction and governance hooks applied when enabled.
- See [SECURITY](./SECURITY.md) for disclosure and operational guidance.
