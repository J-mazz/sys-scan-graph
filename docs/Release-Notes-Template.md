# Release Notes Template

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
