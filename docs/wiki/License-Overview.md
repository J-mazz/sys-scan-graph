# License Overview

This page summarizes how licensing is handled in this repository.
It is intended to be **accurate and repo-aligned**, not legal advice.

## Summary

- **Code (core + agent):** Apache License 2.0 (see `../../LICENSE`)
- **Documentation (`docs/`):** Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Brand assets (`assets/`):** All rights reserved (see `../../NOTICE`)

If you are redistributing or embedding sys-scan-graph, also review:

- `../../NOTICE` (attribution and upstream provenance)
- `../../THIRD_PARTY_NOTICES` (third-party license attributions)

## Apache License 2.0 (code)

Unless a specific file states otherwise, the **source code** in this repository is licensed under the Apache License, Version 2.0:

```markdown
Apache License

Version 2.0, January 2004

http://www.apache.org/licenses/

[Full license text in LICENSE file]
```

### Key Features

- **Permissive License**: Allows commercial and non-commercial use, distribution, modification
- **Patent Grant**: Includes patent license for contributors
- **Attribution Required**: Must include copyright notice and license text
- **Compatible**: Compatible with GPL v3 and many other open-source licenses

## Project Components

### Core Scanner

- **Technology**: High-performance C++ scanning engine (C++20 modules, C++23 features/toolchain)
- **License**: Apache License 2.0
- **Copyright**: Joseph Mazzini

### Intelligence Layer

- **Technology**: Python-based analysis and enrichment with LangGraph
- **License**: Apache License 2.0
- **Copyright**: Joseph Mazzini

### Documentation

- **Content**: Wiki pages, guides, architecture docs
- **License**: Creative Commons Attribution 4.0 International
- **Copyright**: Joseph Mazzini

### Build Tools and Scripts

- **Content**: CMake files, build scripts, test files
- **License**: Apache License 2.0
- **Copyright**: Joseph Mazzini

## Third-Party Dependencies

### Core Scanner Dependencies

- **OpenSSL**: Apache License 2.0 / OpenSSL License
- **CMake**: BSD-3-Clause
- **GCC/Clang**: GPL/LGPL

### Intelligence Layer Dependencies

- **Python**: Python Software Foundation License
- **LangGraph**: MIT License
- **LangChain**: MIT License
- **SQLite**: Public Domain
- **PyTorch**: BSD-3-Clause
- **Transformers**: Apache License 2.0

## Upstream Attribution

This project is based on and includes modifications to the original sys-scan project:

- **Original Author**: J-mazz
- **Original License**: MIT License (upstream project)
- **Source**: <https://github.com/J-mazz/sys-scan>

This repository is distributed under **Apache 2.0**; upstream attribution and third-party license notices are tracked in `../../NOTICE` and `../../THIRD_PARTY_NOTICES`.

## Contributing

Contributions are welcome under the Apache License 2.0. By submitting a contribution, you agree to license it under the same terms.

### Contributor License Agreement

Contributors grant a license to Joseph Mazzini under the Apache License 2.0 for inclusion in the project.

## Commercial Use

The Apache License 2.0 permits commercial use without restrictions. No separate commercial license is required.

## Academic and Research Use

Academic and research use is permitted under the Apache License 2.0.

## Compliance and Legal

### Export Controls

- **ECCN**: Not applicable
- **Country Restrictions**: None
- **Encryption**: No encryption functionality

### Data Privacy

- **User Data**: Tool scans system metadata only
- **PII Handling**: No collection of personal information
- **GDPR**: Not applicable

## Frequently Asked Questions

### Can I use sys-scan-graph for commercial purposes?

Yes, the Apache License 2.0 allows commercial use, distribution, and modification.

### Can I modify and redistribute sys-scan-graph?

Yes, under the terms of the Apache License 2.0.

### Do I need to include the license text?

Yes, you must include the Apache License 2.0 text with distributions.

### Can I contribute code?

Yes! Contributions are welcome. See CONTRIBUTING.md for guidelines.

### What if I have licensing questions?

Contact: <mailto:Joseph@Mazzlabs.works>

## License Texts

### Apache License 2.0

See `../../LICENSE`.

### Documentation License

[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/legalcode)

---

*This license overview is for informational purposes. For legal advice, consult qualified legal counsel.*
