# License Overview

This page provides a comprehensive overview of the licensing structure for sys-scan-graph and its components.

# License Overview

This page provides a comprehensive overview of the licensing for sys-scan-graph.

## Repository Licensing Structure

sys-scan-graph is licensed under the Apache License 2.0.

```
sys-scan-graph/
├── Core Scanner (C++20) - Apache License 2.0
├── Intelligence Layer (agent/) - Apache License 2.0
├── Documentation (docs/) - Creative Commons Attribution 4.0
└── Build Scripts & Tools - Apache License 2.0
```

## Apache License 2.0

The entire sys-scan-graph project is licensed under the Apache License, Version 2.0:

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

- **Technology**: High-performance C++ scanning engine
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

This project is based on the original sys-scan project:

- **Original Author**: J-mazz
- **Original License**: MIT License
- **Source**: https://github.com/J-mazz/sys-scan
- **Modifications**: Added intelligence layer, advanced analytics, LangGraph orchestration

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

Contact: Joseph@Mazzlabs.works

## License Texts

### Apache License 2.0

See [`LICENSE`](LICENSE) in the repository root.

### Documentation License

[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/legalcode)

---

*This license overview is for informational purposes. For legal advice, consult qualified legal counsel.*

## Core Scanner Licensing

### Origin and Basis

The core scanner is based on the original open-source [`J-mazz/sys-scan`](https://github.com/J-mazz/sys-scan) repository, which was released under the MIT License.

### Current Status

- **License**: MIT License
- **Copyright**: Joseph Mazzini
- **Modifications**: Includes enhancements and modifications while maintaining MIT compatibility
- **Redistribution**: Permitted under MIT terms

### Key Components

- **Scanner Engine**: High-performance C++ scanning framework
- **Security Modules**: Process, network, kernel, and file system scanners
- **Output Formats**: JSON, NDJSON, SARIF, HTML generation
- **Build System**: CMake-based compilation and deployment

## Intelligence Layer Licensing

### Business Source License 1.1

The Intelligence Layer (`agent/` directory) is licensed under the Business Source License (BSL) 1.1:

```markdown
Business Source License 1.1

Parameters
- Licensor: Joseph Mazzini
- Licensed Work: sys-scan-graph Intelligence Layer (agent/)
- Additional Use Grant: Non-production evaluation, academic research, contributions
- Change Date: 2028-01-01
- Change License: Apache License, Version 2.0
```

### Permitted Uses (No Commercial License Required)

✅ **Allowed Uses:**
- Internal evaluation and testing
- Academic research and educational purposes
- Personal development and experimentation
- Contributing via pull requests
- Non-production internal operations

### Commercial License Required

❌ **Require Commercial License:**
- Production deployment
- SaaS/hosted offerings
- Commercial redistribution
- Any commercial exploitation

### License Change Timeline

```
2024 ───────────────────── 2028 ───────────────────── ∞
    │                        │                        │
    │     BSL 1.1          Change Date              Apache 2.0
    │   (Proprietary)      (Automatic)            (Open Source)
    │                        │                        │
    └─ Commercial license ───┼────────────────────────┘
       required                                    Free use
```

## Documentation Licensing

### Creative Commons Attribution 4.0

All documentation in the `docs/` directory is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/):

- **Allows**: Commercial and non-commercial use, distribution, modification
- **Requires**: Attribution to Joseph Mazzini
- **Permits**: Use in tutorials, books, and other works

### Documentation Scope

- Wiki pages (`docs/wiki/`)
- README and guides
- Architecture diagrams
- API documentation
- Example code in documentation

## Build Tools and Scripts

### MIT License

Build scripts, configuration files, and development tools use the MIT License:

- **CMakeLists.txt**: Build system configuration
- **Scripts**: Automation and utility scripts
- **Test Files**: Unit and integration tests
- **Configuration**: YAML and JSON config files

## Third-Party Dependencies

### Core Scanner Dependencies

The core scanner has minimal dependencies:

- **C++ Standard Library**: System-provided
- **CMake**: Build system (MIT)
- **Compiler**: GCC/Clang (various open-source licenses)

### Intelligence Layer Dependencies

Python dependencies include:

- **LangGraph**: Apache 2.0
- **LangChain**: MIT
- **OpenAI Python Client**: MIT
- **SQLite**: Public Domain
- **PyYAML**: MIT
- **Requests**: Apache 2.0

## Commercial Licensing

### Obtaining a Commercial License

For commercial use of the Intelligence Layer:

**Contact**: Joseph@Mazzlabs.works
**Subject**: Commercial License Inquiry - sys-scan-graph

### License Terms

Commercial licenses typically include:

- **Perpetual use** of the Intelligence Layer
- **Production deployment** rights
- **Support and updates** for 1-3 years
- **Redistribution rights** (optional)
- **Custom terms** available

### Pricing Structure

Pricing is based on:

- **Usage scale** (number of deployments, users)
- **Support level** required
- **Redistribution** needs
- **Custom features** requested

## Academic and Research Use

### Academic License

Special terms available for:

- **Educational institutions**
- **Research projects**
- **Non-profit organizations**
- **Open-source projects**

### Requirements

- **Documentation** of intended use
- **Attribution** in publications
- **Non-commercial** restriction

## Contributing and Licensing

### Contributor License Agreement

Contributors agree to license their contributions under the same terms as the component they're contributing to:

- **Core Scanner**: MIT License
- **Intelligence Layer**: BSL 1.1 terms
- **Documentation**: CC BY 4.0
- **Tools/Scripts**: MIT

### Pull Request Licensing

When submitting pull requests:

1. **Core changes**: Licensed under MIT
2. **Intelligence Layer**: Licensed under BSL 1.1
3. **Documentation**: Licensed under CC BY 4.0
4. **Tools**: Licensed under MIT

## Compliance and Legal

### Export Controls

- **ECCN**: Not applicable (security scanning tool)
- **Country Restrictions**: None
- **Encryption**: No encryption functionality

### Data Privacy

- **User Data**: Tool scans system metadata only
- **PII Handling**: No collection of personal information
- **GDPR**: Not applicable (no user data processing)

### Security Considerations

- **Vulnerability Disclosure**: Follow responsible disclosure
- **Security Updates**: Provided under support agreements
- **Hardening**: Ongoing security improvements

## Frequently Asked Questions

### Can I use sys-scan-graph for free?

**Yes, for permitted uses:**
- Personal projects (Core Scanner: MIT, Intelligence Layer: BSL permitted uses)
- Internal evaluation (Core Scanner: MIT, Intelligence Layer: BSL permitted uses)
- Academic research (both components)
- Non-production environments (both components)

**Commercial license required for Intelligence Layer:**
- Production deployment of Intelligence Layer
- SaaS/hosted offerings using Intelligence Layer
- Commercial redistribution of Intelligence Layer

**Core Scanner is always free under MIT for all uses.**

### When does the BSL license change?

The BSL 1.1 license automatically converts to Apache License 2.0 on **January 1, 2028**.

### Can I contribute code?

Yes! Contributions are welcome. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

### What if I have licensing questions?

Contact: Joseph@Mazzlabs.works

## License Texts

### Core Scanner License

See [`LICENSE`](LICENSE) in the repository root.

### Intelligence Layer License

See [`agent/LICENSE`](agent/LICENSE).

### Documentation License

[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/legalcode)

---

*This license overview is for informational purposes. For legal advice, consult qualified legal counsel.*