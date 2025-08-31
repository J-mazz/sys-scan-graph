# **sys-scan-graph: Unified Intelligence Core Roadmap**

## **Vision: LangGraph-Powered Intelligence Platform**

The future of sys-scan-graph is not a C++ scanner with a Python script attached; it is a single, cohesive product where the **LangGraph-powered agent is the central intelligence core.** This represents a fundamental architectural shift: we are moving from a linear data-processing pipeline to a dynamic, stateful, and conversational analysis engine.

**Key Principles:**

- **LangGraph as Default:** The LangGraph workflow becomes the sole, non-optional execution path
- **Security-First:** Multi-layered security architecture with guardrails, validation, and sanitization
- **Unified API:** Both CLI and GUI become thin clients to the central agent
- **Architectural Consolidation:** Legacy pipeline deprecated, LangGraph becomes canonical implementation

---

## **Phase 0: Architectural Consolidation (Foundation Sprint)**

**Goal:** Establish LangGraph as the central intelligence core and consolidate the architecture around this new paradigm.

### **\[P0\] Make LangGraph the Default Execution Path**

**Status:** 🔴 CRITICAL PRIORITY - Architectural foundation

- **Issue:** Mixed execution paths create confusion and maintenance burden
- **Actions:**
  - **File:** agent/cli.py - Remove `--graph` flag, make LangGraph the sole execution path
  - **File:** agent/graph.py - Modify build_workflow to default to "enhanced" mode
  - **File:** Move agent/pipeline.py to agent/legacy/pipeline.py
  - **Docs:** Update README.md and ARCHITECTURE.md to reflect LangGraph as canonical implementation
- **Impact:** Eliminates architectural ambiguity, establishes single source of truth

### **\[P0\] Implement Multi-Layered Security Architecture**

**Status:** 🔴 CRITICAL PRIORITY - Security foundation

- **Issue:** Powerful conversational agent requires comprehensive security hardening
- **Actions:**
  - **Create GuardrailNode:** New LangGraph node for prompt sanitization and intent classification
  - **Tool Access Control:** Implement Pydantic validation for all agent/tools.py functions
  - **Output Sanitization:** Add strict parse-then-validate for all LLM-generated structured data
  - **Principle of Least Privilege:** Narrowly scope all tool functions
- **Impact:** Zero-trust security model protecting against prompt injection and privilege escalation

### **\[P0\] Develop Unified API Layer**

**Status:** 🔴 CRITICAL PRIORITY - Interface foundation

- **Issue:** Need single gateway for both CLI and GUI to access intelligence core
- **Actions:**
  - **Create API Module:** New agent/api.py for managing LangGraph agent lifecycles
  - **WebSocket Support:** Implement persistent connections for GUI, single-shot for CLI
  - **State Management:** Handle stateful agent instances across multiple client connections
  - **Protocol Definition:** Establish clear message format for agent communication
- **Impact:** Enables both CLI and GUI as thin clients to the same intelligence core

---

## **Phase 1: Security Hardening & Core Stabilization**

**Goal:** Implement comprehensive security measures and eliminate critical bugs that could compromise the intelligence core.

### **Fix the EbpfScanner ODR Violation**

**Status:** 🔴 HIGH PRIORITY - Build-breaking bug

- **Issue:** One Definition Rule (ODR) violation prevents core eBPF feature from being used
- **Action Required:**
  - EbpfScanner.cpp must `#include "EbpfScanner.h"`
  - Remove duplicate inline class redefinition in .cpp file
  - Provide definitions for all methods declared in header
- **Verification:** Project builds cleanly with WITH_EBPF=ON on GCC and Clang, eBPF scanner produces findings in integration test

### **Fix Hardcoded bpftool Path in CMake**

**Status:** 🔴 HIGH PRIORITY - Build portability issue

- **Issue:** Hardcoded bpftool path prevents portable builds across different systems
- **Actions:**
  - **File:** CMakeLists.txt
  - **Remove:** `set(BPFTOOL "/usr/lib/linux-tools-6.8.0-79/bpftool")`
  - **Replace with:**

    ```cmake
    find_program(BPFTOOL_EXECUTABLE bpftool)
    if(NOT BPFTOOL_EXECUTABLE)
        if(WITH_EBPF_STRICT)
            message(FATAL_ERROR "bpftool not found in PATH, required for WITH_EBPF_STRICT")
        else()
            message(WARNING "bpftool not found in PATH, eBPF scanners will be disabled")
            set(WITH_EBPF OFF)
        endif()
    endif()
    ```

  - **Update usage:** Replace all `${BPFTOOL}` references with `${BPFTOOL_EXECUTABLE}`

### **Modernize Library Finding in CMake**

**Status:** 🟡 MEDIUM PRIORITY - Build system modernization

- **Issue:** Manual find_library calls are less portable than package-based approach
- **Actions:**
  - **File:** CMakeLists.txt
  - **Replace libseccomp block:**

    ```cmake
    find_package(Libseccomp QUIET)
    if(Libseccomp_FOUND)
        target_link_libraries(sys_scan_core PUBLIC Libseccomp::seccomp)
        target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_SECCOMP=1)
    endif()
    ```

  - **Apply similar pattern to libcap**
  - **Benefits:** Better portability across Linux distributions

### **Unify the Risk Model**

**Status:** 🟡 MEDIUM PRIORITY - Architectural consistency

- **Issue:** Conceptual clash between C++ base_severity_score and Python agent's holistic risk_score
- **Decision:** C++ provides ONLY base_severity_score derived from finding severity; Python agent calculates final risk_score
- **Actions:**
  - **C++:** Rename `risk_score` field to `base_severity_score` in Finding struct
  - **Python (models.py):** Update Pydantic Finding model to have `base_severity_score: int` as required field
  - **Python (models.py):** Initialize `risk_score: int` from `base_severity_score` using Pydantic model_validator
  - **Python (pipeline.py):** Remove manual logic copying base_severity_score to risk_score
  - **Docs:** Update model documentation strings to explain the flow

### **Separate Operational Errors from Security Findings**

**Status:** 🟡 MEDIUM PRIORITY - Alert quality issue

- **Issue:** Scanner health issues conflated with security signals, creating alert fatigue
- **Actions:**
  - **C++:** In Report.cpp, hardcode base_severity_score to 0 for findings with operational_error=true
  - **Python:** Filter out operational_error=true findings from risk calculation in pipeline.py and risk.py
  - **Docs:** Update ARCHITECTURE.md and README.md to clarify operational errors are excluded from risk scoring

---

## **Phase 2: Intelligence Core Enhancement**

**Goal:** Enhance the LangGraph intelligence core with advanced capabilities, security features, and operational excellence.

### **Activate Full LangGraph Workflow**

**Status:** 🟡 MEDIUM PRIORITY - Core functionality

- **Issue:** Current implementation uses scaffold/optional nodes instead of full enhanced workflow
- **Actions:**
  - Wire in full operational tail: risk_analyzer, compliance_checker, error_handler, cache_manager, metrics_collector
  - Enable advanced_router for dynamic analysis paths
  - Implement "human-in-the-loop" feedback node for high-impact actions
  - Ensure all nodes are non-optional in the default workflow
- **Impact:** Every analysis run benefits from complete suite of analytical and operational capabilities

### **Implement Advanced Security Guardrails**

**Status:** 🟡 MEDIUM PRIORITY - Security enhancement

- **Issue:** Need comprehensive protection against prompt injection and malicious inputs
- **Actions:**
  - **GuardrailNode Implementation:** Pattern matching and heuristics for meta-instruction detection
  - **Intent Classification:** Micro-LLM for benign vs malicious query classification
  - **Content Filtering:** Strip known malicious payloads and signatures
  - **Tool Validation:** Strict Pydantic models for all tool function arguments
- **Impact:** Zero-trust protection at every input boundary

### **Enhance Agent Tool Security**

**Status:** 🟡 MEDIUM PRIORITY - Security enhancement

- **Issue:** Agent tools represent potential privilege escalation vectors
- **Actions:**
  - **Pydantic Validation:** Every tool function gets strict input validation models
  - **Scoped Access:** Tools have minimal necessary privileges (no filesystem access for query tools)
  - **Role-Based Access:** Future support for different user permission levels
  - **Audit Logging:** Track all tool usage for security monitoring
- **Impact:** Prevents malicious tool execution and privilege escalation

### **Implement LLM Output Sanitization**

**Status:** 🟡 MEDIUM PRIORITY - Security enhancement

- **Issue:** LLM outputs must be treated as untrusted until validated
- **Actions:**
  - **Parse-Then-Validate:** Strict JSON parsing followed by Pydantic model validation
  - **Content Sanitization:** Strip harmful HTML/script tags from natural language outputs
  - **Structured Data Validation:** All structured outputs validated against schemas
  - **Fallback Handling:** Graceful degradation when validation fails
- **Impact:** Prevents injection attacks and malformed data propagation

---

## **Phase 3: Interface Development & User Experience**

**Goal:** Develop unified interfaces and enhance user experience while maintaining security and intelligence core integrity.

### **Refactor C++ CLI to Use Subcommands**

**Status:** � MEDIUM PRIORITY - User experience improvement

- **Issue:** Monolithic CLI interface is confusing and hard to extend
- **Actions:**
  - **Files:** core/ArgumentParser.cpp and main.cpp
  - **main.cpp:** Check argv[1] for command (e.g., "run", "process", "network")
  - **main.cpp:** Pass remaining args (argc-1, argv+1) to specialized parsing functions
  - **ArgumentParser:** Create parse_run_options, parse_process_options, etc.
  - **ArgumentParser:** Update print_help to show new subcommand structure
  - **Benefits:** More intuitive interface and better extensibility

### **Establish a Structured Warning System**

**Status:** � MEDIUM PRIORITY - Monitoring capability

- **Issue:** Warnings emitted as simple strings, not machine-readable
- **Actions:**
  - **C++ (Report.h):** Change add_warning signature to accept WarnCode enum and detail string
  - **C++ (Report.h):** Update warnings_ member to store vector of Warning struct (scanner, code, detail)
  - **C++ (JSONWriter.cpp):** Modify collection_warnings serialization to build proper JSON objects
  - **Python:** Update load_report function to parse new structure
  - **Python:** Enhance cli.py to display warnings in color-coded table

### **Make HTML Report Interactive**

**Status:** 🟡 MEDIUM PRIORITY - User experience enhancement

- **Issue:** Static HTML reports lack interactivity for large datasets
- **Actions:**
  - **File:** agent/report_html.py
  - **Add client-side JavaScript:**
    - `filterFindings()` function for text search
    - `filterBySeverity(sev)` function for severity filtering
  - **Add HTML elements:**
    - Search input: `<input type="text" onkeyup="filterFindings(this.value)" placeholder="Search findings...">`
    - Severity buttons: `<button onclick="filterBySeverity('high')">High</button>`
  - **Benefits:** Improved usability for large security reports

### **Harden the C++ Rule Engine**

**Status:** � MEDIUM PRIORITY - Robustness issue

- **Issue:** Unhandled exceptions in rule parsing could crash entire scanner
- **Actions:**
  - **C++:** Enhance try/catch in RuleEngine.cpp for std::regex compilation
  - **C++:** Log rule ID, filename, and specific regex pattern on failure
  - **Docs:** Document MAX_REGEX_LENGTH and MAX_CONDITIONS_PER_RULE constants in README.md
  - **Docs:** Add regex best practices and performance implications

---

## **Phase 4: Advanced Features & Ecosystem**

**Goal:** Implement cutting-edge features and build out the ecosystem around the intelligence core.

### **Refactor ModuleScanner**

**Status:** 🟡 MEDIUM PRIORITY - Code maintainability

- **Issue:** Monolithic ModuleScanner function handles decompression, signature checks, and heuristic analysis
- **Actions:**
  - Break out responsibilities into helper classes: ModuleDecompressor, ElfParser, SignatureVerifier
  - Create namespace within src/scanners/ for these components
  - Make ModuleScanner a coordinator using these components
  - Enables easier testing, debugging, and future parallelization

### **Native Decompression in ModuleScanner**

**Status:** 🟡 MEDIUM PRIORITY - Security and performance

- **Actions:**
  - Leverage SYS_SCAN_HAVE_LZMA and SYS_SCAN_HAVE_ZLIB flags
  - Integrate liblzma and zlib directly into ModuleScanner for .ko.xz and .ko.gz files
  - Remove shell-injection risks and improve performance over external processes

### **Expand Compliance & Reporting**

**Status:** 🟢 LOW PRIORITY - Enterprise value-add

- **Actions:**
  - Build out compliance control knowledge base mapping to CIS Benchmarks and SOC 2
  - Enhance report_html.py with dynamic single-page application features:
    - Text search bar
    - Clickable severity badges for filtering
    - Collapsible sections for metadata

### **Formalize the v2 → v3 Schema Migration**

**Status:** 🟡 MEDIUM PRIORITY - Backward compatibility

- **Actions:**
  - Implement agent/migration_v3.py module with v2→v3 conversion function
  - Create comprehensive test suite for migration script
  - Update agent/cli.py to trigger conversion before writing output JSON

---

## **Implementation Status & Tracking**

### **Recently Completed ✅**

- ✅ **PII Suppression Enforcement**: Implemented across ProcessScanner, NetworkScanner, and IOCScanner
- ✅ **Privilege Drop Audit**: Verified main.cpp privilege drop lifecycle with proper logging
- ✅ **eBPF Basic Events**: Working in current environment with proper metadata capture

### **Current Critical Path**

- 🔴 **P0 LangGraph Default**: Make LangGraph the sole execution path
- � **P0 Security Architecture**: Implement multi-layered security guardrails
- � **P0 Unified API**: Develop single gateway for CLI/GUI access
- 🔴 **P0 eBPF ODR Fix**: Resolve build-breaking bug

### **Validation Strategy**

- **Security Testing**: Comprehensive validation of guardrails, tool access control, and output sanitization
- **Integration Testing**: End-to-end testing of unified API and LangGraph workflows
- **Performance Benchmarking**: Intelligence core performance and resource usage metrics
- **User Experience Testing**: CLI and GUI interface validation against unified API

---

## **Development Guidelines**

### **Security-First Development**

- **Zero-Trust Model:** Treat every data boundary as a potential threat vector
- **Input Validation:** Pydantic models for all external inputs and LLM-generated content
- **Principle of Least Privilege:** Minimal necessary access for all components
- **Audit Logging:** Track all security-relevant operations

### **Intelligence Core Standards**

- **LangGraph Canonical:** All new analytical capabilities added to LangGraph first
- **Unified API:** Both CLI and GUI access intelligence core through same API
- **Stateful Design:** Support for persistent, conversational analysis sessions
- **Asynchronous Processing:** Full operational tail (risk analysis, compliance, caching, metrics)

### **Coding Standards**

- Follow Google C++ Style Guide
- Use modern CMake find_package modules
- Implement RAII patterns for resource management
- Add comprehensive error handling and logging

---

*This roadmap represents the transformation from a security scanner to a unified intelligence platform. The LangGraph-powered agent becomes the central nervous system, with security hardening and unified interfaces enabling both powerful analysis and safe, intuitive user experiences.*

