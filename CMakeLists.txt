cmake_minimum_required(VERSION 3.16)
project(sys-scan VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build unit tests" ON)
option(ENABLE_OPENSSL "Use OpenSSL for hashing if available" ON)
option(SYS_SCAN_REPRO_BUILD "Enable reproducible build settings (avoid embedding timestamps, absolute paths)" OFF)
option(ENABLE_SECCOMP "Enable optional seccomp-bpf sandbox (requires libseccomp)" ON)
option(ENABLE_CAPABILITIES "Enable Linux capabilities privilege dropping (libcap)" ON)
option(BUILD_FUZZERS "Build libFuzzer harnesses (Clang only)" OFF)
option(WITH_EBPF "Enable eBPF-based scanners (requires bpftool and BTF)" ON)
option(WITH_EBPF_STRICT "Require eBPF skeleton generation (fail if bpftool not found or incompatible)" ON)

set(SYS_SCAN_SLSA_LEVEL "0" CACHE STRING "Declared SLSA build level for provenance metadata (informational only)")

# eBPF support
if(WITH_EBPF)
  find_program(BPFTOOL_EXECUTABLE bpftool)
  if(NOT BPFTOOL_EXECUTABLE)
    if(WITH_EBPF_STRICT)
      message(FATAL_ERROR "bpftool not found in PATH, required for WITH_EBPF_STRICT")
    else()
      message(WARNING "bpftool not found in PATH, eBPF scanners will be disabled")
      set(WITH_EBPF OFF)
    endif()
  endif()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBBPF REQUIRED libbpf)
endif()

if(SYS_SCAN_REPRO_BUILD)
  # Common reproducible build suggestions (user can still override externally)
  add_compile_definitions(SYS_SCAN_REPRO_BUILD=1)
  # Avoid __DATE__/__TIME__ if used anywhere
  add_compile_definitions(__DATE__="1970-01-01" __TIME__="00:00:00")
endif()

include(CheckIncludeFile)
include(CheckLibraryExists)

if(ENABLE_OPENSSL)
  find_package(OpenSSL QUIET)
endif()

add_library(sys_scan_core
  src/core/Scanner.cpp
  src/core/ScannerRegistry.cpp
  src/core/RuleEngine.cpp
  src/core/Report.cpp
  src/core/Utils.cpp
  src/core/JsonUtil.cpp
  src/core/JSONWriter.cpp
  src/core/Logging.cpp
  src/core/Config.cpp
  src/core/Compliance.cpp
  src/core/ArgumentParser.cpp
  src/core/ConfigValidator.cpp
  src/core/OutputWriter.cpp
  src/core/GPGSigner.cpp
  src/core/RuleEngineInitializer.cpp
  src/core/ExitCodeHandler.cpp
  src/scanners/ProcessScanner.cpp
  src/scanners/NetworkScanner.cpp
  src/scanners/KernelParamScanner.cpp
  src/scanners/ModuleScanner.cpp
  src/scanners/ModuleHelpers.cpp
  src/scanners/ModuleUtils.cpp
  src/scanners/WorldWritableScanner.cpp
  src/scanners/SuidScanner.cpp
  src/scanners/IOCScanner.cpp
  src/scanners/MACScanner.cpp
  src/scanners/MountScanner.cpp
  src/scanners/KernelHardeningScanner.cpp
  src/scanners/SystemdUnitScanner.cpp
  src/scanners/AuditdScanner.cpp
  src/scanners/ContainerScanner.cpp
  src/scanners/IntegrityScanner.cpp
  src/scanners/YaraScanner.cpp
  src/core/Privilege.cpp
  $<$<BOOL:${WITH_EBPF}>:src/scanners/EbpfScanner.cpp>
)

if(WITH_EBPF)
  add_dependencies(sys_scan_core ebpf_skeleton)
endif()

#-------------------- Build provenance (git commit, compiler, flags) --------------------
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
  execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                  OUTPUT_VARIABLE GIT_COMMIT
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
  set(GIT_COMMIT "unknown")
endif()

# Merge relevant flags into a single string (escape quotes)
set(ALL_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}" )
string(REPLACE "\n" " " ALL_CXX_FLAGS "${ALL_CXX_FLAGS}")
string(REPLACE "\"" "'" ALL_CXX_FLAGS "${ALL_CXX_FLAGS}")

configure_file(${CMAKE_SOURCE_DIR}/BuildInfo.h.in ${CMAKE_BINARY_DIR}/generated/BuildInfo.h @ONLY)
target_include_directories(sys_scan_core PUBLIC ${CMAKE_BINARY_DIR}/generated)

# eBPF object and skeleton generation
if(WITH_EBPF)
  set(BPF_SRC ${CMAKE_SOURCE_DIR}/src/ebpf/process_exec.bpf.c)
  set(BPF_OBJ ${CMAKE_BINARY_DIR}/generated/process_exec.bpf.o)
  set(BPF_SKEL ${CMAKE_BINARY_DIR}/generated/process_exec.skel.h)
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)
  add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang -O2 -g -Wall -Werror -target bpf -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF object"
  )
  add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/generated
    COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating eBPF skeleton"
  )
  add_custom_target(ebpf_skeleton DEPENDS ${BPF_SKEL})
endif()

target_include_directories(sys_scan_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/third_party ${CMAKE_BINARY_DIR}/generated)

find_package(Threads REQUIRED)

target_link_libraries(sys_scan_core PUBLIC Threads::Threads)

# nlohmann/json for JSON handling
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  # Download nlohmann/json header
  file(DOWNLOAD
    https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
    ${CMAKE_BINARY_DIR}/third_party/nlohmann/json.hpp
    SHOW_PROGRESS
  )
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/third_party/nlohmann)
  target_include_directories(sys_scan_core PUBLIC ${CMAKE_BINARY_DIR}/third_party)
else()
  target_link_libraries(sys_scan_core PUBLIC nlohmann_json::nlohmann_json)
endif()

if(OpenSSL_FOUND)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_OPENSSL=1)
  target_link_libraries(sys_scan_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(WITH_EBPF)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_EBPF=1)
  target_link_libraries(sys_scan_core PUBLIC ${LIBBPF_LIBRARIES})
  target_include_directories(sys_scan_core PUBLIC ${LIBBPF_INCLUDE_DIRS})
endif()

# libseccomp (sandbox)
if(ENABLE_SECCOMP)
  find_library(LIBSECCOMP_LIB seccomp)
  if(NOT LIBSECCOMP_LIB)
    # Try alternative library names and paths
    find_library(LIBSECCOMP_LIB seccomp2)
    if(NOT LIBSECCOMP_LIB)
      find_library(LIBSECCOMP_LIB seccomp.so.2)
      if(NOT LIBSECCOMP_LIB)
        # Try direct path
        set(LIBSECCOMP_LIB "/usr/lib/x86_64-linux-gnu/libseccomp.so")
        if(NOT EXISTS ${LIBSECCOMP_LIB})
          set(LIBSECCOMP_LIB "/usr/lib/x86_64-linux-gnu/libseccomp.so.2")
        endif()
      endif()
    endif()
  endif()
  if(LIBSECCOMP_LIB AND EXISTS ${LIBSECCOMP_LIB})
    target_link_libraries(sys_scan_core PUBLIC ${LIBSECCOMP_LIB})
    target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_SECCOMP=1)
  endif()
endif()

# libcap (capability dropping)
if(ENABLE_CAPABILITIES)
  find_library(LIBCAP_LIB cap)
  if(NOT LIBCAP_LIB)
    # Try alternative library names
    find_library(LIBCAP_LIB cap2)
  endif()
  if(LIBCAP_LIB)
    target_link_libraries(sys_scan_core PUBLIC ${LIBCAP_LIB})
    target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_LIBCAP=1)
  endif()
endif()

# Optional compression libraries for in-process module decompression (replaces popen to xz/gzip)
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  target_link_libraries(sys_scan_core PUBLIC ZLIB::ZLIB)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_ZLIB=1)
endif()

# Fuzzers (libFuzzer) – simple harness example
if(BUILD_FUZZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_executable(fuzz_rules fuzz/fuzz_rules.cpp)
  target_link_libraries(fuzz_rules PRIVATE sys_scan_core)
  target_compile_options(fuzz_rules PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  target_link_options(fuzz_rules PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
find_package(LibLZMA QUIET)
if(LIBLZMA_FOUND)
  target_link_libraries(sys_scan_core PUBLIC LibLZMA::LibLZMA)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_LZMA=1)
endif()

add_executable(sys-scan src/main.cpp)

target_link_libraries(sys-scan PRIVATE sys_scan_core)

# Benchmark executable
add_executable(sys-scan-benchmark src/benchmark.cpp)
target_link_libraries(sys-scan-benchmark PRIVATE sys_scan_core)

# Tests
if(BUILD_TESTS)
  enable_testing()
  
  # Find Google Test
  find_package(GTest QUIET)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    # Prevent overriding the parent project's compiler/linker on Windows
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()

  add_executable(test_basic tests/test_basic.cpp)
  target_link_libraries(test_basic PRIVATE sys_scan_core)
  add_test(NAME basic COMMAND test_basic)
  add_executable(test_suid_expected tests/test_suid_expected.cpp)
  target_link_libraries(test_suid_expected PRIVATE sys_scan_core)
  add_test(NAME suid_expected COMMAND test_suid_expected)
  add_executable(test_modules_anomalies tests/test_modules_anomalies.cpp)
  target_link_libraries(test_modules_anomalies PRIVATE sys_scan_core)
  add_test(NAME modules_anomalies COMMAND test_modules_anomalies)
  add_executable(test_json_schema_smoke tests/test_json_schema_smoke.cpp)
  target_link_libraries(test_json_schema_smoke PRIVATE sys_scan_core)
  add_test(NAME json_schema_smoke COMMAND test_json_schema_smoke)
  add_executable(test_sarif_smoke tests/test_sarif_smoke.cpp)
  target_link_libraries(test_sarif_smoke PRIVATE sys_scan_core)
  add_test(NAME sarif_smoke COMMAND test_sarif_smoke)
  add_executable(test_canonical_golden tests/test_canonical_golden.cpp)
  target_link_libraries(test_canonical_golden PRIVATE sys_scan_core)
  add_test(NAME canonical_golden COMMAND test_canonical_golden)
  add_executable(test_rules_engine tests/test_rules_engine.cpp)
  target_link_libraries(test_rules_engine PRIVATE sys_scan_core)
  add_test(NAME rules_engine COMMAND test_rules_engine)
  add_executable(test_rules_engine_unit tests/test_rules_engine_unit.cpp)
  target_link_libraries(test_rules_engine_unit PRIVATE sys_scan_core)
  add_test(NAME rules_engine_unit COMMAND test_rules_engine_unit)
  add_executable(test_ndjson_mitre tests/test_ndjson_mitre.cpp)
  target_link_libraries(test_ndjson_mitre PRIVATE sys_scan_core)
  add_test(NAME ndjson_mitre COMMAND test_ndjson_mitre)
  add_executable(test_rules_mitre_dedup tests/test_rules_mitre_dedup.cpp)
  target_link_libraries(test_rules_mitre_dedup PRIVATE sys_scan_core)
  add_test(NAME rules_mitre_dedup COMMAND test_rules_mitre_dedup)
  add_executable(test_rules_engine_warnings_structured tests/test_rules_engine_warnings_structured.cpp)
  target_link_libraries(test_rules_engine_warnings_structured PRIVATE sys_scan_core)
  add_test(NAME rules_engine_warnings_structured COMMAND test_rules_engine_warnings_structured)
  add_executable(test_meta_suppression tests/test_meta_suppression.cpp)
  target_link_libraries(test_meta_suppression PRIVATE sys_scan_core)
  add_test(NAME meta_suppression COMMAND test_meta_suppression)
  add_executable(test_report_concurrency tests/test_report_concurrency.cpp)
  target_link_libraries(test_report_concurrency PRIVATE sys_scan_core)
  add_test(NAME report_concurrency COMMAND test_report_concurrency)
  add_executable(test_operational_error_risk tests/test_operational_error_risk.cpp)
  target_link_libraries(test_operational_error_risk PRIVATE sys_scan_core)
  add_test(NAME operational_error_risk COMMAND test_operational_error_risk)
  
  add_executable(test_pii_suppression tests/test_pii_suppression.cpp)
  target_link_libraries(test_pii_suppression PRIVATE sys_scan_core)
  add_test(NAME pii_suppression COMMAND test_pii_suppression)
  
  # Unit tests for new modular components
  add_executable(test_argument_parser tests/test_argument_parser.cpp)
  target_link_libraries(test_argument_parser PRIVATE sys_scan_core GTest::gtest_main)
  add_test(NAME argument_parser COMMAND test_argument_parser)
  
  add_executable(test_config_validator tests/test_config_validator.cpp)
  target_link_libraries(test_config_validator PRIVATE sys_scan_core GTest::gtest_main)
  add_test(NAME config_validator COMMAND test_config_validator)
  
  add_executable(test_output_writer tests/test_output_writer.cpp)
  target_link_libraries(test_output_writer PRIVATE sys_scan_core GTest::gtest_main)
  target_include_directories(test_output_writer PRIVATE ${CMAKE_BINARY_DIR}/third_party)
  add_test(NAME output_writer COMMAND test_output_writer)
  
  add_executable(test_gpg_signer tests/test_gpg_signer.cpp)
  target_link_libraries(test_gpg_signer PRIVATE sys_scan_core GTest::gtest_main)
  add_test(NAME gpg_signer COMMAND test_gpg_signer)
  
  add_executable(test_rule_engine_initializer tests/test_rule_engine_initializer.cpp)
  target_link_libraries(test_rule_engine_initializer PRIVATE sys_scan_core GTest::gtest_main)
  add_test(NAME rule_engine_initializer COMMAND test_rule_engine_initializer)
  
  add_executable(test_exit_code_handler tests/test_exit_code_handler.cpp)
  target_link_libraries(test_exit_code_handler PRIVATE sys_scan_core GTest::gtest_main)
  add_test(NAME exit_code_handler COMMAND test_exit_code_handler)
  
  # Integration test for complete workflow
  add_executable(test_integration tests/test_integration.cpp)
  target_link_libraries(test_integration PRIVATE sys_scan_core GTest::gtest_main)
  add_test(NAME integration COMMAND test_integration)
endif()

install(TARGETS sys-scan RUNTIME DESTINATION bin) # debian/rules will stage into debian/sys-scan/usr/bin automatically
install(DIRECTORY third_party/ DESTINATION include/sys-scan/third_party FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY src/core/ DESTINATION include/sys-scan/core FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/scanners/ DESTINATION include/sys-scan/scanners FILES_MATCHING PATTERN "*.h")
install(DIRECTORY schema/ DESTINATION share/sys-scan/schema FILES_MATCHING PATTERN "*.json")

