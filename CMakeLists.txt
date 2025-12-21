cmake_minimum_required(VERSION 3.28)
project(sys-scan VERSION 6.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR "C++ modules build requires Clang; please reconfigure with CC=clang CXX=clang++")
endif()

include(CTest)

option(SYS_SCAN_ENABLE_COVERAGE "Enable coverage flags (for tests)" OFF)
set(SYS_SCAN_COVERAGE_MIN 85 CACHE STRING "Minimum coverage percentage for line/function/branch")
option(BUILD_FUZZERS "Build fuzzing targets" OFF)

# External Dependencies
find_package(Threads REQUIRED)
find_package(nlohmann_json QUIET)
find_package(OpenSSL QUIET)

# --- Module Library Definition ---
add_library(sys_scan_modules)
target_sources(sys_scan_modules
  PUBLIC
    FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
    src/core/modules/types.ixx
    src/core/modules/config.ixx
    src/core/modules/logging.ixx
    src/core/modules/utils.ixx
    src/core/modules/coro.ixx
    src/core/modules/scanner_interface.ixx
    src/core/modules/report.ixx
    src/core/modules/utils_helper.ixx
    src/core/modules/interfaces.ixx
    src/core/modules/system_services.ixx
    src/core/modules/registry.ixx
    src/scanners/modules/auditd_scanner.ixx
    src/scanners/modules/systemd_scanner.ixx
    src/scanners/modules/process_scanner.ixx
    src/scanners/modules/network_scanner.ixx
    src/scanners/modules/kernel_scanner.ixx
    src/scanners/modules/mount_scanner.ixx
    src/scanners/modules/fs_perms_scanner.ixx
    src/scanners/modules/module_utils.ixx
    src/scanners/modules/mac_scanner.ixx
    src/scanners/modules/integrity_scanner.ixx
    src/scanners/modules/ioc_scanner.ixx
    src/scanners/modules/module_scanner.ixx
    src/scanners/modules/container_scanner.ixx
    src/scanners/modules/yara_scanner.ixx
    src/scanners/modules/ebpf_scanner.ixx
)

# Apply include directories and definitions DIRECTLY to the module library
target_include_directories(sys_scan_modules PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Handle nlohmann_json for module scanning
if(NOT nlohmann_json_FOUND)
  # For bundled version - must exist in third_party directory
  target_include_directories(sys_scan_modules PUBLIC ${CMAKE_BINARY_DIR}/third_party)
else()
  target_link_libraries(sys_scan_modules PUBLIC nlohmann_json::nlohmann_json)
endif()

# Handle OpenSSL
if(OpenSSL_FOUND)
  target_link_libraries(sys_scan_modules PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(sys_scan_modules PUBLIC SYS_SCAN_HAVE_OPENSSL=1)
endif()

# --- Core Interface Library (transitional shim) ---
add_library(sys_scan_core INTERFACE)
target_link_libraries(sys_scan_core INTERFACE sys_scan_modules)

# Executable
add_executable(sys-scan src/main.cpp)
target_link_libraries(sys-scan PRIVATE sys_scan_core)

# Fuzzing targets
if(BUILD_FUZZERS)
  add_executable(fuzz_config fuzz/fuzz_config_module.cpp)
  target_link_libraries(fuzz_config PRIVATE sys_scan_core)
  target_compile_options(fuzz_config PRIVATE -fsanitize=fuzzer,address)
  target_link_options(fuzz_config PRIVATE -fsanitize=fuzzer,address)
endif()

if(SYS_SCAN_ENABLE_COVERAGE)
  # Clang supports --coverage (gcov-compatible) and works with lcov/genhtml.
  foreach(tgt sys_scan_modules sys-scan)
    target_compile_options(${tgt} PRIVATE --coverage -O0 -g)
    target_link_options(${tgt} PRIVATE --coverage)
  endforeach()
endif()

if(BUILD_TESTING)
  add_executable(sys-scan-tests
    tests/test_main.cpp
    tests/test_core.cpp
  )
  target_link_libraries(sys-scan-tests PRIVATE sys_scan_core)

  if(SYS_SCAN_ENABLE_COVERAGE)
    target_compile_options(sys-scan-tests PRIVATE --coverage -O0 -g)
    target_link_options(sys-scan-tests PRIVATE --coverage)
  endif()

  add_test(NAME sys-scan-tests COMMAND sys-scan-tests)

  if(SYS_SCAN_ENABLE_COVERAGE)
    find_program(GCOVR_EXECUTABLE gcovr)
    if(GCOVR_EXECUTABLE)
      add_custom_target(coverage
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        COMMAND ${GCOVR_EXECUTABLE}
          -r ${CMAKE_SOURCE_DIR}
          --filter ${CMAKE_SOURCE_DIR}/src
          --exclude ${CMAKE_BINARY_DIR}
          --exclude ${CMAKE_SOURCE_DIR}/build
          --exclude ${CMAKE_SOURCE_DIR}/build-coverage
          --exclude ${CMAKE_SOURCE_DIR}/build-modules
          --exclude ${CMAKE_SOURCE_DIR}/build-modules-clang
          --exclude ${CMAKE_SOURCE_DIR}/cmake-build-default
          --exclude ${CMAKE_SOURCE_DIR}/tests
          --exclude ${CMAKE_SOURCE_DIR}/src/main.cpp
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/types.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/config.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/utils.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/utils_helper.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/coro.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/interfaces.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/scanner_interface.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/core/modules/system_services.ixx
          --exclude ${CMAKE_SOURCE_DIR}/src/scanners/modules/module_utils.ixx
          --gcov-executable "llvm-cov gcov"
          --gcov-ignore-errors no_working_dir_found
          --gcov-ignore-errors source_not_found
          --print-summary
          --xml-pretty -o coverage.xml
          --html-details -o coverage.html
          --fail-under-line ${SYS_SCAN_COVERAGE_MIN}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        VERBATIM
      )
    endif()
  endif()
endif()