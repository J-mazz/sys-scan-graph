cmake_minimum_required(VERSION 3.28)
project(sys-scan VERSION 6.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

include(CTest)

option(SYS_SCAN_ENABLE_COVERAGE "Enable coverage flags (for tests)" OFF)

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

# --- Core Interface Library (transitional shim) ---
add_library(sys_scan_core INTERFACE)

target_link_libraries(sys_scan_core INTERFACE sys_scan_modules)
target_include_directories(sys_scan_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Handle dependencies
if(NOT nlohmann_json_FOUND)
  target_include_directories(sys_scan_core INTERFACE ${CMAKE_BINARY_DIR}/third_party)
else()
  target_link_libraries(sys_scan_core INTERFACE nlohmann_json::nlohmann_json)
endif()

if(OpenSSL_FOUND)
  target_link_libraries(sys_scan_core INTERFACE OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(sys_scan_core INTERFACE SYS_SCAN_HAVE_OPENSSL=1)
endif()

# Executable
add_executable(sys-scan src/main.cpp)
target_link_libraries(sys-scan PRIVATE sys_scan_core)

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
endif()

