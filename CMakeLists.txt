cmake_minimum_required(VERSION 3.16)
project(sys-scan VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build unit tests" ON)
option(ENABLE_OPENSSL "Use OpenSSL for hashing if available" ON)

include(CheckIncludeFile)
include(CheckLibraryExists)

if(ENABLE_OPENSSL)
  find_package(OpenSSL QUIET)
endif()

add_library(sys_scan_core
  src/core/Scanner.cpp
  src/core/ScannerRegistry.cpp
  src/core/Report.cpp
  src/core/Utils.cpp
  src/core/JSONWriter.cpp
  src/core/Logging.cpp
  src/core/Config.cpp
  src/scanners/ProcessScanner.cpp
  src/scanners/NetworkScanner.cpp
  src/scanners/KernelParamScanner.cpp
  src/scanners/ModuleScanner.cpp
  src/scanners/WorldWritableScanner.cpp
  src/scanners/SuidScanner.cpp
  src/scanners/IOCScanner.cpp
  src/scanners/MACScanner.cpp
)

target_include_directories(sys_scan_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

find_package(Threads REQUIRED)

target_link_libraries(sys_scan_core PUBLIC Threads::Threads)

if(OpenSSL_FOUND)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_OPENSSL=1)
  target_link_libraries(sys_scan_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

# Optional compression libraries for in-process module decompression (replaces popen to xz/gzip)
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  target_link_libraries(sys_scan_core PUBLIC ZLIB::ZLIB)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_ZLIB=1)
endif()
find_package(LibLZMA QUIET)
if(LIBLZMA_FOUND)
  target_link_libraries(sys_scan_core PUBLIC LibLZMA::LibLZMA)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_LZMA=1)
endif()

add_executable(sys-scan src/main.cpp)

target_link_libraries(sys-scan PRIVATE sys_scan_core)

# Tests
if(BUILD_TESTS)
  enable_testing()
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
endif()

install(TARGETS sys-scan RUNTIME DESTINATION bin) # debian/rules will stage into debian/sys-scan/usr/bin automatically
install(DIRECTORY third_party/ DESTINATION include/sys-scan/third_party FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY src/core/ DESTINATION include/sys-scan/core FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/scanners/ DESTINATION include/sys-scan/scanners FILES_MATCHING PATTERN "*.h")
install(DIRECTORY schema/ DESTINATION share/sys-scan/schema FILES_MATCHING PATTERN "*.json")

