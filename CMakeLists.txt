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
)

target_include_directories(sys_scan_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

find_package(Threads REQUIRED)

target_link_libraries(sys_scan_core PUBLIC Threads::Threads)

if(OpenSSL_FOUND)
  target_compile_definitions(sys_scan_core PUBLIC SYS_SCAN_HAVE_OPENSSL=1)
  target_link_libraries(sys_scan_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

add_executable(sys-scan src/main.cpp)

target_link_libraries(sys-scan PRIVATE sys_scan_core)

# Tests
if(BUILD_TESTS)
  enable_testing()
  add_executable(test_basic tests/test_basic.cpp)
  target_link_libraries(test_basic PRIVATE sys_scan_core)
  add_test(NAME basic COMMAND test_basic)
endif()

install(TARGETS sys-scan RUNTIME DESTINATION bin)
install(DIRECTORY third_party/ DESTINATION include/sys-scan/third_party FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY src/core/ DESTINATION include/sys-scan/core FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/scanners/ DESTINATION include/sys-scan/scanners FILES_MATCHING PATTERN "*.h")

