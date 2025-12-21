cmake_minimum_required(VERSION 3.28)
project(sys-scan-ui VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# CRITICAL: Enable module scanning for Clang/GCC
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

# Optimization Flags
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O3 -march=native -flto)
endif()

# Dependencies
find_package(Qt6 REQUIRED COMPONENTS Quick Core Qml)
find_package(nlohmann_json REQUIRED)

# --- AI Backend: llama.cpp (Vulkan) ---
include(FetchContent)

# Force Vulkan backend for GGML
set(GGML_VULKAN ON CACHE BOOL "Enable Vulkan Backend" FORCE)
set(LLAMA_BUILD_TESTS OFF CACHE BOOL "Disable Llama Tests" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "Disable Llama Examples" FORCE)

FetchContent_Declare(
    llama_cpp
    GIT_REPOSITORY https://github.com/ggerganov/llama.cpp
    GIT_TAG        master
)
# Note: FetchContent_MakeAvailable will attempt to download at configure time
FetchContent_MakeAvailable(llama_cpp)

# --- Core Logic as a Module Library ---
add_library(sys_scan_core_ui)
target_sources(sys_scan_core_ui
    PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/core/types.ixx
        src/core/report_parser.ixx
        src/core/finding_model.ixx
        src/core/coro.ixx
        src/core/agent_service.ixx
        src/core/ipc_service.ixx
)
# Implementation units for modules
target_sources(sys_scan_core_ui
    PRIVATE
        src/core/report_parser.cpp
        src/core/finding_model.cpp
        src/core/agent_service.cpp
        src/core/ipc_service.cpp
)
# Ensure Qt's moc (automoc) runs for meta-object macros inside module sources
set_target_properties(sys_scan_core_ui PROPERTIES AUTOMOC ON)
# Skip automoc for module interface files where we include the moc in a private TU
set_source_files_properties(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/finding_model.ixx
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/types.ixx
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/agent_service.ixx
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/ipc_service.ixx
    PROPERTIES SKIP_AUTOMOC ON)

# Add Network for QLocalSocket
find_package(Qt6 REQUIRED COMPONENTS Network)

target_link_libraries(sys_scan_core_ui PUBLIC Qt6::Core nlohmann_json::nlohmann_json Qt6::Network)

if(TARGET llama)
    message(STATUS "Linking with llama backend")
    target_link_libraries(sys_scan_core_ui PUBLIC llama)
endif()

# Link llama if available from FetchContent
if(TARGET llama)
    message(STATUS "Linking with llama backend")
    target_link_libraries(sys_scan_core_ui PUBLIC llama)
endif()

# --- Main Executable ---
qt_add_executable(sys-scan-ui
    MANUAL_FINALIZATION
    src/main.cpp
    resources/qml/Main.qml
)

target_link_libraries(sys-scan-ui PRIVATE Qt6::Quick sys_scan_core_ui)

# Tests
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Install targets
install(TARGETS sys-scan-ui
    RUNTIME DESTINATION bin
)

install(FILES resources/sys-scan-ui.desktop
    DESTINATION share/applications
)
