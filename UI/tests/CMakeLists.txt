# Tests CMakeLists.txt
set(TEST_SOURCES
    test_report_parser.cpp
    test_agent_query_builder.cpp
    test_result_formatter.cpp
    test_main.cpp
    ../src/report_parser.cpp
    ../src/agent_query_builder.cpp
    ../src/result_formatter.cpp
)

# Create test executable
add_executable(sys_scan_ui_tests ${TEST_SOURCES})

# Link with Google Test and our libraries
target_link_libraries(sys_scan_ui_tests
    ${GTEST_LIBRARIES}
    ${GTK4_LIBRARIES}
    ${JSONGLIB_LIBRARIES}
    gtest_main
    pthread
)

# Add test
add_test(NAME sys_scan_ui_unit_tests COMMAND sys_scan_ui_tests)

# Include test headers
target_include_directories(sys_scan_ui_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${GTEST_INCLUDE_DIRS}
)