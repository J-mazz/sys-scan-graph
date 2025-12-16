#pragma once

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace sys_scan_tests {

using TestFn = void(*)();

// Implemented in test_main.cpp
std::vector<std::pair<std::string, TestFn>>& registry();

struct Registrar {
    Registrar(std::string name, TestFn fn);
};

} // namespace sys_scan_tests

#define SYS_SCAN_TEST(name) \
    static void name(); \
    static sys_scan_tests::Registrar name##_registrar{#name, &name}; \
    static void name()

#define SYS_SCAN_ASSERT(expr) do { \
    if (!(expr)) { \
        std::cerr << "ASSERT FAILED: " #expr << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        std::abort(); \
    } \
} while (0)
