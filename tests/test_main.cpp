#include "test_harness.h"

namespace sys_scan_tests {

std::vector<std::pair<std::string, TestFn>>& registry() {
    static std::vector<std::pair<std::string, TestFn>> tests;
    return tests;
}

Registrar::Registrar(std::string name, TestFn fn) {
    registry().emplace_back(std::move(name), fn);
}

} // namespace sys_scan_tests

int main() {
    const auto& tests = sys_scan_tests::registry();
    std::cout << "Running " << tests.size() << " tests\n";

    for (const auto& [name, fn] : tests) {
        try {
            fn();
            std::cout << "[PASS] " << name << "\n";
        } catch (const std::exception& ex) {
            std::cerr << "[FAIL] " << name << ": " << ex.what() << "\n";
            return 1;
        } catch (...) {
            std::cerr << "[FAIL] " << name << ": unknown exception\n";
            return 1;
        }
    }

    return 0;
}
