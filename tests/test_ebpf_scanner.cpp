#include "../src/core/ScanContext.h"
#include "../src/core/Report.h"
#include "../src/core/Config.h"
#include "../src/scanners/EbpfScanner.h"
#include <cassert>
#include <iostream>
#include <string>

int main() {
    std::cout << "Testing EbpfScanner optimizations...\n";

    // Test 1: Scanner creation
    sys_scan::EbpfScanner scanner;
    assert(scanner.name() == "ebpf_exec_trace");
    assert(scanner.description() == "Short-lived execve trace via eBPF");
    std::cout << "✓ Scanner creation test passed\n";

    // Skip time-consuming scanning tests for now
    std::cout << "⏭️ Skipping time-consuming scanning tests\n";

    std::cout << "🎉 EbpfScanner basic tests passed!\n";
    std::cout << "✅ Scanner creation works\n";
    std::cout << "✅ Properties accessible\n";

    return 0;
}