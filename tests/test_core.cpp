#include "test_harness.h"

#include <coroutine>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

import sys_scan.coro;
import sys_scan.report;
import sys_scan.registry;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.config;
import sys_scan.interfaces;
import sys_scan.system_services;

using namespace sys_scan;

namespace {

Generator<int> throwing_generator() {
    co_yield 1;
    throw std::runtime_error("boom");
}

Generator<Finding> one_finding(Severity sev = Severity::Info) {
    Finding f;
    f.id = "t";
    f.title = "title";
    f.severity = sev;
    f.description = "desc";
    co_yield f;
}

class ThrowingScanner final : public Scanner {
public:
    std::string name() const override { return "throwing"; }
    std::string description() const override { return "throws"; }
    Generator<Finding> scan() override {
        throw std::runtime_error("scanner boom");
    }
};

class YieldingScanner final : public Scanner {
    std::string n_;
    int count_;
public:
    explicit YieldingScanner(std::string n, int count) : n_(std::move(n)), count_(count) {}
    std::string name() const override { return n_; }
    std::string description() const override { return "yields"; }
    Generator<Finding> scan() override {
        for (int i = 0; i < count_; ++i) {
            Finding f;
            f.id = n_ + ":" + std::to_string(i);
            f.title = "t";
            f.severity = Severity::Info;
            f.description = "d";
            co_yield f;
        }
    }
};

} // namespace

SYS_SCAN_TEST(generator_rethrows_exceptions) {
    bool threw = false;
    try {
        for (int v : throwing_generator()) {
            (void)v;
        }
    } catch (const std::runtime_error& ex) {
        threw = std::string(ex.what()) == "boom";
    }
    SYS_SCAN_ASSERT(threw);
}

SYS_SCAN_TEST(report_consume_collects_findings) {
    Report r;
    r.consume("s", one_finding(Severity::High));
    SYS_SCAN_ASSERT(r.results().size() == 1);
    SYS_SCAN_ASSERT(r.results()[0].scanner_name == "s");
    SYS_SCAN_ASSERT(r.results()[0].findings.size() == 1);
    SYS_SCAN_ASSERT(r.results()[0].findings[0].severity == Severity::High);
}

SYS_SCAN_TEST(registry_sequential_catches_scanner_exception) {
    ScannerRegistry reg;
    reg.register_scanner(std::make_unique<ThrowingScanner>());

    Config cfg;
    cfg.parallel = false;

    Report rep;
    reg.run_all(rep, cfg);

    SYS_SCAN_ASSERT(!rep.errors().empty());
    SYS_SCAN_ASSERT(rep.errors()[0].first == "throwing");
}

SYS_SCAN_TEST(registry_parallel_runs_all) {
    ScannerRegistry reg;
    reg.register_scanner(std::make_unique<YieldingScanner>("a", 3));
    reg.register_scanner(std::make_unique<YieldingScanner>("b", 2));

    Config cfg;
    cfg.parallel = true;
    cfg.parallel_max_threads = 2;

    Report rep;
    reg.run_all(rep, cfg);

    // Order is not guaranteed in parallel; just validate counts.
    size_t total = 0;
    for (const auto& r : rep.results()) total += r.findings.size();
    SYS_SCAN_ASSERT(total == 5);
}

SYS_SCAN_TEST(list_directory_includes_entry_path) {
    RealFileSystem fs;

    const auto tmp_base = std::filesystem::temp_directory_path() / "sys_scan_test_dir";
    std::error_code ec;
    std::filesystem::remove_all(tmp_base, ec);
    std::filesystem::create_directories(tmp_base, ec);
    SYS_SCAN_ASSERT(!ec);

    const auto f = tmp_base / "file.txt";
    std::ofstream out(f);
    out << "x";
    out.close();

    auto entries = fs.list_directory(tmp_base.string());
    bool saw = false;
    for (const auto& e : entries) {
        if (e.name == "file.txt") {
            saw = true;
            SYS_SCAN_ASSERT(!e.path.empty());
            // Best-effort: should end with file.txt
            SYS_SCAN_ASSERT(e.path.find("file.txt") != std::string::npos);
        }
    }
    SYS_SCAN_ASSERT(saw);

    std::filesystem::remove_all(tmp_base, ec);
}
