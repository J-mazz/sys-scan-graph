#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <algorithm>
#include <coroutine>

#include <fuzzer/FuzzedDataProvider.h>

import sys_scan.config;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.registry;
import sys_scan.report;
import sys_scan.coro; // For Generator and co_yield support

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    FuzzedDataProvider fdp(data, size);

    std::vector<std::string> args;
    args.reserve(16);
    args.emplace_back("fuzz_config");

    const size_t num_args = fdp.ConsumeIntegralInRange<size_t>(1, 16);
    for (size_t i = 0; i < num_args && fdp.remaining_bytes() > 0; ++i) {
        std::string s = fdp.ConsumeRandomLengthString(128);
        if (!s.empty()) args.push_back(std::move(s));
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto &arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    // Configure object fuzzing
    sys_scan::Config cfg;
    cfg.fast_scan = fdp.ConsumeBool();
    cfg.parallel_max_threads = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    if (fdp.ConsumeBool()) {
        cfg.enable_scanners.push_back(fdp.ConsumeRandomLengthString(32));
    }

    // Create a tiny, bounded scanner driven by fuzzer data to exercise Registry.run_all
    struct FuzzScanner final : public sys_scan::Scanner {
        std::string name_;
        int count_;
        int sev_;
        FuzzScanner(std::string n, int c, int s) : name_(std::move(n)), count_(c), sev_(s) {}
        std::string name() const override { return name_; }
        std::string description() const override { return "fuzz scanner"; }
        sys_scan::Generator<sys_scan::Finding> scan() override {
            for (int i = 0; i < count_; ++i) {
                sys_scan::Finding f;
                f.id = name_ + ":" + std::to_string(i);
                f.title = "fuzz";
                f.severity = static_cast<sys_scan::Severity>(std::clamp(sev_, 0, 5));
                f.description = "fuzz finding";
                co_yield f;
            }
        }
    };

    int count = static_cast<int>(fdp.ConsumeIntegralInRange<int>(0, 4));
    int sev = static_cast<int>(fdp.ConsumeIntegralInRange<int>(0, 5));
    std::string scanner_name = fdp.ConsumeRandomLengthString(16);

    sys_scan::ScannerRegistry registry;
    registry.register_scanner(std::make_unique<FuzzScanner>(scanner_name.empty() ? "fuzz" : scanner_name, count, sev));

    sys_scan::Report report;
    registry.run_all(report, cfg);

    // Surface results to prevent optimization
    volatile auto rsize = report.results().size(); (void)rsize;

    (void)argv;
    (void)cfg;
    return 0;
}
