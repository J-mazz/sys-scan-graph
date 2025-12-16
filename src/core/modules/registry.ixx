module;
#include <vector>
#include <memory>
#include <algorithm>
#include <string>
#include <future>
#include <thread>
#include <semaphore>

export module sys_scan.registry;
import sys_scan.scanner;
import sys_scan.report;
import sys_scan.config;
import sys_scan.types;

export namespace sys_scan {

class ScannerRegistry {
public:
    void register_scanner(std::unique_ptr<Scanner> scanner) {
        scanners_.push_back(std::move(scanner));
    }

    void run_all(Report& report, const Config& cfg) {
        auto is_enabled = [&](const std::string& name){
            if(!cfg.enable_scanners.empty()) {
                bool found = std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), name) != cfg.enable_scanners.end();
                if(!found) return false;
            }
            if(!cfg.disable_scanners.empty()) {
                if(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), name) != cfg.disable_scanners.end()) return false;
            }
            return true;
        };

        if (!cfg.parallel) {
            for(auto& s : scanners_) {
                if(!s) continue;
                if(!is_enabled(s->name())) continue;
                try {
                    report.consume(s->name(), s->scan());
                } catch(const std::exception& ex) {
                    report.add_error(s->name(), ex.what());
                } catch(...) {
                    report.add_error(s->name(), "unknown error");
                }
            }
            return;
        }

        unsigned int max_threads = cfg.parallel_max_threads > 0
            ? static_cast<unsigned int>(cfg.parallel_max_threads)
            : std::thread::hardware_concurrency();
        if (max_threads == 0) max_threads = 1;
        // Keep an upper bound so we don't create a silly number of threads.
        if (max_threads > 64) max_threads = 64;

        // counting_semaphore requires a compile-time max; we clamp max_threads to <= 64.
        std::counting_semaphore<64> sem(static_cast<std::ptrdiff_t>(max_threads));
        std::vector<std::future<void>> futures;
        futures.reserve(scanners_.size());

        for (auto& s : scanners_) {
            if (!s) continue;
            const std::string scanner_name = s->name();
            if (!is_enabled(scanner_name)) continue;

            sem.acquire();
            futures.emplace_back(std::async(std::launch::async, [&report, &sem, scanner = s.get(), scanner_name]() {
                struct Releaser {
                    std::counting_semaphore<64>& sem;
                    ~Releaser() { sem.release(); }
                } releaser{sem};

                try {
                    report.consume(scanner_name, scanner->scan());
                } catch (const std::exception& ex) {
                    report.add_error(scanner_name, ex.what());
                } catch (...) {
                    report.add_error(scanner_name, "unknown error");
                }
            }));
        }

        for (auto& f : futures) {
            // Future exceptions should already be handled inside the task, but keep this as a safety net.
            try {
                f.get();
            } catch (const std::exception& ex) {
                report.add_error("registry", ex.what());
            } catch (...) {
                report.add_error("registry", "unknown error");
            }
        }
    }

private:
    std::vector<std::unique_ptr<Scanner>> scanners_;
};

}
