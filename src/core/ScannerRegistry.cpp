#include "ScannerRegistry.h"
#include "ScanContext.h"  // Added ScanContext include
#include "Report.h"
#include "Logging.h"
#include "Config.h"
#include <algorithm>
#include <future>
#include <thread>
#include <chrono>
#include <optional>
#include "../scanners/ProcessScanner.h"
#include "../scanners/NetworkScanner.h"
#include "../scanners/KernelParamScanner.h"
#include "../scanners/ModuleScanner.h"
#include "../scanners/WorldWritableScanner.h"
#include "../scanners/SuidScanner.h"
#include "../scanners/IOCScanner.h"
#include "../scanners/MACScanner.h"
#include "../scanners/MountScanner.h"
#include "../scanners/KernelHardeningScanner.h"
#include "../scanners/SystemdUnitScanner.h"
#include "../scanners/AuditdScanner.h"
#include "../scanners/ContainerScanner.h"
#include "../scanners/IntegrityScanner.h"
#include "../scanners/YaraScanner.h"
#include "Compliance.h"
#include "../scanners/EbpfScanner.h"

namespace sys_scan {

void ScannerRegistry::register_scanner(ScannerPtr scanner) {
    scanners_.push_back(std::move(scanner));
}

void ScannerRegistry::register_all_default(const Config& config) {
    register_scanner(std::make_unique<ProcessScanner>());
    register_scanner(std::make_unique<NetworkScanner>());
    register_scanner(std::make_unique<KernelParamScanner>());
    register_scanner(std::make_unique<ModuleScanner>());
    register_scanner(std::make_unique<WorldWritableScanner>());
    register_scanner(std::make_unique<SuidScanner>());
    register_scanner(std::make_unique<IOCScanner>());
    register_scanner(std::make_unique<MACScanner>());
    register_scanner(std::make_unique<MountScanner>());
    register_scanner(std::make_unique<KernelHardeningScanner>());
    register_scanner(std::make_unique<SystemdUnitScanner>());
    register_scanner(std::make_unique<AuditdScanner>());
    register_scanner(std::make_unique<ContainerScanner>());
    if(config.integrity){
        register_scanner(std::make_unique<IntegrityScanner>());
    }
    if(config.rules_enable){
        register_scanner(std::make_unique<YaraScanner>());
    }
#ifdef SYS_SCAN_HAVE_EBPF
    register_scanner(std::make_unique<EbpfScanner>());
#else
    // Register EbpfScanner even without eBPF support for fallback functionality
    register_scanner(std::make_unique<EbpfScanner>());
#endif
    // Compliance scanners (initial: PCI). Conditional on cfg.compliance
    if(config.compliance) {
        bool include_pci = true;
        const auto& subset = config.compliance_standards;
        if(!subset.empty()) {
            include_pci = std::find(subset.begin(), subset.end(), "pci_dss_4_0") != subset.end();
        }
        if(include_pci) {
            register_scanner(std::make_unique<PCIComplianceScanner>());
        }
    }
}

void ScannerRegistry::run_all(ScanContext& context) {
    const auto& cfg = context.config;  // Use config from context
    // Attach the active configuration to the report for rule engine and filtering
    context.report.attach_config(cfg);
    if(cfg.parallel) {
        run_all_parallel(context);
    } else {
        run_all_sequential(context);
    }
}

void ScannerRegistry::run_all_sequential(ScanContext& context) {
    const auto& cfg = context.config;  // Use config from context
    Report& report = context.report;   // Get report from context
    auto is_enabled = [&](const std::string& name){
        if(!cfg.enable_scanners.empty()) {
            bool found = std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), name)!=cfg.enable_scanners.end();
            if(!found) return false;
        }
        if(!cfg.disable_scanners.empty()) {
            if(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), name)!=cfg.disable_scanners.end()) return false;
        }
        return true;
    };
    for(auto& s : scanners_) {
        if(!is_enabled(s->name())) continue;
        Logger::instance().debug("Starting scanner: " + s->name());
        report.start_scanner(s->name());
        try {
            s->scan(context);  // Pass context instead of report
        } catch(const std::exception& ex) {
            Finding f;
            f.id = s->name() + ":error";
            f.title = "Scanner error";
            f.severity = Severity::Error;
            f.description = ex.what();
            report.add_finding(s->name(), std::move(f));
        }
        report.end_scanner(s->name());
        Logger::instance().debug("Finished scanner: " + s->name());
    }
}

void ScannerRegistry::run_all_parallel(ScanContext& context) {
    const auto& cfg = context.config;  // Use config from context
    Report& report = context.report;   // Get report from context
    auto is_enabled = [&](const std::string& name){
        if(!cfg.enable_scanners.empty()) {
            bool found = std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), name)!=cfg.enable_scanners.end();
            if(!found) return false;
        }
        if(!cfg.disable_scanners.empty()) {
            if(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), name)!=cfg.disable_scanners.end()) return false;
        }
        return true;
    };

    struct TaskResult {
        std::string name;
        std::string error; // empty if ok
    };

    // Collect enabled scanners preserving registration order for deterministic reporting
    std::vector<size_t> indices;
    indices.reserve(scanners_.size());
    for(size_t i=0;i<scanners_.size();++i) {
        if(is_enabled(scanners_[i]->name())) indices.push_back(i);
    }
    if(indices.empty()) return; // nothing to do

    unsigned int max_threads = cfg.parallel_max_threads>0 ? static_cast<unsigned int>(cfg.parallel_max_threads) : std::thread::hardware_concurrency();
    if(max_threads==0) max_threads = 2; // fallback
    if(max_threads > indices.size()) max_threads = static_cast<unsigned int>(indices.size());

    Logger::instance().debug("Parallel scanning enabled with threads=" + std::to_string(max_threads));

    // We'll launch at most max_threads concurrent std::async tasks. Using a simple queue.
    // To preserve deterministic start/end ordering in the report, we record start/end around actual execution but ensure they are inserted in registration order.

    // For each scanner we will hold a future executing the scan; start_scanner/end_scanner must be called exactly once per scanner.
    struct ScanJob { size_t index; std::future<std::string> fut; }; // future returns error string if any
    std::vector<ScanJob> jobs; jobs.reserve(indices.size());

    size_t launch_pos = 0;
    auto launch_job = [&](size_t idx){
        auto& scanner = scanners_[idx];
        std::string name = scanner->name();
        // Mark start immediately in deterministic order (when launched) to keep ordering stable.
        report.start_scanner(name);
        Logger::instance().debug("Starting scanner: " + name);
        return ScanJob{idx, std::async(std::launch::async, [&, idx, name](){
            try {
                scanners_[idx]->scan(context); // Pass context instead of report
                return std::string();
            } catch(const std::exception& ex) {
                return std::string(ex.what());
            } catch(...) {
                return std::string("unknown error");
            }
        })};
    };

    // Launch initial batch
    for(; launch_pos < indices.size() && jobs.size() < max_threads; ++launch_pos) {
        jobs.push_back(launch_job(indices[launch_pos]));
    }

    // Completion loop: when a job finishes, record end_scanner in original order only after its future is ready.
    // We'll process completions in the order of original registration indices to keep deterministic end ordering as well.
    // Map from index to error string once done.
    std::vector<std::optional<std::string>> results(scanners_.size());

    // Simple busy wait with sleep to avoid complexity; number of scanners small. Could use condition_variable if needed.
    size_t completed = 0;
    while(completed < indices.size()) {
        bool progress = false;
        for(auto it = jobs.begin(); it != jobs.end();) {
            auto status = it->fut.wait_for(std::chrono::milliseconds(0));
            if(status == std::future_status::ready) {
                std::string err = it->fut.get();
                results[it->index] = err; // store
                // end scanner now (in completion order, which might differ). We'll defer ordering normalization by calling end in index order below.
                it = jobs.erase(it);
                progress = true;
                // Launch a new job if remaining
                if(launch_pos < indices.size()) {
                    jobs.push_back(launch_job(indices[launch_pos++]));
                }
            } else {
                ++it;
            }
        }
        if(!progress) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        // After marking completions, emit end_scanner events in deterministic order for any finished scanners whose end not yet emitted.
        for(size_t idx : indices) {
            if(results[idx].has_value()) {
                // End scanner exactly once.
                // We signal end then clear optional to sentinel consumed.
                auto tmp = std::move(results[idx]);
                if(tmp) { // still present
                    if(!tmp->empty()) {
                        Finding f;
                        f.id = scanners_[idx]->name() + ":error";
                        f.title = "Scanner error";
                        f.severity = Severity::Error;
                        f.description = *tmp;
                        report.add_finding(scanners_[idx]->name(), std::move(f));
                    }
                    report.end_scanner(scanners_[idx]->name());
                    Logger::instance().debug("Finished scanner: " + scanners_[idx]->name());
                    results[idx] = std::nullopt; // consumed
                    ++completed;
                }
            }
        }
    }
}

}
