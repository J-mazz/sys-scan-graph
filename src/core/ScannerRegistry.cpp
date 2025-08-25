#include "ScannerRegistry.h"
#include "Report.h"
#include "Logging.h"
#include "Config.h"
#include "../scanners/ProcessScanner.h"
#include "../scanners/NetworkScanner.h"
#include "../scanners/KernelParamScanner.h"
#include "../scanners/ModuleScanner.h"
#include "../scanners/WorldWritableScanner.h"
#include "../scanners/SuidScanner.h"
#include "../scanners/IOCScanner.h"

namespace sys_scan {

void ScannerRegistry::register_scanner(ScannerPtr scanner) {
    scanners_.push_back(std::move(scanner));
}

void ScannerRegistry::register_all_default() {
    register_scanner(std::make_unique<ProcessScanner>());
    register_scanner(std::make_unique<NetworkScanner>());
    register_scanner(std::make_unique<KernelParamScanner>());
    register_scanner(std::make_unique<ModuleScanner>());
    register_scanner(std::make_unique<WorldWritableScanner>());
    register_scanner(std::make_unique<SuidScanner>());
    register_scanner(std::make_unique<IOCScanner>());
}

void ScannerRegistry::run_all(Report& report) {
    auto& cfg = config();
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
            s->scan(report);
        } catch(const std::exception& ex) {
            Finding f;
            f.id = s->name() + ":error";
            f.title = "Scanner error";
            f.severity = "error";
            f.description = ex.what();
            report.add_finding(s->name(), std::move(f));
        }
        report.end_scanner(s->name());
        Logger::instance().debug("Finished scanner: " + s->name());
    }
}

}
