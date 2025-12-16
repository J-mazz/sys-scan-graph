module;
#include <vector>
#include <memory>
#include <algorithm>
#include <string>

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

        for(auto& s : scanners_) {
            if(!s) continue;
            if(!is_enabled(s->name())) continue;
            try {
                auto gen = s->scan();
                report.consume(s->name(), gen);
            } catch(const std::exception& ex) {
                report.add_error(s->name(), ex.what());
            } catch(...) {
                report.add_error(s->name(), "unknown error");
            }
        }
    }

private:
    std::vector<std::unique_ptr<Scanner>> scanners_;
};

}
