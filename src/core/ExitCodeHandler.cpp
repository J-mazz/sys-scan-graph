#include "ExitCodeHandler.h"
#include "Severity.h"
#include <algorithm>

namespace sys_scan {

int ExitCodeHandler::calculate_exit_code(const Report& report, const Config& cfg) const {
    // Check severity threshold first
    if(!cfg.fail_on_severity.empty()) {
        int thresh = severity_rank(cfg.fail_on_severity);
        const auto& results = report.results();
        for(const auto& r : results) {
            for(const auto& f : r.findings) {
                if(severity_rank_enum(f.severity) >= thresh) {
                    return 1;  // Severity threshold met, fail immediately
                }
            }
        }
        // Severity threshold set but not met - don't check count
        return 0;
    }

    // No severity threshold set, check count threshold
    if(cfg.fail_on_count >= 0) {
        size_t total = 0;
        for(const auto& r : report.results()) {
            total += r.findings.size();
        }
        if(total >= static_cast<size_t>(cfg.fail_on_count)) {
            return 1;
        }
    }

    return 0;
}

int ExitCodeHandler::severity_rank(const std::string& severity) const {
    return sys_scan::severity_rank(severity);
}

int ExitCodeHandler::severity_rank_enum(Severity severity) const {
    return sys_scan::severity_rank_enum(severity);
}

} // namespace sys_scan