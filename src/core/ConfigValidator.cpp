#include "ConfigValidator.h"
#include <iostream>
#include <fstream>
#include <algorithm>

namespace sys_scan {

bool ConfigValidator::validate(Config& cfg) {
    // Normalize ioc_exec_trace default duration
    if(cfg.ioc_exec_trace && cfg.ioc_exec_trace_seconds == 0) {
        cfg.ioc_exec_trace_seconds = 3;
    }

    // Conflict detection: sarif vs ndjson (allow both, implementation handles precedence)
    // if(cfg.sarif && cfg.ndjson) {
    //     std::cerr << "--sarif and --ndjson are mutually exclusive\n";
    //     return false;
    // }

    // pretty vs compact: if both set, compact wins (documented behavior)
    if(cfg.pretty && cfg.compact) {
        cfg.pretty = false;
    }

    // Required value checks
    if(cfg.sign_gpg && cfg.output_file.empty()) {
        std::cerr << "--sign-gpg requires --output FILE\n";
        return false;
    }

    // Basic severity validation
    if(!validate_severity(cfg.min_severity, "--min-severity")) {
        return false;
    }
    if(!validate_severity(cfg.fail_on_severity, "--fail-on")) {
        return false;
    }

    // Severity relationship validation
    if(!cfg.min_severity.empty() && !cfg.fail_on_severity.empty()) {
        if(severity_rank(cfg.min_severity) > severity_rank(cfg.fail_on_severity)) {
            std::cerr << "--min-severity cannot be higher than --fail-on severity\n";
            return false;
        }
    }

    // Scanner enable/disable conflicts
    for(const auto& scanner : cfg.enable_scanners) {
        if(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), scanner) != cfg.disable_scanners.end()) {
            std::cerr << "Cannot enable and disable the same scanner: " << scanner << "\n";
            return false;
        }
    }

    if(!cfg.container_id_filter.empty() && !cfg.containers) {
        std::cerr << "--container-id requires --containers\n";
        return false;
    }

    return true;
}

void ConfigValidator::apply_fast_scan_optimizations(Config& cfg) {
    if(!cfg.fast_scan) return;

    // Only add disables if user hasn't explicitly enabled them
    auto add_disable = [&](const std::string& name) {
        if(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), name) == cfg.enable_scanners.end()) {
            cfg.disable_scanners.push_back(name);
        }
    };

    add_disable("modules");
    add_disable("integrity");
    add_disable("ebpf");

    // Set fast scan optimizations
    cfg.modules_summary_only = true;

    // Re-set config after mutation
    set_config(cfg);
}

bool ConfigValidator::load_external_files(Config& cfg) {
    bool success = true;

    if(!cfg.ioc_allow_file.empty()) {
        if(!load_ioc_allowlist(cfg)) {
            success = false;
        }
    }

    if(!cfg.suid_expected_file.empty()) {
        if(!load_suid_expected(cfg)) {
            success = false;
        }
    }

    return success;
}

bool ConfigValidator::validate_severity(const std::string& severity, const std::string& flag_name) {
    if(severity.empty()) return true;

    if(std::find(allowed_severities_.begin(), allowed_severities_.end(), severity) == allowed_severities_.end()) {
        std::cerr << "Invalid " << flag_name << " value: " << severity << "\n";
        return false;
    }

    return true;
}

int ConfigValidator::severity_rank(const std::string& severity) const {
    if(severity == "info") return 0;
    if(severity == "low") return 1;
    if(severity == "medium") return 2;
    if(severity == "high") return 3;
    if(severity == "critical") return 4;
    if(severity == "error") return 5;
    return -1; // Invalid severity
}

bool ConfigValidator::load_ioc_allowlist(Config& cfg) {
    std::ifstream af(cfg.ioc_allow_file);
    if(!af) {
        std::cerr << "Failed to open IOC allowlist file: " << cfg.ioc_allow_file << "\n";
        return false;
    }

    std::string line;
    while(std::getline(af, line)) {
        // Trim leading whitespace
        size_t start = line.find_first_not_of(" \t");
        if(start != std::string::npos) {
            line = line.substr(start);
        } else {
            line.clear(); // All whitespace
        }

        if(line.empty()) continue;
        if(!line.empty() && line[0] == '#') continue; // Skip comments
        cfg.ioc_allow.push_back(line);
    }

    // Update global config with merged allowlist
    set_config(cfg);
    return true;
}

bool ConfigValidator::load_suid_expected(Config& cfg) {
    std::ifstream ef(cfg.suid_expected_file);
    if(!ef) {
        std::cerr << "Failed to open SUID expected file: " << cfg.suid_expected_file << "\n";
        return false;
    }

    std::string line;
    while(std::getline(ef, line)) {
        if(line.empty()) continue;
        if(line[0] == '#') continue; // Skip comments
        cfg.suid_expected_add.push_back(line);
    }

    // Update global config
    set_config(cfg);
    return true;
}

} // namespace sys_scan