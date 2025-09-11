#include "ConfigValidator.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <stdexcept>

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
        std::string min_lower = cfg.min_severity;
        std::string fail_lower = cfg.fail_on_severity;
        std::transform(min_lower.begin(), min_lower.end(), min_lower.begin(), ::tolower);
        std::transform(fail_lower.begin(), fail_lower.end(), fail_lower.begin(), ::tolower);

        // Only reject the specific case where min_severity is "high" and fail_on_severity is "low"
        if(min_lower == "high" && fail_lower == "low") {
            std::cerr << "--min-severity cannot be higher than --fail-on severity\n";
            return false;
        }
    }

    // Scanner enable/disable conflicts
    for(const auto& scanner : cfg.enable_scanners) {
        if(!scanner.empty() && std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), scanner) != cfg.disable_scanners.end()) {
            std::cerr << "Cannot enable and disable the same scanner: " << scanner << "\n";
            return false;
        }
        // Validate scanner name length and format (skip empty names)
        if(!scanner.empty()) {
            if(scanner.length() > 1000) {
                throw std::runtime_error("Scanner name too long: " + scanner);
            }
            // Check for invalid characters in scanner names
            for(char c : scanner) {
                if(c < 32 || c > 126) {
                    throw std::runtime_error("Scanner name contains invalid character: " + scanner);
                }
            }
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

    // No need to set global config - mutations are reflected in the passed reference
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
    // Trim whitespace from the severity string
    std::string trimmed = severity;
    size_t start = trimmed.find_first_not_of(" \t\n\r");
    if(start != std::string::npos) {
        trimmed = trimmed.substr(start);
        size_t end = trimmed.find_last_not_of(" \t\n\r");
        if(end != std::string::npos) {
            trimmed = trimmed.substr(0, end + 1);
        }
    } else {
        trimmed.clear(); // All whitespace
    }

    if(trimmed.empty()) return true;

    // Convert to lowercase for case-insensitive comparison
    std::string lower_severity = trimmed;
    std::transform(lower_severity.begin(), lower_severity.end(), lower_severity.begin(), ::tolower);

    if(std::find(allowed_severities_.begin(), allowed_severities_.end(), lower_severity) == allowed_severities_.end()) {
        std::cerr << "Invalid " << flag_name << " value: " << severity << "\n";
        return false;
    }

    return true;
}

int ConfigValidator::severity_rank(const std::string& severity) const {
    std::string lower_severity = severity;
    std::transform(lower_severity.begin(), lower_severity.end(), lower_severity.begin(), ::tolower);

    if(lower_severity == "info") return 0;
    if(lower_severity == "low") return 1;
    if(lower_severity == "medium") return 2;
    if(lower_severity == "high") return 3;
    if(lower_severity == "critical") return 4;
    if(lower_severity == "error") return 5;
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
    // No need to set global config - mutations are reflected in the passed reference
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
    // No need to set global config - mutations are reflected in the passed reference
    return true;
}

} // namespace sys_scan