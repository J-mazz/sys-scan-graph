#pragma once

#include "core/Config.h"
#include "core/RuleEngine.h"
#include <string>

namespace sys_scan {

class RuleEngineInitializer {
public:
    RuleEngineInitializer() = default;
    ~RuleEngineInitializer() = default;

    // Initialize rule engine if enabled
    bool initialize(const Config& cfg);

private:
    bool validate_rules_directory(const std::string& path) const;
    bool check_legacy_rules() const;
};

} // namespace sys_scan