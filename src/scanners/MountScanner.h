// ==============================================================================

#pragma once
#include "../core/Scanner.h"
#include <vector>
#include <sstream>

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class MountScanner : public Scanner {
public:
    std::string name() const override { return "mounts"; }
    std::string description() const override { return "Checks mount options and surfaces risky configurations"; }
    void scan(ScanContext& context) override;
    void scan(ScanContext& context, const std::string& mounts_file); // Test helper

    // Test helper function to check mount options
    static bool has_mount_option(const std::string& opts, const std::string& key) {
        // Check for malformed options (leading/trailing commas or empty options)
        if (opts.empty() || opts.front() == ',' || opts.back() == ',' || opts.find(",,") != std::string::npos) {
            return false;
        }
        
        std::istringstream iss(opts);
        std::string option;
        while (std::getline(iss, option, ',')) {
            if (option.empty()) return false; // Empty option is malformed
            if (option == key) return true;
        }
        return false;
    }
};

}
