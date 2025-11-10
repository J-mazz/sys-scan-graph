


#include "../core/Scanner.h"
#include <string>
#include <vector>
#include <utility>
#include <optional>

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;
struct Config;

class IntegrityScanner : public Scanner {
public:
    std::string name() const override { return "integrity"; }
    std::string description() const override { return "Package & system integrity verification"; }
    void scan(ScanContext& context) override;

    // Public test methods to exercise protected functions for coverage
    std::pair<size_t, size_t> test_check_ima_measurements() { return check_ima_measurements(); }
    std::optional<std::string> test_compute_file_hash(const std::string& path) { return compute_file_hash(path); }
protected:
    // Allow tests to override these to inject controlled behavior
    virtual std::string run_cmd_capture(const std::vector<std::string>& args);
    virtual std::pair<size_t, size_t> check_ima_measurements();
    virtual std::optional<std::string> compute_file_hash(const std::string& path);

    // Package verification helpers that use the above hooks
    struct PackageVerificationResult;
    PackageVerificationResult verify_packages_dpkg(const Config& cfg);
    PackageVerificationResult verify_packages_rpm(const Config& cfg);
};
}
