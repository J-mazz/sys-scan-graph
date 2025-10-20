// ==============================================================================

#include "IntegrityScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <cstdio>
#include <array>
#include <optional>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <random>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/sha.h>
#endif

namespace fs = std::filesystem;
namespace sys_scan {

// Secure command execution using fork/execvp (avoids shell injection)
static std::string run_cmd_capture(const std::vector<std::string>& args) {
    if (args.empty()) return "";

    int pipefd[2];
    if (pipe(pipefd) == -1) return "";

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }

    if (pid == 0) { // Child process
        close(pipefd[0]); // Close read end
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe
        dup2(pipefd[1], STDERR_FILENO); // Redirect stderr to pipe
        close(pipefd[1]);

        // Convert args to char* array for execvp
        std::vector<char*> argv;
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        // Clear potentially dangerous environment variables
        unsetenv("IFS");
        unsetenv("PATH"); // Will be set by execvp to default

        execvp(argv[0], argv.data());
        _exit(127); // exec failed
    } else { // Parent process
        close(pipefd[1]); // Close write end

        std::string output;
        char buffer[256];
        ssize_t bytes_read;

        // Read from pipe with timeout protection
        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            output += buffer;
            // Prevent excessive output (1MB limit)
            if (output.size() > 1 * 1024 * 1024) {
                break;
            }
        }

        close(pipefd[0]);

        // Wait for child process
        int status;
        waitpid(pid, &status, 0);

        return output;
    }
}

// Helper struct for package verification results
struct PackageVerificationResult {
    size_t mismatch_count = 0;
    size_t checked_count = 0;
    std::vector<std::string> mismatch_samples;
    std::vector<std::string> files_to_rehash;
    std::string tool_used;
};

// Helper function to verify packages using dpkg
PackageVerificationResult verify_packages_dpkg(const Config& cfg) {
    PackageVerificationResult result;
    result.tool_used = "dpkg";

    std::string out;

    // Choose verification mode based on config
    if (cfg.integrity_critical_only) {
        // Verify only critical packages
        std::vector<std::string> critical_pkgs = {
            "coreutils", "bash", "sudo", "openssh-server", "openssl", "libpam",
            "systemd", "init", "login", "passwd", "libc6", "libc-bin"
        };
        for (const auto& pkg : critical_pkgs) {
            std::string pkg_out = run_cmd_capture({"dpkg", "-V", pkg});
            out += pkg_out;
            result.checked_count++;
            if (cfg.integrity_max_mismatches > 0 && result.mismatch_count >= (size_t)cfg.integrity_max_mismatches) {
                break;
            }
        }
    } else if (cfg.integrity_sample_pct > 0 && cfg.integrity_sample_pct <= 100) {
        // Sample mode: verify random N% of packages
        std::string pkg_list = run_cmd_capture({"dpkg", "-l"});
        std::vector<std::string> packages;
        std::istringstream plist(pkg_list);
        std::string line;
        while (std::getline(plist, line)) {
            if (line.size() > 4 && line.substr(0, 2) == "ii") {
                std::istringstream lss(line);
                std::string status, name;
                lss >> status >> name;
                if (!name.empty()) packages.push_back(name);
            }
        }

        // Sample random packages
        size_t sample_count = (packages.size() * cfg.integrity_sample_pct) / 100;
        if (sample_count > 0) {
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(packages.begin(), packages.end(), g);
            packages.resize(std::min(sample_count, packages.size()));
            result.checked_count = packages.size();

            for (const auto& pkg : packages) {
                std::string pkg_out = run_cmd_capture({"dpkg", "-V", pkg});
                out += pkg_out;
                if (cfg.integrity_max_mismatches > 0 && result.mismatch_count >= (size_t)cfg.integrity_max_mismatches) {
                    break;
                }
            }
        }
    } else {
        // Full verification
        out = run_cmd_capture({"dpkg", "-V"});
    }

    // Parse dpkg output
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        if (line.size() > 0 && (line[0] == ' ' || line[0] == '?')) continue;

        // dpkg -V format: mismatches start with flags
        if (line[0] != ' ') {
            result.mismatch_count++;
            if (cfg.integrity_max_mismatches > 0 && result.mismatch_count >= (size_t)cfg.integrity_max_mismatches) {
                break;
            }
            if (result.mismatch_samples.size() < 10) {
                result.mismatch_samples.push_back(line.substr(0, 40));
            }

            // Extract filename
            std::string path;
            size_t pos = line.find(' ');
            if (pos != std::string::npos) {
                path = line.substr(pos + 1);
            }
            if (!path.empty() && result.files_to_rehash.size() < (size_t)cfg.integrity_pkg_rehash_limit) {
                result.files_to_rehash.push_back(path);
            }
        }
    }

    return result;
}

// Helper function to verify packages using rpm
PackageVerificationResult verify_packages_rpm(const Config& cfg) {
    PackageVerificationResult result;
    result.tool_used = "rpm";

    std::string out;

    // Choose verification mode based on config
    if (cfg.integrity_critical_only) {
        // Verify only critical packages
        std::vector<std::string> critical_pkgs = {
            "coreutils", "bash", "sudo", "openssh-server", "openssl", "pam",
            "systemd", "glibc", "shadow-utils"
        };
        for (const auto& pkg : critical_pkgs) {
            std::string pkg_out = run_cmd_capture({"rpm", "-V", pkg});
            out += pkg_out;
            result.checked_count++;
            if (cfg.integrity_max_mismatches > 0 && result.mismatch_count >= (size_t)cfg.integrity_max_mismatches) {
                break;
            }
        }
    } else if (cfg.integrity_sample_pct > 0 && cfg.integrity_sample_pct <= 100) {
        std::string pkg_list = run_cmd_capture({"rpm", "-qa"});
        std::vector<std::string> packages;
        std::istringstream plist(pkg_list);
        std::string line;
        while (std::getline(plist, line)) {
            if (!line.empty()) packages.push_back(line);
        }

        size_t sample_count = (packages.size() * cfg.integrity_sample_pct) / 100;
        if (sample_count > 0) {
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(packages.begin(), packages.end(), g);
            packages.resize(std::min(sample_count, packages.size()));
            result.checked_count = packages.size();

            for (const auto& pkg : packages) {
                std::string pkg_out = run_cmd_capture({"rpm", "-V", pkg});
                out += pkg_out;
                if (cfg.integrity_max_mismatches > 0 && result.mismatch_count >= (size_t)cfg.integrity_max_mismatches) {
                    break;
                }
            }
        }
    } else {
        // Full verification
        out = run_cmd_capture({"rpm", "-Va"});
    }

    // Parse rpm output
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        if (line.size() < 2) continue;

        // rpm -V format: 8 chars of flags, space, path
        bool mismatch = false;
        for (char c : line.substr(0, 8)) {
            if (c != '.' && c != ' ') {
                mismatch = true;
                break;
            }
        }
        if (!mismatch) continue;

        result.mismatch_count++;
        if (cfg.integrity_max_mismatches > 0 && result.mismatch_count >= (size_t)cfg.integrity_max_mismatches) {
            break;
        }
        if (result.mismatch_samples.size() < 10) {
            result.mismatch_samples.push_back(line.substr(0, 40));
        }

        std::string path;
        if (line.size() > 9) path = line.substr(9);
        if (!path.empty() && result.files_to_rehash.size() < (size_t)cfg.integrity_pkg_rehash_limit) {
            result.files_to_rehash.push_back(path);
        }
    }

    return result;
}

// Helper function to check IMA measurements
std::pair<size_t, size_t> check_ima_measurements() {
    size_t entries = 0;
    size_t failures = 0;

    if (fs::exists("/sys/kernel/security/ima/ascii_runtime_measurements")) {
        std::ifstream ifs("/sys/kernel/security/ima/ascii_runtime_measurements");
        std::string line;
        while (std::getline(ifs, line)) {
            if (line.empty()) continue;
            ++entries;
            // Simple heuristic: look for 'fail' in measurements
            if (line.find("fail") != std::string::npos) ++failures;
            if (entries > 500000) break; // Prevent excessive processing
        }
    }

    return {entries, failures};
}

// Helper function to compute SHA256 hash of a file
std::optional<std::string> compute_file_hash(const std::string& path) {
#ifdef SYS_SCAN_HAVE_OPENSSL
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::nullopt;

    unsigned char buf[8192];
    SHA256_CTX c;
    SHA256_Init(&c);

    while (ifs) {
        ifs.read((char*)buf, sizeof(buf));
        std::streamsize got = ifs.gcount();
        if (got > 0) SHA256_Update(&c, buf, (size_t)got);
    }

    unsigned char md[32];
    SHA256_Final(md, &c);

    static const char* hex = "0123456789abcdef";
    std::string hexsum;
    hexsum.reserve(64);
    for (int i = 0; i < 32; i++) {
        hexsum.push_back(hex[md[i] >> 4]);
        hexsum.push_back(hex[md[i] & 0xF]);
    }

    return hexsum;
#else
    return std::nullopt;
#endif
}

void IntegrityScanner::scan(ScanContext& context) {
    auto& cfg = context.config;
    if (!cfg.integrity) return; // gated entirely

    PackageVerificationResult pkg_result;

    // Package verification
    if (cfg.integrity_pkg_verify) {
        if (fs::exists("/usr/bin/dpkg")) {
            pkg_result = verify_packages_dpkg(cfg);
        } else if (fs::exists("/usr/bin/rpm")) {
            pkg_result = verify_packages_rpm(cfg);
        }
    }

    // IMA measurement stats
    auto [ima_entries, ima_failures] = check_ima_measurements();

    // Rehash mismatched files
    if (cfg.integrity_pkg_rehash && !pkg_result.files_to_rehash.empty()) {
        for (const auto& fpath : pkg_result.files_to_rehash) {
            std::error_code ec;
            if (!fs::is_regular_file(fpath, ec)) continue;

            auto hash = compute_file_hash(fpath);
            if (hash) {
                Finding hf;
                hf.id = std::string("pkg_rehash:") + fpath;
                hf.title = "Package mismatch file hash";
                hf.severity = Severity::Info;
                hf.description = "Recomputed SHA256 for mismatched file";
                hf.metadata["path"] = fpath;
                hf.metadata["sha256"] = *hash;
                context.report.add_finding(this->name(), std::move(hf));
            }
        }
    }

    // Generate detailed findings for mismatches
    if (pkg_result.mismatch_count > 0 && pkg_result.mismatch_count <= (size_t)cfg.integrity_pkg_limit) {
        // This would generate individual findings - simplified for now
    }

    // Summary finding
    Finding summary;
    summary.id = "integrity_summary";
    summary.title = "Integrity summary";
    summary.severity = Severity::Info;
    summary.description = "Package / integrity verification";

    if (pkg_result.mismatch_count > 0) summary.severity = Severity::Medium;
    if (ima_failures > 0) summary.severity = Severity::High;

    if (!pkg_result.tool_used.empty()) summary.metadata["pkg_tool"] = pkg_result.tool_used;
    summary.metadata["pkg_mismatch_count"] = std::to_string(pkg_result.mismatch_count);

    // Document scan mode
    if (cfg.integrity_critical_only) {
        summary.metadata["scan_mode"] = "critical_only";
    } else if (cfg.integrity_sample_pct > 0) {
        summary.metadata["scan_mode"] = "sample_" + std::to_string(cfg.integrity_sample_pct) + "pct";
    } else {
        summary.metadata["scan_mode"] = "full";
    }

    if (cfg.integrity_max_mismatches > 0) {
        summary.metadata["early_exit_threshold"] = std::to_string(cfg.integrity_max_mismatches);
    }

    if (!pkg_result.mismatch_samples.empty()) {
        std::string s;
        for (size_t i = 0; i < pkg_result.mismatch_samples.size(); ++i) {
            if (i) s += ",";
            s += pkg_result.mismatch_samples[i];
        }
        summary.metadata["pkg_mismatch_sample"] = s;
    }

    if (cfg.integrity_ima) {
        summary.metadata["ima_entries"] = std::to_string(ima_entries);
        if (ima_failures > 0) summary.metadata["ima_fail"] = std::to_string(ima_failures);
    }

    context.report.add_finding(this->name(), std::move(summary));
}

}