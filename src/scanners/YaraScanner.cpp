// ==============================================================================

#include "YaraScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>

// Minimal optional YARA integration placeholder (no libyara dependency yet)
// Strategy: look for simple substring signatures defined in external files (pseudo-YARA) to avoid heavy dep now.
// Each rule file: one pattern per line (ignoring empty/#). When real YARA added, this module will wrap libyara.

namespace fs = std::filesystem;
namespace sys_scan {

// Supported rule file extensions
const std::vector<std::string> RULE_EXTENSIONS = {".yar", ".yara", ".sig"};

// Default scan roots (conservative) - similar to world writable scan roots + /bin
const std::vector<std::string> DEFAULT_SCAN_ROOTS = {"/usr/bin", "/bin", "/usr/local/bin"};

// Helper function to check if file extension is supported for rules
bool is_rule_file_extension(const fs::path& path) {
    std::string ext = path.extension().string();
    return std::find(RULE_EXTENSIONS.begin(), RULE_EXTENSIONS.end(), ext) != RULE_EXTENSIONS.end();
}

// Load patterns from rule files in the specified directory
std::vector<std::string> load_patterns(const std::string& dir) {
    std::vector<std::string> patterns;

    if (dir.empty()) return patterns;

    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) {
        return patterns;
    }

    for (const auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) break;

        if (!entry.is_regular_file()) continue;
        if (!is_rule_file_extension(entry.path())) continue;

        std::ifstream ifs(entry.path());
        if (!ifs) continue;

        std::string line;
        while (std::getline(ifs, line)) {
            // Skip empty lines and comments
            if (line.empty() || line[0] == '#') continue;

            // Limit pattern length to prevent excessive memory usage
            if (line.size() > 4096) {
                line.resize(4096);
            }

            // Skip empty patterns after trimming
            if (line.empty()) continue;

            patterns.push_back(line);
        }
    }

    return patterns;
}

// Scan a single file for patterns
std::vector<std::string> scan_file_for_patterns(const fs::path& file_path, const std::vector<std::string>& patterns) {
    std::vector<std::string> matches;

    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) return matches;

    // Read first 8KB of file content for pattern matching
    std::string content;
    content.resize(8192);
    ifs.read(&content[0], content.size());
    content.resize(ifs.gcount());

    if (content.empty()) return matches;

    // Check each pattern against the content
    for (const auto& pattern : patterns) {
        if (content.find(pattern) != std::string::npos) {
            matches.push_back(pattern);
        }
    }

    return matches;
}

// Scan a directory tree for pattern matches
void scan_directory(const std::string& root_path,
                   const std::vector<std::string>& patterns,
                   ScanContext& context,
                   size_t& files_scanned,
                   size_t& matches_emitted,
                   size_t file_limit,
                   size_t match_limit) {

    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root_path, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator();
         ++it) {

        if (ec) break;

        if (!it->is_regular_file(ec)) continue;

        if (files_scanned++ > file_limit) return;

        auto file_path = it->path();
        auto matched_patterns = scan_file_for_patterns(file_path, patterns);

        for (const auto& pattern : matched_patterns) {
            if (matches_emitted >= match_limit) return;

            Finding f;
            f.id = file_path.string() + ":yara:" + pattern.substr(0, 16);
            f.title = "Pseudo-YARA pattern match";
            f.severity = Severity::Medium;
            f.description = "Pattern found in file prefix";
            f.metadata["pattern"] = pattern;
            f.metadata["path"] = file_path.string();

            context.report.add_finding("yara", std::move(f));
            matches_emitted++;
        }
    }
}

void YaraScanner::scan(ScanContext& context) {
    const auto& cfg = context.config;

    // Determine YARA rules directory
    std::string yara_dir = cfg.rules_dir.empty() ? std::string() : (cfg.rules_dir + "/yara");

    // Load patterns from rule files
    auto patterns = load_patterns(yara_dir);
    if (patterns.empty()) return; // Nothing to do if no patterns loaded

    // Use configurable scan roots, fallback to defaults
    std::vector<std::string> scan_roots;
    if (!cfg.yara_scan_roots.empty()) {
        scan_roots = cfg.yara_scan_roots;
    } else {
        scan_roots = DEFAULT_SCAN_ROOTS;
    }

    // Limits to control runtime and resource usage
    size_t file_limit = 2000;
    size_t match_limit = 200;
    size_t files_scanned = 0;
    size_t matches_emitted = 0;

    // Scan each root directory
    for (const auto& root : scan_roots) {
        std::error_code ec;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            continue; // Skip non-existent or non-directory roots
        }

        scan_directory(root, patterns, context, files_scanned, matches_emitted, file_limit, match_limit);

        if (files_scanned > file_limit || matches_emitted >= match_limit) {
            break; // Reached limits
        }
    }
}

}