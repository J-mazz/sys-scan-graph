#include "ModuleScanner.h"
#include "../core/Report.h"
#include "../core/ScanContext.h"
#include <fstream>
#include <sstream>
#include "../core/Config.h"
#include <sys/utsname.h>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <cstring>
#include <cstdio>
#include <memory>
#include <cstdint>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "ModuleUtils.h"
#include "ModuleHelpers.h"
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace sys_scan {

// Static configuration for better performance
static const size_t MAX_MODULES = 10000;
static const size_t SAMPLE_LIMIT = 10;
static const size_t OOT_SAMPLE_LIMIT = 5;
static const size_t UNSIGNED_SAMPLE_LIMIT = 5;
static const size_t HIDDEN_SAMPLE_LIMIT = 5;
static const size_t MISSING_FILE_SAMPLE_LIMIT = 5;
static const size_t SYSFS_ONLY_SAMPLE_LIMIT = 5;
static const size_t WX_SECTION_SAMPLE_LIMIT = 5;
static const size_t LARGE_TEXT_SAMPLE_LIMIT = 5;
static const size_t SUSPICIOUS_SECTION_SAMPLE_LIMIT = 5;

// Pre-allocated buffers for file reading
static const size_t READ_BUFFER_SIZE = 8192;
static char read_buffer[READ_BUFFER_SIZE];

// Optimized file reading function using POSIX I/O
static bool read_file_posix(const char* path, std::string& content) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return false;

    content.clear();
    content.reserve(READ_BUFFER_SIZE); // Pre-allocate

    ssize_t bytes_read;
    while ((bytes_read = read(fd, read_buffer, READ_BUFFER_SIZE)) > 0) {
        content.append(read_buffer, bytes_read);
    }

    close(fd);
    return bytes_read >= 0;
}

// Optimized line-by-line file reading
static bool read_lines_posix(const char* path, std::vector<std::string>& lines) {
    std::string content;
    if (!read_file_posix(path, content)) return false;

    lines.clear();
    lines.reserve(1000); // Pre-allocate reasonable capacity

    size_t start = 0;
    size_t end = content.find('\n');
    while (end != std::string::npos) {
        if (end > start) {
            lines.emplace_back(content.substr(start, end - start));
        }
        start = end + 1;
        end = content.find('\n', start);
    }
    if (start < content.size()) {
        lines.emplace_back(content.substr(start));
    }

    return true;
}

// Fast string splitting for module lines
static bool parse_module_line(const std::string& line, std::string& name) {
    size_t space_pos = line.find(' ');
    if (space_pos == std::string::npos) return false;

    name.assign(line.data(), space_pos);
    return !name.empty();
}

// Fast path stripping function
static std::string strip_extension(std::string s) {
    static const char* extensions[] = {".ko", ".ko.xz", ".ko.gz"};
    for (const char* ext : extensions) {
        size_t ext_len = strlen(ext);
        if (s.size() >= ext_len && memcmp(s.data() + s.size() - ext_len, ext, ext_len) == 0) {
            s.resize(s.size() - ext_len);
            break;
        }
    }
    return s;
}

// Pre-allocated data structures
struct ModuleScanSummary {
    size_t total = 0;
    size_t likely_out_of_tree = 0;
    size_t unsigned_count = 0;
    size_t compressed_count = 0;
    size_t compressed_scanned = 0;
    size_t compressed_unsigned = 0;
    size_t missing_file_count = 0;
    size_t hidden_in_proc_only_count = 0;
    size_t sysfs_only_count = 0;
    size_t wx_section_modules = 0;
    size_t large_text_section_modules = 0;
    size_t suspicious_name_section_modules = 0;
};

struct ModuleInfo {
    std::string name;
    std::string path;
    std::string full_path;
    bool is_oot;
    bool is_unsigned;
    bool is_missing_file;
    bool is_hidden;
};

class ModuleScanData {
private:
    std::unordered_map<std::string, std::string> name_to_path;
    std::unordered_set<std::string> builtin_modules;
    std::unordered_set<std::string> sysfs_modules;
    std::unordered_set<std::string> proc_modules_set;

    // Pre-allocate vectors with reasonable capacities
    std::vector<std::string> sample;
    std::vector<std::string> oot_sample;
    std::vector<std::string> unsigned_sample;
    std::vector<std::string> compressed_unsigned_sample;
    std::vector<std::string> missing_file_sample;
    std::vector<std::string> hidden_sample;
    std::vector<std::string> sysfs_only_sample;
    std::vector<std::string> wx_section_sample;
    std::vector<std::string> large_text_section_sample;
    std::vector<std::string> suspicious_section_name_sample;

public:
    ModuleScanData() {
        name_to_path.reserve(2000);
        builtin_modules.reserve(1000);
        sysfs_modules.reserve(1000);
        proc_modules_set.reserve(1000);

        sample.reserve(SAMPLE_LIMIT);
        oot_sample.reserve(OOT_SAMPLE_LIMIT);
        unsigned_sample.reserve(UNSIGNED_SAMPLE_LIMIT);
        compressed_unsigned_sample.reserve(UNSIGNED_SAMPLE_LIMIT);
        missing_file_sample.reserve(MISSING_FILE_SAMPLE_LIMIT);
        hidden_sample.reserve(HIDDEN_SAMPLE_LIMIT);
        sysfs_only_sample.reserve(SYSFS_ONLY_SAMPLE_LIMIT);
        wx_section_sample.reserve(WX_SECTION_SAMPLE_LIMIT);
        large_text_section_sample.reserve(LARGE_TEXT_SAMPLE_LIMIT);
        suspicious_section_name_sample.reserve(SUSPICIOUS_SECTION_SAMPLE_LIMIT);
    }

    // Module path mapping
    void add_module_path(const std::string& name, const std::string& path) {
        name_to_path[name] = path;
    }

    std::string get_module_path(const std::string& name) const {
        auto it = name_to_path.find(name);
        return (it != name_to_path.end()) ? it->second : std::string();
    }

    // Built-in modules
    void add_builtin_module(const std::string& name) {
        builtin_modules.insert(name);
    }

    bool is_builtin_module(const std::string& name) const {
        return builtin_modules.find(name) != builtin_modules.end();
    }

    // Sysfs modules
    void add_sysfs_module(const std::string& name) {
        sysfs_modules.insert(name);
    }

    bool is_sysfs_module(const std::string& name) const {
        return sysfs_modules.find(name) != sysfs_modules.end();
    }

    // Proc modules
    void add_proc_module(const std::string& name) {
        proc_modules_set.insert(name);
    }

    bool is_proc_module(const std::string& name) const {
        return proc_modules_set.find(name) != proc_modules_set.end();
    }

    // Sample collections
    void add_sample(const std::string& name) {
        if (sample.size() < SAMPLE_LIMIT) {
            sample.push_back(name);
        }
    }

    void add_oot_sample(const std::string& name) {
        if (oot_sample.size() < OOT_SAMPLE_LIMIT) {
            oot_sample.push_back(name);
        }
    }

    void add_unsigned_sample(const std::string& name) {
        if (unsigned_sample.size() < UNSIGNED_SAMPLE_LIMIT) {
            unsigned_sample.push_back(name);
        }
    }

    void add_compressed_unsigned_sample(const std::string& name) {
        if (compressed_unsigned_sample.size() < UNSIGNED_SAMPLE_LIMIT) {
            compressed_unsigned_sample.push_back(name);
        }
    }

    void add_missing_file_sample(const std::string& name) {
        if (missing_file_sample.size() < MISSING_FILE_SAMPLE_LIMIT) {
            missing_file_sample.push_back(name);
        }
    }

    void add_hidden_sample(const std::string& name) {
        if (hidden_sample.size() < HIDDEN_SAMPLE_LIMIT) {
            hidden_sample.push_back(name);
        }
    }

    void add_sysfs_only_sample(const std::string& name) {
        if (sysfs_only_sample.size() < SYSFS_ONLY_SAMPLE_LIMIT) {
            sysfs_only_sample.push_back(name);
        }
    }

    void add_wx_section_sample(const std::string& name) {
        if (wx_section_sample.size() < WX_SECTION_SAMPLE_LIMIT) {
            wx_section_sample.push_back(name);
        }
    }

    void add_large_text_section_sample(const std::string& name) {
        if (large_text_section_sample.size() < LARGE_TEXT_SAMPLE_LIMIT) {
            large_text_section_sample.push_back(name);
        }
    }

    void add_suspicious_section_name_sample(const std::string& name) {
        if (suspicious_section_name_sample.size() < SUSPICIOUS_SECTION_SAMPLE_LIMIT) {
            suspicious_section_name_sample.push_back(name);
        }
    }

    // Accessors for backward compatibility (will be removed in subsequent refactorings)
    const std::unordered_map<std::string, std::string>& get_name_to_path() const { return name_to_path; }
    const std::unordered_set<std::string>& get_builtin_modules() const { return builtin_modules; }
    const std::unordered_set<std::string>& get_sysfs_modules() const { return sysfs_modules; }
    const std::unordered_set<std::string>& get_proc_modules_set() const { return proc_modules_set; }
    const std::vector<std::string>& get_sample() const { return sample; }
    const std::vector<std::string>& get_oot_sample() const { return oot_sample; }
    const std::vector<std::string>& get_unsigned_sample() const { return unsigned_sample; }
    const std::vector<std::string>& get_compressed_unsigned_sample() const { return compressed_unsigned_sample; }
    const std::vector<std::string>& get_missing_file_sample() const { return missing_file_sample; }
    const std::vector<std::string>& get_hidden_sample() const { return hidden_sample; }
    const std::vector<std::string>& get_sysfs_only_sample() const { return sysfs_only_sample; }
    const std::vector<std::string>& get_wx_section_sample() const { return wx_section_sample; }
    const std::vector<std::string>& get_large_text_section_sample() const { return large_text_section_sample; }
    const std::vector<std::string>& get_suspicious_section_name_sample() const { return suspicious_section_name_sample; }
};

// Forward declarations for functions used in build_module_info
void analyze_module_signature(const std::string& path, const std::string& full_path,
                            bool& unsigned_mod, bool& missing_file, const std::string& scanner_name,
                            ScanContext& context);
bool is_out_of_tree_module(const std::string& path);
void detect_hidden_module(const std::string& name, const ModuleScanData& data, bool& hidden_proc_only);

ModuleInfo build_module_info(const std::string& module_name, const ModuleScanData& data,
                           const std::string& lib_modules_base, ScanContext& context,
                           const std::string& scanner_name) {
    ModuleInfo info;
    info.name = module_name;
    info.path = data.get_module_path(module_name);

    if (!info.path.empty()) {
        info.full_path = lib_modules_base + info.path;
        analyze_module_signature(info.path, info.full_path, info.is_unsigned, info.is_missing_file, scanner_name, context);
    }

    info.is_oot = (!info.path.empty() && is_out_of_tree_module(info.path));
    detect_hidden_module(info.name, data, info.is_hidden);

    return info;
}

// Helper functions for build_summary_finding
Severity calculate_module_summary_severity(size_t likely_out_of_tree, size_t unsigned_count,
                                         size_t hidden_in_proc_only_count, size_t missing_file_count,
                                         size_t sysfs_only_count);

void add_basic_metadata(Finding& f, size_t total, const ModuleScanData& data);

void add_sample_metadata(Finding& f, const std::string& key, const std::vector<std::string>& samples);

void add_taint_metadata(Finding& f, const std::string& test_root);

void add_kallsyms_metadata(Finding& f, const std::string& test_root);

Severity calculate_module_summary_severity(size_t likely_out_of_tree, size_t unsigned_count,
                                         size_t hidden_in_proc_only_count, size_t missing_file_count,
                                         size_t sysfs_only_count) {
    if (unsigned_count > 0 || hidden_in_proc_only_count > 0 ||
        missing_file_count > 0 || sysfs_only_count > 0) {
        return Severity::High;
    }
    if (likely_out_of_tree > 0) {
        return Severity::Medium;
    }
    return Severity::Info;
}

void add_basic_metadata(Finding& f, size_t total, const ModuleScanData& data) {
    f.metadata["total"] = std::to_string(total);
    add_sample_metadata(f, "sample", data.get_sample());
}

void add_taint_metadata(Finding& f, const std::string& test_root) {
    std::string tainted_path = test_root.empty() ? "/proc/sys/kernel/tainted" : test_root + "/proc/sys/kernel/tainted";
    std::string tainted_content;
    if (read_file_posix(tainted_path.c_str(), tainted_content)) {
        // Remove trailing whitespace
        while (!tainted_content.empty() && (tainted_content.back() == '\n' || tainted_content.back() == ' ')) {
            tainted_content.pop_back();
        }
        if (!tainted_content.empty()) {
            f.metadata["taint_value"] = tainted_content;
            // Decode bits using lookup table
            unsigned long val = std::strtoul(tainted_content.c_str(), nullptr, 10);
            if (val) {
                static const std::map<unsigned long, std::string> taint_bit_names = {
                    {0, "PROPRIETARY_MODULE"}, {1, "FORCED_MODULE"}, {2, "UNSAFE_SMP"},
                    {3, "FORCED_RMMOD"}, {4, "MACHINE_CHECK"}, {5, "BAD_PAGE"},
                    {6, "USER"}, {7, "DIE"}, {8, "OVERRIDDEN_ACPI_TABLE"},
                    {9, "WARN"}, {10, "OOPS"}, {11, "HARDWARE_INCOMPAT"},
                    {12, "SOFTWARE_INCOMPAT"}, {13, "FIRMWARE_WORKAROUND"},
                    {14, "CRAP"}, {15, "FIRMWARE_BUG"}, {16, "RANDSTRUCT"},
                    {17, "PANIC"}
                };
                std::string flags;
                for (const auto& [bit, name] : taint_bit_names) {
                    if (val & (1UL << bit)) {
                        if (!flags.empty()) flags += ",";
                        flags += name;
                    }
                }
                if (!flags.empty()) f.metadata["taint_flags"] = std::move(flags);
            }
        }
    }
}

void add_kallsyms_metadata(Finding& f, const std::string& test_root) {
    std::string kallsyms_path = test_root.empty() ? "/proc/kallsyms" : test_root + "/proc/kallsyms";
    std::string kallsyms_content;
    if (read_file_posix(kallsyms_path.c_str(), kallsyms_content)) {
        size_t lines = 0;
        size_t limited = 0;
        size_t start = 0;
        size_t end = kallsyms_content.find('\n');

        // Sample first 5000 lines for performance
        while (end != std::string::npos && lines < 5000) {
            ++lines;
            if (end > start) {
                const char* line_start = kallsyms_content.data() + start;
                size_t line_len = end - start;
                if (line_len > 1 && line_start[0] == '0' && line_start[1] == '0') {
                    ++limited;
                }
            }
            start = end + 1;
            end = kallsyms_content.find('\n', start);
        }

        f.metadata["kallsyms_readable"] = "yes";
        f.metadata["kallsyms_sampled"] = std::to_string(lines);
        if (lines < 100) f.metadata["kallsyms_low"] = "true";
        if (limited > 0 && limited == lines) f.metadata["kallsyms_all_zero"] = "true";
    } else {
        f.metadata["kallsyms_readable"] = "no";
    }
}

void add_sample_metadata(Finding& f, const std::string& key, const std::vector<std::string>& samples) {
    f.metadata[key + "_count"] = std::to_string(samples.size());
    if (!samples.empty() && samples.size() <= 10) {  // Only add list if small number
        std::string sample_list = samples[0];
        for (size_t i = 1; i < samples.size(); ++i) {
            sample_list += "," + samples[i];
        }
        f.metadata[key + "_list"] = sample_list;
    }
}

// Helper to add details about a specific anomaly to a Finding
static void add_anomaly_details(Finding& f, const std::string& key, const std::string& description) {
    f.metadata[key] = "true";
    if (f.severity < Severity::High) f.severity = Severity::High;
    f.description = description;
}

// Helper specifically for the complex ELF heuristics
static void check_elf_heuristics(Finding& f, const ModuleInfo& module, ModuleScanData& data, ModuleScanSummary& summary) {
    if (module.full_path.empty() || module.is_missing_file) {
        return; // Guard clause
    }

    auto sections = ElfModuleHeuristics::parse_sections(module.full_path);
    if (sections.empty()) {
        return; // Guard clause
    }

    if (ElfModuleHeuristics::has_wx_section(sections)) {
        f.metadata["wx_section"] = "true";
        if (f.severity < Severity::High) f.severity = Severity::High;
        ++summary.wx_section_modules;
        data.add_wx_section_sample(module.name);
    }

    if (ElfModuleHeuristics::has_large_text_section(sections)) {
        uint64_t text_size = 0;
        for (const auto& s : sections) {
            if (s.name == ".text") {
                text_size = s.size;
                break;
            }
        }
        f.metadata["large_text_section"] = std::to_string(text_size);
        if (f.severity < Severity::High) f.severity = Severity::High;
        ++summary.large_text_section_modules;
        data.add_large_text_section_sample(module.name);
    }

    if (ElfModuleHeuristics::has_suspicious_section_name(sections)) {
        for (const auto& s : sections) {
            if (ElfModuleHeuristics::has_suspicious_section_name({s})) {
                f.metadata["suspicious_section_name"] = s.name;
                if (f.severity < Severity::High) f.severity = Severity::High;
                ++summary.suspicious_name_section_modules;
                data.add_suspicious_section_name_sample(module.name);
                break;
            }
        }
    }
}

void build_summary_finding(ScanContext& context, const std::string& scanner_name,
                           const ModuleScanData& data, const ModuleScanSummary& summary,
                           const std::string& test_root) {
    Finding f;
    f.id = "module_summary";
    f.title = "Kernel Module Summary";
    f.severity = calculate_module_summary_severity(summary.likely_out_of_tree, summary.unsigned_count,
                                                  summary.hidden_in_proc_only_count, summary.missing_file_count,
                                                  summary.sysfs_only_count);
    f.description = "Summary of loaded kernel modules and potential security issues";

    // Add basic metadata
    add_basic_metadata(f, summary.total, data);

    // Add detailed counts
    f.metadata["likely_out_of_tree"] = std::to_string(summary.likely_out_of_tree);
    f.metadata["unsigned"] = std::to_string(summary.unsigned_count);
    f.metadata["compressed"] = std::to_string(summary.compressed_count);
    f.metadata["compressed_scanned"] = std::to_string(summary.compressed_scanned);
    f.metadata["compressed_unsigned"] = std::to_string(summary.compressed_unsigned);
    f.metadata["missing_file"] = std::to_string(summary.missing_file_count);
    f.metadata["hidden_proc_only"] = std::to_string(summary.hidden_in_proc_only_count);
    f.metadata["sysfs_only_count"] = std::to_string(summary.sysfs_only_count);
    f.metadata["wx_section"] = std::to_string(summary.wx_section_modules);
    f.metadata["large_text_section"] = std::to_string(summary.large_text_section_modules);
    f.metadata["suspicious_section_name"] = std::to_string(summary.suspicious_name_section_modules);

    // Add sample metadata for various categories
    add_sample_metadata(f, "oot", data.get_oot_sample());
    add_sample_metadata(f, "unsigned", data.get_unsigned_sample());
    add_sample_metadata(f, "compressed_unsigned", data.get_compressed_unsigned_sample());
    add_sample_metadata(f, "missing_file", data.get_missing_file_sample());
    add_sample_metadata(f, "hidden", data.get_hidden_sample());
    add_sample_metadata(f, "sysfs_only", data.get_sysfs_only_sample());
    add_sample_metadata(f, "wx_section", data.get_wx_section_sample());
    add_sample_metadata(f, "large_text_section", data.get_large_text_section_sample());
    add_sample_metadata(f, "suspicious_section_name", data.get_suspicious_section_name_sample());

    // Add system metadata
    add_taint_metadata(f, test_root);
    add_kallsyms_metadata(f, test_root);

    context.report.add_finding(scanner_name, std::move(f));
}

void setup_scan_paths(const std::string& kernel_release, std::string& modules_dep_path,
                     std::string& modules_builtin_path, std::string& lib_modules_base,
                     const std::string& test_root) {
    std::string base_path = test_root.empty() ? "" : test_root;
    modules_dep_path = base_path + "/lib/modules/" + kernel_release + "/modules.dep";
    modules_builtin_path = base_path + "/lib/modules/" + kernel_release + "/modules.builtin";
    lib_modules_base = base_path + "/lib/modules/" + kernel_release + "/";
}

void build_module_path_map(const std::string& modules_dep_path, ModuleScanData& data) {
    std::vector<std::string> dep_lines;
    if (read_lines_posix(modules_dep_path.c_str(), dep_lines)) {
        for (auto& line : dep_lines) {
            if (line.empty()) continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;

            std::string path = line.substr(0, colon);
            size_t slash = path.find_last_of('/');
            std::string fname = (slash == std::string::npos) ? path : path.substr(slash + 1);
            std::string base = strip_extension(std::move(fname));

            data.add_module_path(std::move(base), std::move(path));
        }
    }
}

void build_builtin_modules_set(const std::string& modules_builtin_path, ModuleScanData& data) {
    std::vector<std::string> builtin_lines;
    if (read_lines_posix(modules_builtin_path.c_str(), builtin_lines)) {
        for (auto& line : builtin_lines) {
            if (line.empty()) continue;
            size_t slash = line.find_last_of('/');
            std::string fname = (slash == std::string::npos) ? line : line.substr(slash + 1);
            std::string base = strip_extension(std::move(fname));
            data.add_builtin_module(std::move(base));
        }
    }
}

void collect_sysfs_modules(ModuleScanData& data, const std::string& test_root) {
    std::string sysfs_path = test_root.empty() ? "/sys/module" : test_root + "/sys/module";
    DIR* dir = opendir(sysfs_path.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                data.add_sysfs_module(entry->d_name);
            }
        }
        closedir(dir);
    }
}

bool read_proc_modules(std::vector<std::string>& proc_lines, const std::string& test_root) {
    std::string proc_path = test_root.empty() ? "/proc/modules" : test_root + "/proc/modules";
    return read_lines_posix(proc_path.c_str(), proc_lines);
}

void handle_simple_mode(ScanContext& context, const std::string& scanner_name, const std::vector<std::string>& proc_lines) {
    for (const auto& line : proc_lines) {
        std::string name;
        if (parse_module_line(line, name)) {
            Finding f;
            f.id = std::move(name);
            f.title = "Module " + f.id;
            f.severity = Severity::Info;
            f.description = "Loaded kernel module";
            context.report.add_finding(scanner_name, std::move(f));
        }
    }
}

bool is_out_of_tree_module(const std::string& path) {
    return path.find("extra/") != std::string::npos ||
           path.find("updates/") != std::string::npos ||
           path.find("dkms") != std::string::npos ||
           path.find("nvidia") != std::string::npos ||
           path.find("virtualbox") != std::string::npos ||
           path.find("vmware") != std::string::npos;
}

void analyze_module_signature(const std::string& path, const std::string& full_path,
                            bool& unsigned_mod, bool& missing_file, const std::string& scanner_name,
                            ScanContext& context) {
    unsigned_mod = false;
    missing_file = false;

    if (path.size() >= 3 && memcmp(path.data() + path.size() - 3, ".ko", 3) == 0) {
        // Uncompressed module
        unsigned_mod = SignatureAnalyzer::is_unsigned_module(full_path);
    } else if (CompressionUtils::is_compressed(path)) {
        std::string contents;
        if (path.size() >= 6 && memcmp(path.data() + path.size() - 6, ".ko.xz", 6) == 0) {
            contents = CompressionUtils::decompress_xz_bounded(full_path);
        } else {
            contents = CompressionUtils::decompress_gz_bounded(full_path);
        }

        if (contents.empty()) {
            context.report.add_warning(scanner_name, WarnCode::DecompressFail, path);
        } else {
            if (contents.find("Module signature appended") == std::string::npos) {
                unsigned_mod = true;
            }
        }
    }

    // File existence check using stat for better performance
    struct stat st;
    if (stat(full_path.c_str(), &st) != 0) {
        missing_file = true;
    }
}

void detect_hidden_module(const std::string& name, const ModuleScanData& data, bool& hidden_proc_only) {
    hidden_proc_only = (!data.is_sysfs_module(name) && !data.is_builtin_module(name));
}

void process_module_anomalies(ScanContext& context, const std::string& scanner_name,
                            const ModuleInfo& module, ModuleScanData& data,
                            ModuleScanSummary& summary) {
    // Guard clause: if there are no anomalies, do nothing.
    if (!module.is_oot && !module.is_unsigned && !module.is_missing_file && !module.is_hidden) {
        return;
    }

    Finding f(module.name, "Module anomaly: " + module.name, Severity::Medium, "Kernel module anomaly");

    // Add details for each specific anomaly
    if (module.is_unsigned) add_anomaly_details(f, "unsigned", "Unsigned kernel module detected");
    if (module.is_oot) add_anomaly_details(f, "out_of_tree", "Out-of-tree kernel module");
    if (module.is_missing_file) add_anomaly_details(f, "missing_file", "Module file missing on disk");
    if (module.is_hidden) add_anomaly_details(f, "hidden_sysfs", "Module in /proc but not /sys");

    // Perform the complex ELF check
    check_elf_heuristics(f, module, data, summary);

#ifdef SYS_SCAN_HAVE_OPENSSL
    if (context.config.modules_hash && !module.full_path.empty() && !module.is_missing_file) {
        std::string hash = SignatureAnalyzer::compute_sha256(module.full_path);
        if (!hash.empty()) {
            f.metadata["sha256"] = hash;
        }
    }
#endif

    if (!module.path.empty()) f.metadata["path"] = module.path;
    context.report.add_finding(scanner_name, std::move(f));
}

void process_modules_detailed(ScanContext& context, const std::string& scanner_name, ModuleScanData& data,
                            const std::vector<std::string>& proc_lines,
                            const std::string& lib_modules_base) {
    ModuleScanSummary summary;

    for (const auto& line : proc_lines) {
        std::string name;
        if (!parse_module_line(line, name)) continue;

        // Build the module info object
        ModuleInfo module = build_module_info(name, data, lib_modules_base, context, scanner_name);

        // Update summary counts based on module properties
        ++summary.total;
        data.add_sample(module.name);

        if (module.is_oot) {
            ++summary.likely_out_of_tree;
            data.add_oot_sample(module.name);
        }

        // Handle compression logic
        if (!module.path.empty() && CompressionUtils::is_compressed(module.path)) {
            ++summary.compressed_count;
            if (!module.is_unsigned) {
                ++summary.compressed_scanned;
            } else {
                ++summary.compressed_unsigned;
                data.add_compressed_unsigned_sample(module.name);
            }
        }

        if (module.is_unsigned) {
            ++summary.unsigned_count;
            data.add_unsigned_sample(module.name);
        }

        if (module.is_missing_file) {
            ++summary.missing_file_count;
            data.add_missing_file_sample(module.name);
        }

        if (module.is_hidden) {
            ++summary.hidden_in_proc_only_count;
            data.add_hidden_sample(module.name);
        }

        // Process anomalies if in anomalies-only mode
        if (context.config.modules_anomalies_only) {
            process_module_anomalies(context, scanner_name, module, data, summary);
        }
    }

    // Build proc modules set for sysfs-only detection
    for (const auto& line : proc_lines) {
        std::string name;
        if (parse_module_line(line, name)) {
            data.add_proc_module(std::move(name));
        }
    }

    // Find sysfs-only modules
    for (const auto& m : data.get_sysfs_modules()) {
        if (!data.is_builtin_module(m) && !data.is_proc_module(m)) {
            ++summary.sysfs_only_count;
            data.add_sysfs_only_sample(m);
        }
    }

    if (context.config.modules_anomalies_only) return; // Done with anomalies-only mode

    // Create summary finding
    build_summary_finding(context, scanner_name, data, summary, context.config.test_root);
}

void ModuleScanner::scan(ScanContext& context) {
    ModuleScanData data;
    auto& cfg = context.config;

    context.report.start_scanner(name());

    // Get kernel release
    struct utsname un {};
    if (uname(&un) != 0) {
        context.report.end_scanner(name());
        return;
    }
    std::string kernel_release = un.release;

    // Build paths once
    std::string modules_dep_path, modules_builtin_path, lib_modules_base;
    setup_scan_paths(kernel_release, modules_dep_path, modules_builtin_path, lib_modules_base, cfg.test_root);

    if (!cfg.modules_summary_only && !cfg.modules_anomalies_only) {
        // Simple mode: just list modules
        std::vector<std::string> proc_lines;
        if (read_proc_modules(proc_lines, cfg.test_root)) {
            handle_simple_mode(context, this->name(), proc_lines);
        }
        context.report.end_scanner(name());
        return;
    }

    // Summary/anomalies mode: gather detailed stats

    // Build module name->path map from modules.dep
    build_module_path_map(modules_dep_path, data);

    // Prepare built-in module name set
    build_builtin_modules_set(modules_builtin_path, data);

    // Collect sysfs module directory names
    collect_sysfs_modules(data, cfg.test_root);

    // Read /proc/modules and process modules
    std::vector<std::string> proc_lines;
    if (!read_proc_modules(proc_lines, cfg.test_root)) {
        context.report.end_scanner(name());
        return;
    }

    process_modules_detailed(context, this->name(), data, proc_lines, lib_modules_base);

    context.report.end_scanner(name());
}

} // namespace sys_scan
