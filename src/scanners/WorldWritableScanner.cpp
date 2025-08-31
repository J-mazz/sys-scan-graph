#include "WorldWritableScanner.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include "../core/Config.h"
#include <filesystem>
#include <sys/stat.h>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#ifdef __linux__
#include <sys/types.h>
#include <sys/xattr.h>
#endif

namespace fs = std::filesystem;
namespace sys_scan {

// Fast directory listing with optional recursion and limits
static std::vector<std::string> fast_list_files(const char* path, bool recursive = false, size_t max_files = 10000) {
    std::vector<std::string> files;
    std::vector<std::string> dirs_to_scan = {path};

    while (!dirs_to_scan.empty() && files.size() < max_files) {
        std::string current_dir = dirs_to_scan.back();
        dirs_to_scan.pop_back();

        DIR* dir = opendir(current_dir.c_str());
        if (!dir) continue;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr && files.size() < max_files) {
            if (entry->d_name[0] == '.') continue;  // Skip hidden files

            std::string full_path = current_dir;
            if (full_path.back() != '/') full_path += '/';
            full_path += entry->d_name;

            if (recursive && entry->d_type == DT_DIR) {
                dirs_to_scan.push_back(full_path);
            } else if (entry->d_type == DT_REG) {
                files.push_back(full_path);
            }
        }
        closedir(dir);
    }

    return files;
}

// Fast world-writable check
static bool fast_is_world_writable(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return false;
    return (st.st_mode & S_IWOTH) != 0;
}

// Fast SUID check
static bool fast_has_suid(const char* path) {
    struct stat st;
    if (lstat(path, &st) != 0) return false;
    return (st.st_mode & S_ISUID) != 0;
}

// Fast file capabilities check
#ifdef __linux__
static bool fast_has_file_caps(const char* path) {
    ssize_t len = getxattr(path, "security.capability", nullptr, 0);
    return len > 0;
}
#endif

// Fast shebang check
static std::string fast_get_shebang(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return "";

    char buffer[128];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytes_read <= 0) return "";

    buffer[bytes_read] = '\0';
    std::string content(buffer);

    if (content.rfind("#!/", 0) == 0) {
        size_t newline_pos = content.find('\n');
        if (newline_pos != std::string::npos) {
            return content.substr(0, newline_pos);
        }
        return content;
    }

    return "";
}

void WorldWritableScanner::scan(Report& report) {
    const size_t MAX_FILES_PER_DIR = 5000;  // Limit files per directory
    const size_t MAX_TOTAL_FILES = 20000;   // Total limit across all directories

    // Base directories to scan
    std::vector<std::string> dirs = {"/etc", "/usr/bin", "/usr/local/bin", "/var"};
    for (const auto& extra : config().world_writable_dirs) {
        dirs.push_back(extra);
    }

    // Fast exclusion check
    auto should_exclude = [&](const std::string& p) {
        for (const auto& pat : config().world_writable_exclude) {
            if (p.find(pat) != std::string::npos) return true;
        }
        return false;
    };

    size_t total_files_scanned = 0;
    size_t ww_count = 0;
    int ww_limit = config().fs_world_writable_limit;

    // Scan directories for world-writable files
    for (const auto& d : dirs) {
        if (total_files_scanned >= MAX_TOTAL_FILES) break;

        auto files = fast_list_files(d.c_str(), true, MAX_FILES_PER_DIR);
        total_files_scanned += files.size();

        for (const auto& filepath : files) {
            if (should_exclude(filepath)) continue;

            if (fast_is_world_writable(filepath.c_str())) {
                if (ww_limit > 0 && static_cast<int>(ww_count) >= ww_limit) continue;

                Finding f;
                f.id = filepath;
                f.title = "World-writable file";
                f.severity = Severity::Medium;
                f.description = "File is world writable";

                // Adjust severity based on path
                if (filepath.find("/tmp/") != std::string::npos) {
                    f.severity = Severity::Low;
                } else if (filepath.find(".so") != std::string::npos ||
                          filepath.find("/bin/") != std::string::npos) {
                    f.severity = Severity::High;
                }

                report.add_finding(this->name(), std::move(f));
                ++ww_count;
            }
        }
    }

    if (!config().fs_hygiene) return;  // Advanced checks gated

    // 1. PATH directory world-writable detection
    const char* path_env = getenv("PATH");
    if (path_env) {
        std::string path_str = path_env;
        size_t pos = 0;
        while (pos < path_str.length()) {
            size_t colon_pos = path_str.find(':', pos);
            std::string seg = (colon_pos == std::string::npos) ?
                             path_str.substr(pos) : path_str.substr(pos, colon_pos - pos);

            if (!seg.empty()) {
                struct stat st;
                if (stat(seg.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    if (st.st_mode & S_IWOTH) {
                        Finding f;
                        f.id = seg;
                        f.title = "World-writable PATH directory";
                        f.severity = Severity::High;
                        f.description = "Executable search path directory is world-writable";
                        f.metadata["rule"] = "path_dir_world_writable";
                        report.add_finding(this->name(), std::move(f));
                    }
                }
            }

            if (colon_pos == std::string::npos) break;
            pos = colon_pos + 1;
        }
    }

    // 2. Setuid interpreter detection
    const char* interpreters[] = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby"};
    const size_t interpreter_count = sizeof(interpreters) / sizeof(interpreters[0]);

    std::vector<std::string> bin_dirs = {"/usr/bin", "/bin", "/usr/local/bin"};

    for (const auto& bd : bin_dirs) {
        if (total_files_scanned >= MAX_TOTAL_FILES) break;

        auto files = fast_list_files(bd.c_str(), false, 1000);  // Non-recursive for bin dirs
        total_files_scanned += files.size();

        for (const auto& filepath : files) {
            if (!fast_has_suid(filepath.c_str())) continue;

            std::string filename = filepath.substr(filepath.find_last_of('/') + 1);
            bool match = false;

            // Check filename first
            for (size_t i = 0; i < interpreter_count; ++i) {
                if (filename == interpreters[i]) {
                    match = true;
                    break;
                }
            }

            // Check shebang if filename didn't match
            if (!match) {
                std::string shebang = fast_get_shebang(filepath.c_str());
                for (size_t i = 0; i < interpreter_count; ++i) {
                    if (shebang.find(interpreters[i]) != std::string::npos) {
                        match = true;
                        break;
                    }
                }
            }

            if (match) {
                Finding f;
                f.id = filepath;
                f.title = "Setuid interpreter";
                f.severity = Severity::Critical;
                f.description = "Setuid shell or script interpreter";
                f.metadata["rule"] = "setuid_interpreter";
                report.add_finding(this->name(), std::move(f));
            }
        }
    }

    // 3. File capabilities detection
#ifdef __linux__
    for (const auto& bd : bin_dirs) {
        if (total_files_scanned >= MAX_TOTAL_FILES) break;

        auto files = fast_list_files(bd.c_str(), false, 1000);
        total_files_scanned += files.size();

        for (const auto& filepath : files) {
            if (fast_has_file_caps(filepath.c_str())) {
                struct stat st;
                if (stat(filepath.c_str(), &st) == 0 && !(st.st_mode & S_ISUID)) {
                    Finding f;
                    f.id = filepath;
                    f.title = "File capabilities binary";
                    f.severity = Severity::Medium;
                    f.description = "Binary has file capabilities set";
                    f.metadata["rule"] = "file_capability";
                    report.add_finding(this->name(), std::move(f));
                }
            }
        }
    }
#endif

    // 4. Dangling SUID hardlinks detection (simplified)
    std::unordered_map<ino_t, std::vector<std::string>> inode_paths;
    std::vector<std::string> suspect_roots = {"/tmp", "/var/tmp", "/dev/shm"};

    for (const auto& bd : bin_dirs) {
        if (total_files_scanned >= MAX_TOTAL_FILES) break;

        auto files = fast_list_files(bd.c_str(), false, 1000);
        total_files_scanned += files.size();

        for (const auto& filepath : files) {
            struct stat st;
            if (lstat(filepath.c_str(), &st) != 0) continue;
            if (!(st.st_mode & S_ISUID)) continue;

            inode_paths[st.st_ino].push_back(filepath);
        }
    }

    // Check for suspicious hardlinks
    for (const auto& kv : inode_paths) {
        const auto& paths = kv.second;
        if (paths.size() < 2) continue;

        bool has_system = false;
        bool has_suspect = false;

        for (const auto& path : paths) {
            if (path.rfind("/usr/bin/", 0) == 0 ||
                path.rfind("/bin/", 0) == 0 ||
                path.rfind("/usr/sbin/", 0) == 0) {
                has_system = true;
            }
            for (const auto& suspect : suspect_roots) {
                if (path.rfind(suspect, 0) == 0) {
                    has_suspect = true;
                    break;
                }
            }
        }

        if (has_system && has_suspect) {
            Finding f;
            f.id = paths.front() + ":dangling_suid_link";
            f.title = "Dangling SUID hardlink";
            f.severity = Severity::High;
            f.description = "SUID binary hardlinked into temporary/untrusted location";
            f.metadata["rule"] = "dangling_suid_hardlink";

            std::string all_paths;
            for (size_t i = 0; i < paths.size(); ++i) {
                if (i > 0) all_paths += ",";
                all_paths += paths[i];
            }
            f.metadata["paths"] = all_paths;

            report.add_finding(this->name(), std::move(f));
        }
    }

    // Clean up memory
    inode_paths.clear();
}

}
