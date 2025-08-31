#include "ProcessScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <pwd.h>
#include <sys/stat.h>
#include <regex>
#include <unordered_map>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace fs = std::filesystem;
namespace sys_scan {

// Fast directory iteration using POSIX calls
static std::vector<std::string> fast_list_dir(const char* path) {
    std::vector<std::string> entries;
    DIR* dir = opendir(path);
    if (!dir) return entries;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;  // Skip hidden files
        entries.push_back(entry->d_name);
    }
    closedir(dir);
    return entries;
}

// Fast container ID extraction without regex
static std::string extract_container_id(const char* cgroup_data, size_t len) {
    // Look for 64-char or 32-char hex strings (container IDs)
    const char* ptr = cgroup_data;
    const char* end = cgroup_data + len;

    while (ptr < end - 32) {  // Need at least 32 chars
        if (isxdigit(*ptr)) {
            // Check for 64-char hex string
            bool is_64_char = true;
            for (int i = 0; i < 64 && ptr + i < end; ++i) {
                if (!isxdigit(ptr[i])) {
                    is_64_char = false;
                    break;
                }
            }
            if (is_64_char && ptr + 64 <= end) {
                return std::string(ptr, 12);  // Return first 12 chars
            }

            // Check for 32-char hex string
            bool is_32_char = true;
            for (int i = 0; i < 32 && ptr + i < end; ++i) {
                if (!isxdigit(ptr[i])) {
                    is_32_char = false;
                    break;
                }
            }
            if (is_32_char && ptr + 32 <= end) {
                return std::string(ptr, 12);  // Return first 12 chars
            }
        }
        ++ptr;
    }
    return "";
}

// Fast file reading with size limits
static std::string fast_read_file_limited(const char* path, size_t max_size = 4096) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return "";

    char buffer[4096];
    size_t to_read = std::min(max_size, sizeof(buffer));
    ssize_t bytes_read = read(fd, buffer, to_read);
    close(fd);

    if (bytes_read > 0) {
        return std::string(buffer, bytes_read);
    }
    return "";
}

// Memory-efficient SHA256 calculation
static std::string fast_sha256(const char* filepath) {
#ifdef SYS_SCAN_HAVE_OPENSSL
    int fd = open(filepath, O_RDONLY);
    if (fd == -1) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        return "";
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return "";
    }

    char buffer[8192];
    ssize_t bytes_read;
    size_t total_read = 0;
    const size_t MAX_READ = 256 * 1024;  // Limit to 256KB for performance

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0 && total_read < MAX_READ) {
        EVP_DigestUpdate(ctx, buffer, bytes_read);
        total_read += bytes_read;
    }
    close(fd);

    unsigned char md[32];
    unsigned int mdlen = 0;
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) == 1 && mdlen == 32) {
        static const char hex[] = "0123456789abcdef";
        std::string hexhash;
        hexhash.reserve(64);
        for (unsigned i = 0; i < 32; ++i) {
            hexhash.push_back(hex[md[i] >> 4]);
            hexhash.push_back(hex[md[i] & 0xF]);
        }
        EVP_MD_CTX_free(ctx);
        return hexhash;
    }

    EVP_MD_CTX_free(ctx);
    return "";
#else
    return "(disabled - OpenSSL not found)";
#endif
}

void ProcessScanner::scan(Report& report) {
    const size_t MAX_PROCESSES = config().max_processes > 0 ? config().max_processes : 10000;
    size_t emitted = 0;
    bool inventory = config().process_inventory;

    // Memory-efficient container mapping
    std::unordered_map<std::string, std::string> pid_to_container;
    if (config().containers) {
        auto proc_entries = fast_list_dir("/proc");
        for (const auto& pid : proc_entries) {
            if (pid.length() > 6) continue;  // PIDs are short

            bool is_valid_pid = true;
            for (char c : pid) {
                if (!isdigit(c)) {
                    is_valid_pid = false;
                    break;
                }
            }
            if (!is_valid_pid) continue;

            std::string cgroup_path = "/proc/" + pid + "/cgroup";
            std::string cgroup_data = fast_read_file_limited(cgroup_path.c_str(), 2048);
            if (!cgroup_data.empty()) {
                std::string container_id = extract_container_id(cgroup_data.c_str(), cgroup_data.length());
                if (!container_id.empty()) {
                    pid_to_container[pid] = container_id;
                }
            }

            // Limit container mapping size
            if (pid_to_container.size() >= 1000) break;
        }
    }

    // Fast process scanning
    auto proc_entries = fast_list_dir("/proc");
    for (const auto& name : proc_entries) {
        if (name.length() > 6) continue;  // PIDs are short

        bool is_valid_pid = true;
        for (char c : name) {
            if (!isdigit(c)) {
                is_valid_pid = false;
                break;
            }
        }
        if (!is_valid_pid) continue;

        if (emitted >= MAX_PROCESSES) break;

        // Read status file efficiently
        std::string status_path = "/proc/" + name + "/status";
        std::string status_data = fast_read_file_limited(status_path.c_str(), 2048);
        if (status_data.empty()) {
            report.add_warning(this->name(), WarnCode::ProcUnreadableStatus, status_path);
            continue;
        }

        // Parse UID and GID from status
        std::string uid, gid;
        const char* ptr = status_data.c_str();
        const char* end = ptr + status_data.length();

        while (ptr < end) {
            if (strncmp(ptr, "Uid:", 4) == 0) {
                ptr += 4;
                while (ptr < end && *ptr == ' ' || *ptr == '\t') ++ptr;
                const char* start = ptr;
                while (ptr < end && isdigit(*ptr)) ++ptr;
                uid.assign(start, ptr - start);
            } else if (strncmp(ptr, "Gid:", 4) == 0) {
                ptr += 4;
                while (ptr < end && *ptr == ' ' || *ptr == '\t') ++ptr;
                const char* start = ptr;
                while (ptr < end && isdigit(*ptr)) ++ptr;
                gid.assign(start, ptr - start);
            }

            // Move to next line
            while (ptr < end && *ptr != '\n') ++ptr;
            if (ptr < end) ++ptr;

            if (!uid.empty() && !gid.empty()) break;
        }

        // Read cmdline efficiently
        std::string cmdline_path = "/proc/" + name + "/cmdline";
        std::string cmd = fast_read_file_limited(cmdline_path.c_str(), 4096);
        if (cmd.empty()) {
            report.add_warning(this->name(), WarnCode::ProcUnreadableCmdline, cmdline_path);
        }

        // Apply filtering rules
        if (cmd.empty() && !config().all_processes) continue;
        if (!config().all_processes && !cmd.empty() && cmd.front() == '[' && cmd.back() == ']') continue;

        // Container filtering
        if (config().containers && !config().container_id_filter.empty()) {
            auto it = pid_to_container.find(name);
            if (it == pid_to_container.end() || it->second != config().container_id_filter) {
                continue;
            }
        }

        if (inventory) {
            Finding f;
            f.id = name;
            f.title = "Process " + name;
            f.severity = Severity::Info;
            f.description = cmd.empty() ? "(no cmdline)" :
                          (config().no_cmdline_meta ? "(cmdline suppressed)" : cmd);

            if (!config().no_user_meta) {
                f.metadata["uid"] = uid;
                f.metadata["gid"] = gid;
            }

            if (config().containers) {
                auto it = pid_to_container.find(name);
                if (it != pid_to_container.end()) {
                    f.metadata["container_id"] = it->second;
                }
            }

            if (config().process_hash) {
                char exe_link_path[PATH_MAX];
                std::string exe_link_str = "/proc/" + name + "/exe";
                ssize_t len = readlink(exe_link_str.c_str(), exe_link_path, sizeof(exe_link_path) - 1);
                if (len > 0) {
                    exe_link_path[len] = '\0';
                    f.metadata["exe_path"] = exe_link_path;
                    std::string sha256 = fast_sha256(exe_link_path);
                    f.metadata["sha256"] = sha256;
                } else {
                    report.add_warning(this->name(), WarnCode::ProcExeSymlinkUnreadable, exe_link_str);
                }
            }

            report.add_finding(this->name(), std::move(f));
            ++emitted;
        }
    }

    // Clean up memory
    pid_to_container.clear();
}

}
