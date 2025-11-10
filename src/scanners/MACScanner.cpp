//    .________      ._____.___ .______  .______ .______ .___ .______  .___
//    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
//     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
//    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
//     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
//        :/               |___|    |___|    :       :   |___|    |___||___|
//        :                                  •       •                      
//                                                                          
//                                                                          

// ==============================================================================

#include "MACScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#include <cstdlib>

namespace sys_scan {

// Ultra-lean constants
static const size_t MAX_PROC_ENTRIES = 1000;
static const size_t MAX_PATH_LEN_LEAN = 512;
static const size_t MAX_BUF_SIZE = 512;

// Ultra-fast file existence check
static inline bool file_exists_lean(const char* path, const char* test_root = nullptr) {
    std::string full_path = test_root ? std::string(test_root) + path : std::string(path);
    struct stat st;
    return stat(full_path.c_str(), &st) == 0;
}

// Ultra-fast file read to buffer
static ssize_t read_file_to_buffer_lean(const char* path, char* buffer, size_t buffer_size, const char* test_root = nullptr) {
    std::string full_path = test_root ? std::string(test_root) + path : std::string(path);
    int fd = open(full_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    ssize_t total_read = 0;
    while (total_read < static_cast<ssize_t>(buffer_size)) {
        ssize_t bytes_read = read(fd, buffer + total_read, buffer_size - total_read);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }
    close(fd);
    return total_read;
}

// Ultra-fast string trim
static void trim_string_lean(char* str) {
    if (!str) return;
    // Trim leading whitespace
    char* start = str;
    while (*start && isspace(*start)) ++start;
    // Trim trailing whitespace
    char* end = start + strlen(start) - 1;
    while (end >= start && isspace(*end)) --end;
    *(end + 1) = '\0';
    // Move to start
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

// Ultra-fast process scanning for MAC labels
static void scan_processes_mac_lean(size_t* apparmor_profiles, size_t* apparmor_profiles_complain,
                                   size_t* apparmor_unconfined_critical, const char* test_root = nullptr) {
    std::string proc_path = test_root ? std::string(test_root) + "/proc" : "/proc";
    DIR* dir = opendir(proc_path.c_str());
    if (!dir) return;

    struct dirent* entry;
    char buffer[MAX_BUF_SIZE];

    while ((entry = readdir(dir)) != nullptr && *apparmor_profiles < MAX_PROC_ENTRIES) {
        if (entry->d_name[0] == '.') continue;

        // Check if it's a PID directory
        bool is_pid = true;
        for (const char* p = entry->d_name; *p; ++p) {
            if (!isdigit(*p)) {
                is_pid = false;
                break;
            }
        }
        if (!is_pid) continue;

        // Build paths
        char comm_path[MAX_PATH_LEN_LEAN];
        char attr_path[MAX_PATH_LEN_LEAN];
        char exe_path[MAX_PATH_LEN_LEAN];

        if (test_root) {
            snprintf(comm_path, sizeof(comm_path), "%s/proc/%s/comm", test_root, entry->d_name);
            snprintf(attr_path, sizeof(attr_path), "%s/proc/%s/attr/current", test_root, entry->d_name);
            snprintf(exe_path, sizeof(exe_path), "%s/proc/%s/exe", test_root, entry->d_name);
        } else {
            snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
            snprintf(attr_path, sizeof(attr_path), "/proc/%s/attr/current", entry->d_name);
            snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", entry->d_name);
        }

        // Read comm
        ssize_t comm_len = read_file_to_buffer_lean(comm_path, buffer, sizeof(buffer) - 1);
        if (comm_len <= 0) continue;
        buffer[comm_len] = '\0';
        trim_string_lean(buffer);
        const char* comm = buffer;

        // Read AppArmor label
        ssize_t attr_len = read_file_to_buffer_lean(attr_path, buffer, sizeof(buffer) - 1);
        if (attr_len <= 0) continue;
        buffer[attr_len] = '\0';
        trim_string_lean(buffer);
        const char* label = buffer;

        // Check for complain mode
        if (strstr(label, "(complain)") != nullptr) {
            ++(*apparmor_profiles_complain);
        }

        // Check for unconfined (case-insensitive)
        char lower_label[MAX_BUF_SIZE];
        strcpy(lower_label, label);
        for (char* p = lower_label; *p; ++p) *p = tolower(*p);
        if (strstr(lower_label, "unconfined") != nullptr) {
            // Read exe symlink to check if it's a critical binary
            char exe_buf[MAX_PATH_LEN_LEAN];
            ssize_t exe_link_len = readlink(exe_path, exe_buf, sizeof(exe_buf) - 1);
            if (exe_link_len > 0) {
                exe_buf[exe_link_len] = '\0';

                // Adjust path for test_root
                std::string exe_path_str(exe_buf);
                if (test_root) {
                    std::string test_root_str(test_root);
                    if (exe_path_str.find(test_root_str) == 0) {
                        exe_path_str = exe_path_str.substr(test_root_str.length());
                    }
                }

                // Critical binaries to check
                const char* critical_bins[] = {
                    "/usr/sbin/sshd", "/usr/bin/dbus-daemon", "/usr/sbin/nginx",
                    "/usr/bin/containerd", "/usr/bin/dockerd",
                    "/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-networkd",
                    "/usr/sbin/apache2", "/usr/sbin/mysql", "/usr/lib/postgresql/bin/postgres"
                };
                const size_t critical_count = sizeof(critical_bins) / sizeof(critical_bins[0]);

                for (size_t i = 0; i < critical_count; ++i) {
                    if (strcmp(exe_path_str.c_str(), critical_bins[i]) == 0) {
                        ++(*apparmor_unconfined_critical);
                        break;
                    }
                }
            }
        }

        ++(*apparmor_profiles);
    }

    closedir(dir);
}

void MACScanner::scan(ScanContext& context) {
    context.report.start_scanner(this->name());

    const char* test_root = context.config.test_root.empty() ? nullptr : context.config.test_root.c_str();

    // Detect container (simple heuristics) to potentially downgrade severity
    bool in_container = file_exists_lean("/.dockerenv", test_root) || 
                       file_exists_lean("/run/.containerenv", test_root) ||
                       file_exists_lean("/run/.dockerenv", test_root) ||
                       file_exists_lean("/.lxcenv", test_root) ||
                       file_exists_lean("/run/systemd/container", test_root);

    // SELinux detection (ultra-fast)
    bool selinux_present = false;
    bool selinux_enforcing = false;
    bool selinux_permissive = false;
    char buffer[MAX_BUF_SIZE];

    if (file_exists_lean("/sys/fs/selinux", test_root)) {
        selinux_present = true;

        // Read enforce status
        ssize_t len = read_file_to_buffer_lean("/sys/fs/selinux/enforce", buffer, sizeof(buffer) - 1, test_root);
        if (len > 0) {
            buffer[len] = '\0';
            trim_string_lean(buffer);
            if (strcmp(buffer, "1") == 0) selinux_enforcing = true;
            else if (strcmp(buffer, "0") == 0) selinux_permissive = true;
        }
    }

    // Read SELinux config
    char selinux_cfg_mode[MAX_BUF_SIZE] = "";
    if (file_exists_lean("/etc/selinux/config", test_root)) {
        std::string config_path = test_root ? std::string(test_root) + "/etc/selinux/config" : "/etc/selinux/config";
        int fd = open(config_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd != -1) {
            ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
            close(fd);

            if (len > 0) {
                buffer[len] = '\0';

                // Find SELINUX= line
                const char* ptr = buffer;
                const char* selinux_line = strstr(ptr, "SELINUX=");
                if (selinux_line) {
                    const char* start = selinux_line + 8;  // Skip "SELINUX="
                    const char* end = start;
                    while (*end && *end != '\n' && *end != ' ' && *end != '\t') ++end;
                    size_t mode_len = end - start;
                    if (mode_len < sizeof(selinux_cfg_mode) - 1) {
                        memcpy(selinux_cfg_mode, start, mode_len);
                        selinux_cfg_mode[mode_len] = '\0';
                    }
                }
            }
        }
    }

    // AppArmor detection (ultra-fast)
    bool apparmor_enabled = false;
    char apparmor_mode_line[MAX_BUF_SIZE] = "";

    if (file_exists_lean("/sys/module/apparmor/parameters/enabled", test_root)) {
        ssize_t len = read_file_to_buffer_lean("/sys/module/apparmor/parameters/enabled",
                                             apparmor_mode_line, sizeof(apparmor_mode_line) - 1, test_root);
        if (len > 0) {
            apparmor_mode_line[len] = '\0';
            trim_string_lean(apparmor_mode_line);
            if (apparmor_mode_line[0]) apparmor_enabled = true;
        }
    }

    // Process scanning for AppArmor profiles (ultra-fast)
    size_t apparmor_profiles = 0;
    size_t apparmor_profiles_complain = 0;
    size_t apparmor_unconfined_critical = 0;

    scan_processes_mac_lean(&apparmor_profiles, &apparmor_profiles_complain, &apparmor_unconfined_critical, test_root);

    // SELinux Finding
    {
        Finding f;
        f.id = "selinux";
        f.title = "SELinux status";
        f.severity = Severity::Info;
        f.description = "SELinux detection";

        if (!selinux_present) {
            f.metadata["present"] = "false";
            // If AppArmor is enabled, absence of SELinux alone is not high severity (Ubuntu default)
            if (apparmor_enabled) {
                f.severity = in_container ? Severity::Info : Severity::Low;
            } else {
                f.severity = in_container ? Severity::Info : Severity::High;
            }
        } else {
            f.metadata["present"] = "true";
            f.metadata["enforcing"] = selinux_enforcing ? "true" : "false";
            f.metadata["permissive"] = selinux_permissive ? "true" : "false";
            if (selinux_cfg_mode[0]) f.metadata["config_mode"] = selinux_cfg_mode;
            if (selinux_permissive) f.severity = Severity::Low;
            if (selinux_enforcing) f.severity = Severity::Info;
        }
        context.report.add_finding(this->name(), std::move(f));
    }

    // AppArmor Finding
    {
        Finding f;
        f.id = "apparmor";
        f.title = "AppArmor status";
        f.severity = Severity::Info;
        f.description = "AppArmor detection";

        if (!apparmor_enabled) {
            f.severity = in_container ? Severity::Info : Severity::High;
            f.metadata["enabled"] = "false";
        } else {
            f.metadata["enabled"] = "true";
            f.metadata["mode_line"] = apparmor_mode_line;
            f.metadata["profiles_seen"] = std::to_string(apparmor_profiles);
            f.metadata["complain_count"] = std::to_string(apparmor_profiles_complain);
            if (apparmor_unconfined_critical > 0) {
                f.metadata["unconfined_critical"] = std::to_string(apparmor_unconfined_critical);
                f.severity = Severity::Medium;
            }
        }
        context.report.add_finding(this->name(), std::move(f));
    }

    // Combined Advisory
    if (!selinux_present && !apparmor_enabled) {
        Finding f;
        f.id = "mac_none";
        f.title = "No MAC enforcement";
        f.severity = in_container ? Severity::Low : Severity::High;
        f.description = "Neither SELinux nor AppArmor appears active";
        context.report.add_finding(this->name(), std::move(f));
    } else if (selinux_present && apparmor_enabled) {
        Finding f;
        f.id = "mac_dual";
        f.title = "Dual MAC layers";
        f.severity = Severity::Info;
        f.description = "Both SELinux and AppArmor appear present (double-check for conflicts)";
        context.report.add_finding(this->name(), std::move(f));
    }
}

}
