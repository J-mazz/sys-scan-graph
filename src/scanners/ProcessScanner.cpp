#include "ProcessScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/ScanContext.h"  // Added ScanContext include
#include "../core/Logging.h"
#include <unordered_map>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#include <sys/stat.h>
#include <pwd.h>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace sys_scan {

// Fast PID validation
static inline bool is_valid_pid(const char* str, int* pid_out = nullptr) {
    if (!str || !*str) return false;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val <= 0 || val > INT_MAX) return false;
    if (pid_out) *pid_out = static_cast<int>(val);
    return true;
}

// Fast file reading with fixed buffer
static ssize_t read_file_to_buffer(const char* path, char* buffer, size_t buffer_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
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

// Ultra-fast container ID extraction (no allocations)
static bool extract_container_id_lean(const char* cgroup_data, size_t len, char* out_id, size_t out_size) {
    if (out_size < 13) return false;  // Need at least 12 chars + null

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
                memcpy(out_id, ptr, 12);
                out_id[12] = '\0';
                return true;
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
                memcpy(out_id, ptr, 12);
                out_id[12] = '\0';
                return true;
            }
        }
        ++ptr;
    }
    return false;
}

// Ultra-fast UID/GID parsing (no string allocations)
static bool parse_uid_gid_lean(const char* status_data, size_t len, char* uid_buf, size_t uid_size, char* gid_buf, size_t gid_size) {
    const char* ptr = status_data;
    const char* end = status_data + len;
    bool found_uid = false, found_gid = false;

    while (ptr < end && !(found_uid && found_gid)) {
        if (strncmp(ptr, "Uid:", 4) == 0 && !found_uid) {
            ptr += 4;
            while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ++ptr;
            const char* start = ptr;
            while (ptr < end && isdigit(*ptr)) ++ptr;
            size_t len = ptr - start;
            if (len > 0 && len < uid_size) {
                memcpy(uid_buf, start, len);
                uid_buf[len] = '\0';
                found_uid = true;
            }
        } else if (strncmp(ptr, "Gid:", 4) == 0 && !found_gid) {
            ptr += 4;
            while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ++ptr;
            const char* start = ptr;
            while (ptr < end && isdigit(*ptr)) ++ptr;
            size_t len = ptr - start;
            if (len > 0 && len < gid_size) {
                memcpy(gid_buf, start, len);
                gid_buf[len] = '\0';
                found_gid = true;
            }
        }

        // Move to next line
        while (ptr < end && *ptr != '\n') ++ptr;
        if (ptr < end) ++ptr;
    }
    return found_uid && found_gid;
}

// Ultra-fast SHA256 with pre-allocated hex buffer
static bool fast_sha256_lean(const char* filepath, char* hash_out) {
#ifdef SYS_SCAN_HAVE_OPENSSL
    int fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        return false;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return false;
    }

    char buffer[4096];  // Smaller buffer for better cache performance
    ssize_t bytes_read;
    size_t total_read = 0;
    const size_t MAX_READ = 128 * 1024;  // Reduced limit for speed

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0 && total_read < MAX_READ) {
        EVP_DigestUpdate(ctx, buffer, bytes_read);
        total_read += bytes_read;
    }
    close(fd);

    unsigned char md[32];
    unsigned int mdlen = 0;
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) == 1 && mdlen == 32) {
        // Pre-computed hex table for speed
        static const char hex_chars[] = "0123456789abcdef";
        for (unsigned i = 0; i < 32; ++i) {
            hash_out[i * 2] = hex_chars[md[i] >> 4];
            hash_out[i * 2 + 1] = hex_chars[md[i] & 0xF];
        }
        hash_out[64] = '\0';
        EVP_MD_CTX_free(ctx);
        return true;
    }

    EVP_MD_CTX_free(ctx);
    return false;
#else
    strcpy(hash_out, "(disabled)");
    return true;
#endif
}

// Fast directory listing
static size_t list_proc_pids(int* pid_buffer, size_t max_pids) {
    DIR* dir = opendir("/proc");
    if (!dir) return 0;

    size_t count = 0;
    struct dirent* entry;
    while (count < max_pids && (entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        int pid;
        if (is_valid_pid(entry->d_name, &pid)) {
            pid_buffer[count++] = pid;
        }
    }
    closedir(dir);
    return count;
}

void ProcessScanner::scan(ScanContext& context) {
    const size_t MAX_PROCESSES = 5000;
    int pid_buffer[MAX_PROCESSES];
    size_t emitted = 0;

    // Fast directory scan
    size_t pid_count = list_proc_pids(pid_buffer, MAX_PROCESSES);

    // Preload container id mapping if container mode
    char container_map[2000][13];  // Fixed-size container IDs (12 chars + null)
    int container_pids[2000];      // Corresponding PIDs
    size_t container_count = 0;

    if (context.config.containers) {
        for (size_t i = 0; i < pid_count && container_count < 2000; ++i) {
            int pid = pid_buffer[i];
            char cgroup_path[64];
            snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%d/cgroup", pid);

            char cgroup_data[2048];
            ssize_t len = read_file_to_buffer(cgroup_path, cgroup_data, sizeof(cgroup_data) - 1);
            if (len > 0) {
                cgroup_data[len] = '\0';
                if (extract_container_id_lean(cgroup_data, len, container_map[container_count], 13)) {
                    container_pids[container_count] = pid;
                    container_count++;
                }
            }
        }
    }

    bool inventory = context.config.process_inventory;

    // Process each PID
    for (size_t i = 0; i < pid_count; ++i) {
        int pid = pid_buffer[i];
        std::string name = std::to_string(pid);

        // Read status file efficiently
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);

        char status_data[2048];
        ssize_t status_len = read_file_to_buffer(status_path, status_data, sizeof(status_data) - 1);
        if (status_len <= 0) {
            context.report.add_warning(this->name(), WarnCode::ProcUnreadableStatus, status_path);
            continue;
        }
        status_data[status_len] = '\0';

        // Parse UID and GID (lean version)
        char uid_buf[16], gid_buf[16];
        uid_buf[0] = gid_buf[0] = '\0';
        parse_uid_gid_lean(status_data, status_len, uid_buf, sizeof(uid_buf), gid_buf, sizeof(gid_buf));

        // Read cmdline efficiently
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

        char cmd_buffer[4096];
        ssize_t cmd_len = read_file_to_buffer(cmdline_path, cmd_buffer, sizeof(cmd_buffer) - 1);
        std::string cmd;
        if (cmd_len > 0) {
            cmd_buffer[cmd_len] = '\0';
            cmd = cmd_buffer;
        } else {
            context.report.add_warning(this->name(), WarnCode::ProcUnreadableCmdline, cmdline_path);
        }

        // Apply filtering rules
        if (cmd.empty() && !context.config.all_processes) continue;
        if (!context.config.all_processes && !cmd.empty() && cmd.front() == '[' && cmd.back() == ']') continue;

        // Container filtering (lean version)
        if (context.config.containers && !context.config.container_id_filter.empty()) {
            bool found_match = false;
            for (size_t j = 0; j < container_count; ++j) {
                if (container_pids[j] == pid && strcmp(container_map[j], context.config.container_id_filter.c_str()) == 0) {
                    found_match = true;
                    break;
                }
            }
            if (!found_match) continue;
        }

        if (context.config.max_processes > 0 && emitted >= (size_t)context.config.max_processes) break;

        // Parse UID/GID (lean version)
        parse_uid_gid_lean(status_data, status_len, uid_buf, sizeof(uid_buf), gid_buf, sizeof(gid_buf));

        // Convert to integers
        uid_t uid_val = 0;
        gid_t gid_val = 0;
        if (uid_buf[0]) uid_val = static_cast<uid_t>(strtoul(uid_buf, nullptr, 10));
        if (gid_buf[0]) gid_val = static_cast<gid_t>(strtoul(gid_buf, nullptr, 10));

        if (inventory) {
            Finding f;
            f.id = name;
            f.title = "Process " + name;
            f.severity = Severity::Info;
            f.description = cmd.empty() ? "(no cmdline)" : cmd;
            // Metadata assignment (lean version)
            if (!context.config.no_user_meta) {
                f.metadata["uid"] = std::to_string(uid_val);
                f.metadata["gid"] = std::to_string(gid_val);
            }
            if (context.config.containers) {
                // Container lookup (lean version)
                for (size_t j = 0; j < container_count; ++j) {
                    if (container_pids[j] == pid) {
                        f.metadata["container_id"] = container_map[j];
                        break;
                    }
                }
            }

            if (context.config.process_hash) {
                // Read exe symlink
                char exe_link_path[PATH_MAX];
                char exe_path[64];
                snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
                ssize_t exe_len = readlink(exe_path, exe_link_path, sizeof(exe_link_path) - 1);
                if (exe_len > 0) {
                    exe_link_path[exe_len] = '\0';
                    f.metadata["exe_path"] = exe_link_path;

                    // Fast SHA256 calculation (lean version)
                    char hash_buffer[65];
                    if (fast_sha256_lean(exe_link_path, hash_buffer)) {
                        f.metadata["sha256"] = hash_buffer;
                    } else {
                        f.metadata["sha256"] = "(error)";
                    }
                } else {
                    context.report.add_warning(this->name(), WarnCode::ProcExeSymlinkUnreadable, exe_path);
                }
            }

            context.report.add_finding(this->name(), std::move(f));
            ++emitted;
        }
    }
}

}
