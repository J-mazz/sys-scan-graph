#include "IOCScanner.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include <filesystem>
#include <fstream>
#include <regex>
#include <unordered_set>
#include <unordered_map>
#include "../core/Config.h"
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

namespace fs = std::filesystem;
namespace sys_scan {

static bool is_executable(const fs::path& p){ struct stat st{}; if(stat(p.c_str(), &st)!=0) return false; return (st.st_mode & S_IXUSR)||(st.st_mode & S_IXGRP)||(st.st_mode & S_IXOTH); }
static bool has_suid(const fs::path& p){ struct stat st{}; if(lstat(p.c_str(), &st)!=0) return false; return (st.st_mode & S_ISUID); }

// Fast string matching functions to replace regex where possible
static bool fast_string_match(const std::string& str, const std::vector<std::string>& patterns) {
    for (const auto& pattern : patterns) {
        if (str.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

static bool fast_path_match(const std::string& path, const std::vector<std::string>& prefixes) {
    for (const auto& prefix : prefixes) {
        if (path.rfind(prefix, 0) == 0) {  // starts_with check
            return true;
        }
    }
    return false;
}

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

// Fast file reading using POSIX calls
static std::string fast_read_file(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return "";

    std::string content;
    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        content.append(buffer, bytes_read);
    }
    close(fd);
    return content;
}

void IOCScanner::scan(Report& report) {
    // Memory-optimized version with streaming and limited data structures

    // Use fixed-size arrays instead of vectors for better memory control
    const char* suspicious_names[] = {"kworker", "cryptominer", "xmrig", "minerd", "kthreadd", "malware", "bot"};
    const size_t suspicious_count = sizeof(suspicious_names) / sizeof(suspicious_names[0]);

    const char* ww_dirs[] = {"/tmp", "/dev/shm", "/var/tmp"};
    const size_t ww_dirs_count = sizeof(ww_dirs) / sizeof(ww_dirs[0]);

    // Use smaller, more memory-efficient data structures
    // Limit maximum entries to prevent memory exhaustion
    const size_t MAX_PROC_ENTRIES = 1000;
    const size_t MAX_ENV_ENTRIES = 500;

    std::unordered_map<std::string, std::vector<std::string>> proc_hits;  // exe -> pids
    std::unordered_map<std::string, std::string> proc_cmds;  // exe -> first cmd
    std::unordered_map<std::string, uint8_t> proc_flags;  // exe -> flags (bitmask)

    // Process /proc directory with memory limits
    auto proc_entries = fast_list_dir("/proc");
    size_t proc_count = 0;

    for (const auto& pid_str : proc_entries) {
        if (proc_count >= MAX_PROC_ENTRIES) break;  // Memory limit

        // Validate PID
        bool is_valid_pid = true;
        for (char c : pid_str) {
            if (!isdigit(c)) {
                is_valid_pid = false;
                break;
            }
        }
        if (!is_valid_pid) continue;

        std::string pid = pid_str;
        proc_count++;

        // Read cmdline efficiently
        std::string cmdline_path = "/proc/" + pid + "/cmdline";
        std::string raw_cmd = fast_read_file(cmdline_path.c_str());
        if (raw_cmd.empty()) continue;

        // Replace null bytes with spaces for string processing
        for (char& c : raw_cmd) {
            if (c == '\0') c = ' ';
        }

        // Fast pattern matching without regex
        bool matched = false;
        if (raw_cmd.find("/tmp/") != std::string::npos ||
            raw_cmd.find("/dev/shm/") != std::string::npos ||
            raw_cmd.find("/var/tmp/") != std::string::npos ||
            raw_cmd.find("/home/") != std::string::npos) {
            matched = true;
        }

        // Check suspicious names
        if (!matched) {
            for (size_t i = 0; i < suspicious_count; ++i) {
                if (raw_cmd.find(suspicious_names[i]) != std::string::npos) {
                    matched = true;
                    break;
                }
            }
        }

        // Read exe symlink
        std::string exe_path = "/proc/" + pid + "/exe";
        char exe_buf[PATH_MAX];
        ssize_t len = readlink(exe_path.c_str(), exe_buf, sizeof(exe_buf) - 1);
        std::string exe_target;
        if (len > 0) {
            exe_buf[len] = '\0';
            exe_target = exe_buf;
        }

        bool deleted = (!exe_target.empty() && exe_target.find("(deleted)") != std::string::npos);
        bool ww_exec = false;
        if (!exe_target.empty()) {
            for (size_t i = 0; i < ww_dirs_count; ++i) {
                if (exe_target.rfind(ww_dirs[i], 0) == 0) {
                    ww_exec = true;
                    break;
                }
            }
        }

        if (matched || deleted || ww_exec) {
            std::string key = exe_target.empty() ? raw_cmd : exe_target;

            // Limit key length to prevent memory issues
            if (key.length() > 1024) key = key.substr(0, 1024);

            auto& pids = proc_hits[key];
            if (pids.size() < 10) {  // Limit PIDs per process
                pids.push_back(pid);
            }

            if (proc_cmds.find(key) == proc_cmds.end()) {
                proc_cmds[key] = raw_cmd.substr(0, 512);  // Limit cmd length
            }

            uint8_t flags = 0;
            if (matched) flags |= 1;
            if (deleted) flags |= 2;
            if (ww_exec) flags |= 4;
            proc_flags[key] = flags;
        }

        // Memory-efficient environment checking
        if (proc_hits.size() < MAX_ENV_ENTRIES) {
            std::string env_path = "/proc/" + pid + "/environ";
            int env_fd = open(env_path.c_str(), O_RDONLY);
            if (env_fd != -1) {
                char env_buf[2048];  // Fixed buffer size
                ssize_t env_len = read(env_fd, env_buf, sizeof(env_buf) - 1);
                close(env_fd);

                if (env_len > 0) {
                    env_buf[env_len] = '\0';
                    std::string env_data(env_buf, env_len);

                    bool has_preload = env_data.find("LD_PRELOAD=") != std::string::npos;
                    bool has_libpath = env_data.find("LD_LIBRARY_PATH=") != std::string::npos;

                    if (has_preload || has_libpath) {
                        bool temp_ref = (env_data.find("/tmp/") != std::string::npos ||
                                       env_data.find("/dev/shm/") != std::string::npos);

                        std::string key = exe_target.empty() ? std::string("<unknown>") : exe_target;
                        if (key.length() > 512) key = key.substr(0, 512);

                        // Store minimal env info
                        std::string env_key = key + ":env";
                        uint8_t env_flags = 0;
                        if (temp_ref) env_flags |= 1;
                        if (has_preload) env_flags |= 2;
                        if (has_libpath) env_flags |= 4;

                        proc_flags[env_key] = env_flags;
                        auto& env_pids = proc_hits[env_key];
                        if (env_pids.size() < 5) {
                            env_pids.push_back(pid);
                        }
                    }
                }
            }
        }
    }

    // Generate findings with memory cleanup
    for (const auto& kv : proc_hits) {
        const std::string& key = kv.first;
        const std::vector<std::string>& pids = kv.second;

        if (key.find(":env") != std::string::npos) {
            // Environment finding
            uint8_t flags = proc_flags[key];
            std::string sev = "medium";
            std::string rule = "ld_env";
            std::string desc = "LD_* environment usage";

            if (flags & 1) {  // temp_ref
                rule += "_tmp";
                desc += " referencing tmp";
            }

            Finding f;
            f.id = key;
            f.title = "Environment IOC";
            f.severity = severity_from_string(sev);
            f.description = desc;
            f.metadata["rule"] = rule;
            f.metadata["pid_count"] = std::to_string(pids.size());
            report.add_finding(this->name(), std::move(f));
        } else {
            // Process finding
            uint8_t flags = proc_flags[key];
            std::string sev = "high";
            if (flags & 2) sev = "critical";  // deleted
            else if (flags & 4) sev = "high";  // ww_exec

            auto cmd_it = proc_cmds.find(key);
            std::string desc = (cmd_it != proc_cmds.end()) ? cmd_it->second : key;

            Finding f;
            f.id = key + ":proc_ioc";
            f.title = "Process IOC";
            f.severity = severity_from_string(sev);
            f.description = desc;
            f.metadata["pid_count"] = std::to_string(pids.size());

            if (flags & 1) f.metadata["pattern_match"] = "true";
            if (flags & 2) f.metadata["deleted_exe"] = "true";
            if (flags & 4) f.metadata["world_writable_exec"] = "true";

            report.add_finding(this->name(), std::move(f));
        }
    }

    // Clear memory after processing
    proc_hits.clear();
    proc_cmds.clear();
    proc_flags.clear();

}

}
