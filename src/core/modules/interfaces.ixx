module;
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <utility>

export module sys_scan.interfaces;

export namespace sys_scan {

struct FileEntry {
    // Full path to this entry (best-effort; may be empty for synthetic/mock file systems).
    std::string path;
    std::string name;
    bool is_directory;
    bool is_symlink;
    bool is_regular;
};

// System information and time primitives for testability.
struct ISystemInfo {
    virtual ~ISystemInfo() = default;
    virtual std::string kernel_release() const = 0;
};

struct ISleeper {
    virtual ~ISleeper() = default;
    virtual void sleep_for(std::chrono::milliseconds duration) const = 0;
};

struct IFileSystem {
    virtual ~IFileSystem() = default;
    
    // Core operations
    virtual bool exists(const std::string& path) const = 0;
    virtual bool is_directory(const std::string& path) const = 0;
    virtual std::string read_file(const std::string& path) const = 0;
    virtual std::vector<FileEntry> list_directory(const std::string& path) const = 0;
    virtual std::string read_symlink(const std::string& path) const = 0;
    virtual std::filesystem::perms permissions(const std::string& path) const = 0;
};

struct IProcessRunner {
    virtual ~IProcessRunner() = default;
    // Returns {exit_code, stdout/stderr combined output}
    virtual std::pair<int, std::string> exec(const std::string& command, const std::vector<std::string>& args) const = 0;
};

}
