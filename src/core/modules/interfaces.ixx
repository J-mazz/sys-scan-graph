module;
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <filesystem>
#include <utility>

export module sys_scan.interfaces;

export namespace sys_scan {

struct FileEntry {
    std::string name;
    bool is_directory;
    bool is_symlink;
    bool is_regular;
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
