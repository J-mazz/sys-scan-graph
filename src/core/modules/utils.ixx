module;
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cctype>
export module sys_scan.utils;
export import :helper;

namespace fs = std::filesystem;

export namespace sys_scan::utils {
    
    inline std::string trim(const std::string& s) {
        auto start = s.begin();
        while (start != s.end() && std::isspace(static_cast<unsigned char>(*start))) {
            ++start;
        }

        if (start == s.end()) {
            return "";
        }

        auto end = s.end();
        do {
            --end;
        } while (end != start && std::isspace(static_cast<unsigned char>(*end)));

        return std::string(start, end + 1);
    }

    inline std::optional<std::string> read_file(const std::string& path, size_t max_bytes = 1<<20) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return std::nullopt;
        
        // Check size
        f.seekg(0, std::ios::end);
        size_t size = f.tellg();
        f.seekg(0, std::ios::beg);
        
        if (size > max_bytes) return std::nullopt;
        
        std::string buffer(size, '\0');
        if (f.read(&buffer[0], size)) return buffer;
        return std::nullopt;
    }

    inline std::vector<std::string> read_lines(const std::string& path) {
        std::vector<std::string> lines;
        std::ifstream f(path);
        if (!f) return lines;
        std::string line;
        while (std::getline(f, line)) {
            lines.push_back(line);
        }
        return lines;
    }
    
    inline bool is_world_writable(const std::string& path) {
        std::error_code ec;
        auto status = fs::status(path, ec);
        if (ec) return false;
        return (status.permissions() & fs::perms::others_write) != fs::perms::none;
    }

    inline std::string get_proc_path(int pid, const std::string& file = "") {
        std::string p = "/proc/" + std::to_string(pid);
        if (!file.empty()) p += "/" + file;
        return p;
    }

    inline std::string get_sys_path(const std::string& file = "") {
         return "/sys/" + file;
    }
}
