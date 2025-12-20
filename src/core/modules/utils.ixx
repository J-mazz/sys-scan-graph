module;
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <fstream>
#include <filesystem>
#include <cctype>

// GCOVR_EXCL_START
export module sys_scan.utils;
export import :helper;

namespace fs = std::filesystem;

export namespace sys_scan::utils {

    inline std::string trim(std::string_view s) {
        auto is_space = [](unsigned char c) { return std::isspace(c); };
        std::size_t start = 0;
        while (start < s.size() && is_space(static_cast<unsigned char>(s[start]))) ++start;
        std::size_t end = s.size();
        while (end > start && is_space(static_cast<unsigned char>(s[end - 1]))) --end;
        return std::string{s.substr(start, end - start)};
    }

    // C++23: static constexpr variables inside constexpr functions
    constexpr bool is_safe_path_char(char c) {
        static constexpr std::string_view safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-";
        return safe_chars.find(c) != std::string_view::npos;
    }

    inline std::vector<std::string_view> split_lines_sv(std::string_view content) {
        std::vector<std::string_view> lines;
        size_t start = 0;
        while (start < content.size()) {
            size_t pos = content.find('\n', start);
            if (pos == std::string_view::npos) {
                lines.emplace_back(content.substr(start));
                break;
            }
            lines.emplace_back(content.substr(start, pos - start));
            start = pos + 1;
        }
        return lines;
    }

    inline std::vector<std::string> read_lines_from_string(const std::string& content) {
        std::vector<std::string> lines;
        lines.reserve(128);
        for (auto sv : split_lines_sv(content)) {
            lines.emplace_back(sv);
        }
        return lines;
    }

    inline std::optional<std::string> read_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return std::nullopt;
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }
}
// GCOVR_EXCL_STOP
