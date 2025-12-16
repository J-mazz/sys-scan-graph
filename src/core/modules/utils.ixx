module;
#include <algorithm>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <fstream>
#include <filesystem>
#include <cctype>

export module sys_scan.utils;
export import :helper;

namespace fs = std::filesystem;

export namespace sys_scan::utils {

    // C++23: Ranges & Views for zero-copy trimming
    inline std::string trim(std::string_view s) {
        auto is_space = [](unsigned char c) { return std::isspace(c); };
        auto dropped = s | std::views::drop_while(is_space);
        auto reversed = dropped | std::views::reverse | std::views::drop_while(is_space);

        // In C++23 compliant compilers: return reversed | std::views::reverse | std::ranges::to<std::string>();
        // Fallback for partial C++23 support:
        auto final_view = reversed | std::views::reverse;
        return std::string(final_view.begin(), final_view.end());
    }

    // C++23: static constexpr variables inside constexpr functions
    constexpr bool is_safe_path_char(char c) {
        static constexpr std::string_view safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-";
        return safe_chars.find(c) != std::string_view::npos;
    }

    inline std::vector<std::string> read_lines_from_string(const std::string& content) {
        std::vector<std::string> lines;
        // C++23: Split view
        for (const auto& word : content | std::views::split('\n')) {
            lines.emplace_back(word.begin(), word.end());
        }
        return lines;
    }

    inline std::optional<std::string> read_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return std::nullopt;
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }
}
