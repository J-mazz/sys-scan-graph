module;
#include <string>
#include <vector>
#include <sstream>
export module sys_scan.utils:helper;

export namespace sys_scan::utils {
    inline std::vector<std::string> read_lines_from_string(const std::string& content) {
        std::vector<std::string> lines;
        std::stringstream ss(content);
        std::string line;
        while(std::getline(ss, line)) {
            lines.push_back(line);
        }
        return lines;
    }
}
