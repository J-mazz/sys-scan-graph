#include "Utils.h"
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

namespace sys_scan { namespace utils {

std::vector<std::string> read_lines(const std::string& path) {
    std::ifstream ifs(path);
    std::vector<std::string> lines;
    std::string line;
    while(std::getline(ifs, line)) lines.push_back(line);
    return lines;
}

std::optional<std::string> read_file(const std::string& path, size_t max_bytes) {
    std::ifstream ifs(path, std::ios::binary);
    if(!ifs) return std::nullopt;
    std::ostringstream ss; 
    ss << ifs.rdbuf();
    std::string data = ss.str();
    if(data.size() > max_bytes) data.resize(max_bytes);
    return data;
}

bool is_world_writable(const std::string& path) {
    struct stat st{}; if(stat(path.c_str(), &st)!=0) return false; return (st.st_mode & S_IWOTH);
}

std::string trim(const std::string& s){
    auto b = s.begin(); while(b!=s.end() && isspace((unsigned char)*b)) ++b;
    auto e = s.end(); while(e!=b && isspace((unsigned char)*(e-1))) --e;
    return std::string(b,e);
}

std::string read_file_trim(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::string s;
    std::getline(f, s);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

}} // namespaces
