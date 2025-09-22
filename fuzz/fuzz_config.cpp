#include "core/Config.h"
#include "core/ArgumentParser.h"
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz data to string
    std::string input(reinterpret_cast<const char*>(data), size);
    
    // Split into args (simple split on spaces)
    std::vector<std::string> args;
    size_t pos = 0;
    while (pos < input.size()) {
        size_t next = input.find(' ', pos);
        if (next == std::string::npos) {
            args.push_back(input.substr(pos));
            break;
        }
        args.push_back(input.substr(pos, next - pos));
        pos = next + 1;
    }
    
    // Convert to argv style
    std::vector<char*> argv;
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    
    // Try to parse
    sys_scan::ArgumentParser parser;
    sys_scan::Config cfg;
    parser.parse(static_cast<int>(argv.size()), argv.data(), cfg);
    
    return 0; // Non-zero return values are reserved for future use.
}