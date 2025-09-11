#include <iostream>
#include <regex>
#include <string>

int main() {
    std::string bad_regex = "[invalid regex";
    std::string long_regex(600, 'a');
    
    std::cout << "Testing bad regex: " << bad_regex << std::endl;
    try {
        std::regex re(bad_regex, std::regex::ECMAScript);
        std::cout << "Bad regex compiled successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Bad regex failed: " << e.what() << std::endl;
    }
    
    std::cout << "Long regex length: " << long_regex.size() << std::endl;
    std::cout << "MAX_REGEX_LENGTH: 512" << std::endl;
    
    return 0;
}
