#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

std::string escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if ((unsigned char)c < 0x20) {
            std::ostringstream tmp;
            tmp << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
            o += tmp.str();
            std::cout << "Character " << (int)(unsigned char)c << " -> " << tmp.str() << std::endl;
        } else {
            o += c;
        }
    }
    return o;
}

int main() {
    std::string input = "Test\x00End";
    std::string result = escape(input);
    std::cout << "Input: " << input << std::endl;
    std::cout << "Result: " << result << std::endl;
    return 0;
}
