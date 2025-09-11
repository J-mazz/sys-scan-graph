#include <iostream>
#include <chrono>
#include <ctime>
#include <string>

std::string time_to_iso(std::chrono::system_clock::time_point tp) {
    if (!tp.time_since_epoch().count()) return "";
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return buf;
}

int main() {
    auto now = std::chrono::system_clock::now();
    std::string result = time_to_iso(now);
    std::cout << "Time result: '" << result << "'" << std::endl;
    std::cout << "Length: " << result.length() << std::endl;
    for (size_t i = 0; i < result.length(); ++i) {
        std::cout << "result[" << i << "] = '" << result[i] << "' (" << (int)result[i] << ")" << std::endl;
    }
    return 0;
}
