#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/JsonUtil.h"
#include <chrono>
#include <string>

namespace sys_scan {
namespace jsonutil {

class JsonUtilTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No setup needed
    }
};

TEST_F(JsonUtilTest, EscapeEmptyString) {
    std::string input = "";
    std::string result = escape(input);
    EXPECT_EQ(result, "");
}

TEST_F(JsonUtilTest, EscapeNormalString) {
    std::string input = "Hello World";
    std::string result = escape(input);
    EXPECT_EQ(result, "Hello World");
}

TEST_F(JsonUtilTest, EscapeQuote) {
    std::string input = "He said \"Hello\"";
    std::string result = escape(input);
    EXPECT_EQ(result, "He said \\\"Hello\\\"");
}

TEST_F(JsonUtilTest, EscapeBackslash) {
    std::string input = "Path\\to\\file";
    std::string result = escape(input);
    EXPECT_EQ(result, "Path\\\\to\\\\file");
}

TEST_F(JsonUtilTest, EscapeNewline) {
    std::string input = "Line 1\nLine 2";
    std::string result = escape(input);
    EXPECT_EQ(result, "Line 1\\nLine 2");
}

TEST_F(JsonUtilTest, EscapeCarriageReturn) {
    std::string input = "Line 1\rLine 2";
    std::string result = escape(input);
    EXPECT_EQ(result, "Line 1\\rLine 2");
}

TEST_F(JsonUtilTest, EscapeTab) {
    std::string input = "Col1\tCol2";
    std::string result = escape(input);
    EXPECT_EQ(result, "Col1\\tCol2");
}

TEST_F(JsonUtilTest, EscapeControlCharacters) {
    std::string input = "Test\x01\x02\x03";
    std::string result = escape(input);
    EXPECT_EQ(result, "Test\\u0001\\u0002\\u0003");
}

TEST_F(JsonUtilTest, EscapeMixedSpecialChars) {
    std::string input = "Say \"Hello\\World\"\n\tTest";
    std::string result = escape(input);
    EXPECT_EQ(result, "Say \\\"Hello\\\\World\\\"\\n\\tTest");
}

TEST_F(JsonUtilTest, EscapeUnicodeCharacters) {
    std::string input = "Test\xE2\x9C\x93"; // Unicode checkmark
    std::string result = escape(input);
    // Unicode characters above 0x20 should not be escaped
    EXPECT_EQ(result, "Test\xE2\x9C\x93");
}

TEST_F(JsonUtilTest, EscapeNullCharacter) {
    std::string input = "Test";
    input += '\0';
    input += "End";
    std::string result = escape(input);
    EXPECT_EQ(result, "Test\\u0000End");
}

TEST_F(JsonUtilTest, EscapeAllControlCharacters) {
    for (int i = 0; i < 0x20; ++i) {
        if (i == '\t' || i == '\n' || i == '\r') continue; // These are handled with readable escapes
        std::string input(1, static_cast<char>(i));
        std::string result = escape(input);
        std::ostringstream expected;
        expected << "\\u" << std::hex << std::setw(4) << std::setfill('0') << i;
        EXPECT_EQ(result, expected.str()) << "Failed for control character " << i;
    }
}

TEST_F(JsonUtilTest, TimeToIsoEpoch) {
    std::chrono::system_clock::time_point epoch;
    std::string result = time_to_iso(epoch);
    EXPECT_EQ(result, "");
}

TEST_F(JsonUtilTest, TimeToIsoValidTime) {
    // Create a specific time: 2023-12-25 12:30:45 UTC
    // Use timegm to ensure it's interpreted as UTC
    std::tm tm_struct = {};
    tm_struct.tm_year = 123; // 2023 - 1900
    tm_struct.tm_mon = 11;   // December (0-based)
    tm_struct.tm_mday = 25;
    tm_struct.tm_hour = 12;
    tm_struct.tm_min = 30;
    tm_struct.tm_sec = 45;
    tm_struct.tm_isdst = 0;  // Not daylight saving

    // Use timegm if available, otherwise adjust for timezone
#ifdef __USE_MISC
    std::time_t time_val = timegm(&tm_struct);
#else
    // Fallback: set TZ to UTC temporarily
    std::string old_tz = getenv("TZ") ? getenv("TZ") : "";
    setenv("TZ", "UTC", 1);
    tzset();
    std::time_t time_val = mktime(&tm_struct);
    if (!old_tz.empty()) {
        setenv("TZ", old_tz.c_str(), 1);
    } else {
        unsetenv("TZ");
    }
    tzset();
#endif

    std::chrono::system_clock::time_point tp = std::chrono::system_clock::from_time_t(time_val);

    std::string result = time_to_iso(tp);
    EXPECT_EQ(result, "2023-12-25T12:30:45Z");
}

TEST_F(JsonUtilTest, TimeToIsoCurrentTime) {
    auto now = std::chrono::system_clock::now();
    std::string result = time_to_iso(now);

    // Result should be in ISO format: YYYY-MM-DDTHH:MM:SSZ
    EXPECT_EQ(result.length(), 20); // ISO format length
    EXPECT_EQ(result.substr(10, 1), "T"); // T separator
    EXPECT_EQ(result.back(), 'Z'); // Z suffix

    // Check date format - corrected positions
    EXPECT_TRUE(std::isdigit(result[0]) && std::isdigit(result[1]) &&
                std::isdigit(result[2]) && std::isdigit(result[3])); // Year
    EXPECT_EQ(result[4], '-');
    EXPECT_TRUE(std::isdigit(result[5]) && std::isdigit(result[6])); // Month
    EXPECT_EQ(result[7], '-');
    EXPECT_TRUE(std::isdigit(result[8]) && std::isdigit(result[9])); // Day
    EXPECT_EQ(result[10], 'T'); // Date/Time separator
    EXPECT_TRUE(std::isdigit(result[11]) && std::isdigit(result[12])); // Hour
    EXPECT_EQ(result[13], ':'); // Hour:Minute separator
    EXPECT_TRUE(std::isdigit(result[14]) && std::isdigit(result[15])); // Minute
    EXPECT_EQ(result[16], ':');
    EXPECT_TRUE(std::isdigit(result[17]) && std::isdigit(result[18])); // Second
    EXPECT_EQ(result[19], 'Z'); // UTC indicator
}

TEST_F(JsonUtilTest, TimeToIsoLeapYear) {
    // Test February 29, 2024 (leap year)
    std::tm tm_struct = {};
    tm_struct.tm_year = 124; // 2024 - 1900
    tm_struct.tm_mon = 1;    // February (0-based)
    tm_struct.tm_mday = 29;
    tm_struct.tm_hour = 0;
    tm_struct.tm_min = 0;
    tm_struct.tm_sec = 0;
    tm_struct.tm_isdst = 0;

#ifdef __USE_MISC
    std::time_t time_val = timegm(&tm_struct);
#else
    std::string old_tz = getenv("TZ") ? getenv("TZ") : "";
    setenv("TZ", "UTC", 1);
    tzset();
    std::time_t time_val = mktime(&tm_struct);
    if (!old_tz.empty()) {
        setenv("TZ", old_tz.c_str(), 1);
    } else {
        unsetenv("TZ");
    }
    tzset();
#endif

    std::chrono::system_clock::time_point tp = std::chrono::system_clock::from_time_t(time_val);

    std::string result = time_to_iso(tp);
    EXPECT_EQ(result, "2024-02-29T00:00:00Z");
}

TEST_F(JsonUtilTest, TimeToIsoYearBoundaries) {
    // Test year 2000
    std::tm tm_struct_2000 = {};
    tm_struct_2000.tm_year = 100; // 2000 - 1900
    tm_struct_2000.tm_mon = 0;
    tm_struct_2000.tm_mday = 1;
    tm_struct_2000.tm_hour = 0;
    tm_struct_2000.tm_min = 0;
    tm_struct_2000.tm_sec = 0;
    tm_struct_2000.tm_isdst = 0;

#ifdef __USE_MISC
    std::time_t time_2000 = timegm(&tm_struct_2000);
#else
    std::string old_tz = getenv("TZ") ? getenv("TZ") : "";
    setenv("TZ", "UTC", 1);
    tzset();
    std::time_t time_2000 = mktime(&tm_struct_2000);
    if (!old_tz.empty()) {
        setenv("TZ", old_tz.c_str(), 1);
    } else {
        unsetenv("TZ");
    }
    tzset();
#endif

    auto tp_2000 = std::chrono::system_clock::from_time_t(time_2000);
    EXPECT_EQ(time_to_iso(tp_2000), "2000-01-01T00:00:00Z");

    // Test year 2038 (potential 32-bit time_t boundary)
    std::tm tm_struct_2038 = {};
    tm_struct_2038.tm_year = 138; // 2038 - 1900
    tm_struct_2038.tm_mon = 0;
    tm_struct_2038.tm_mday = 1;
    tm_struct_2038.tm_hour = 0;
    tm_struct_2038.tm_min = 0;
    tm_struct_2038.tm_sec = 0;
    tm_struct_2038.tm_isdst = 0;

#ifdef __USE_MISC
    std::time_t time_2038 = timegm(&tm_struct_2038);
#else
    std::string old_tz = getenv("TZ") ? getenv("TZ") : "";
    setenv("TZ", "UTC", 1);
    tzset();
    std::time_t time_2038 = mktime(&tm_struct_2038);
    if (!old_tz.empty()) {
        setenv("TZ", old_tz.c_str(), 1);
    } else {
        unsetenv("TZ");
    }
    tzset();
#endif

    auto tp_2038 = std::chrono::system_clock::from_time_t(time_2038);
    EXPECT_EQ(time_to_iso(tp_2038), "2038-01-01T00:00:00Z");
}

TEST_F(JsonUtilTest, TimeToIsoTimeZoneHandling) {
    // All times should be converted to UTC regardless of local timezone
    auto now = std::chrono::system_clock::now();
    std::string result = time_to_iso(now);

    // The result should always end with Z (UTC)
    EXPECT_EQ(result.back(), 'Z');

    // And should be in the expected format
    EXPECT_EQ(result.length(), 20);
    EXPECT_EQ(result[10], 'T');
    EXPECT_EQ(result[13], ':');
    EXPECT_EQ(result[16], ':');
}

TEST_F(JsonUtilTest, EscapePerformance) {
    // Test with a large string to ensure no performance issues
    std::string large_input(10000, 'a');
    large_input[5000] = '"';
    large_input[7500] = '\\';

    auto start = std::chrono::high_resolution_clock::now();
    std::string result = escape(large_input);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 100); // Should complete in less than 100ms

    // Verify correctness
    EXPECT_EQ(result.size(), large_input.size() + 2); // Two escapes add 2 chars each
}

TEST_F(JsonUtilTest, TimeToIsoEdgeCases) {
    // Test minimum time_point
    std::chrono::system_clock::time_point min_time(std::chrono::system_clock::duration::min());
    std::string min_result = time_to_iso(min_time);
    // Should handle gracefully, either return empty or valid ISO string
    EXPECT_TRUE(min_result.empty() || min_result.length() == 20);

    // Test maximum time_point
    std::chrono::system_clock::time_point max_time(std::chrono::system_clock::duration::max());
    std::string max_result = time_to_iso(max_time);
    // Should handle gracefully
    EXPECT_TRUE(max_result.empty() || max_result.length() == 20);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace jsonutil
} // namespace sys_scan