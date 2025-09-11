#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/Utils.h"
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace sys_scan {
namespace utils {

class UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for tests
        temp_dir = fs::temp_directory_path() / "sys_scan_test";
        fs::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files and directory
        fs::remove_all(temp_dir);
    }

    fs::path temp_dir;
    fs::path create_temp_file(const std::string& content = "") {
        auto temp_file = temp_dir / ("test_" + std::to_string(rand()) + ".txt");
        std::ofstream file(temp_file);
        file << content;
        file.close();
        return temp_file;
    }
};

TEST_F(UtilsTest, ReadLinesEmptyFile) {
    auto temp_file = create_temp_file("");
    auto lines = read_lines(temp_file.string());
    EXPECT_TRUE(lines.empty());
}

TEST_F(UtilsTest, ReadLinesSingleLine) {
    auto temp_file = create_temp_file("Hello World");
    auto lines = read_lines(temp_file.string());
    ASSERT_EQ(lines.size(), 1);
    EXPECT_EQ(lines[0], "Hello World");
}

TEST_F(UtilsTest, ReadLinesMultipleLines) {
    std::string content = "Line 1\nLine 2\nLine 3\n";
    auto temp_file = create_temp_file(content);
    auto lines = read_lines(temp_file.string());
    ASSERT_EQ(lines.size(), 3);
    EXPECT_EQ(lines[0], "Line 1");
    EXPECT_EQ(lines[1], "Line 2");
    EXPECT_EQ(lines[2], "Line 3");
}

TEST_F(UtilsTest, ReadLinesWithEmptyLines) {
    std::string content = "Line 1\n\nLine 3\n";
    auto temp_file = create_temp_file(content);
    auto lines = read_lines(temp_file.string());
    ASSERT_EQ(lines.size(), 3);
    EXPECT_EQ(lines[0], "Line 1");
    EXPECT_EQ(lines[1], "");
    EXPECT_EQ(lines[2], "Line 3");
}

TEST_F(UtilsTest, ReadLinesNonExistentFile) {
    auto lines = read_lines("/non/existent/file.txt");
    EXPECT_TRUE(lines.empty());
}

TEST_F(UtilsTest, ReadFileEmptyFile) {
    auto temp_file = create_temp_file("");
    auto content = read_file(temp_file.string());
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content.value(), "");
}

TEST_F(UtilsTest, ReadFileWithContent) {
    std::string test_content = "This is test content\nwith multiple lines\nand special chars: \t\n";
    auto temp_file = create_temp_file(test_content);
    auto content = read_file(temp_file.string());
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content.value(), test_content);
}

TEST_F(UtilsTest, ReadFileNonExistentFile) {
    auto content = read_file("/non/existent/file.txt");
    EXPECT_FALSE(content.has_value());
}

TEST_F(UtilsTest, ReadFileWithSizeLimit) {
    std::string large_content(2000, 'A'); // 2000 characters
    auto temp_file = create_temp_file(large_content);
    auto content = read_file(temp_file.string(), 1000); // Limit to 1000 bytes
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content.value().size(), 1000);
    EXPECT_EQ(content.value(), std::string(1000, 'A'));
}

TEST_F(UtilsTest, ReadFileExactSizeLimit) {
    std::string content(1000, 'B');
    auto temp_file = create_temp_file(content);
    auto result = read_file(temp_file.string(), 1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().size(), 1000);
    EXPECT_EQ(result.value(), content);
}

TEST_F(UtilsTest, IsWorldWritableNonExistentFile) {
    EXPECT_FALSE(is_world_writable("/non/existent/file.txt"));
}

TEST_F(UtilsTest, IsWorldWritableRegularFile) {
    auto temp_file = create_temp_file("test");
    // Regular files created by create_temp_file should not be world-writable by default
    EXPECT_FALSE(is_world_writable(temp_file.string()));
}

TEST_F(UtilsTest, IsWorldWritableWorldWritableFile) {
    auto temp_file = create_temp_file("test");

    // Make the file world-writable
    chmod(temp_file.c_str(), 0666);

    // Now it should be world-writable
    EXPECT_TRUE(is_world_writable(temp_file.string()));
}

TEST_F(UtilsTest, TrimEmptyString) {
    EXPECT_EQ(trim(""), "");
}

TEST_F(UtilsTest, TrimNoWhitespace) {
    EXPECT_EQ(trim("hello"), "hello");
}

TEST_F(UtilsTest, TrimLeadingWhitespace) {
    EXPECT_EQ(trim("  hello"), "hello");
}

TEST_F(UtilsTest, TrimTrailingWhitespace) {
    EXPECT_EQ(trim("hello  "), "hello");
}

TEST_F(UtilsTest, TrimBothWhitespace) {
    EXPECT_EQ(trim("  hello  "), "hello");
}

TEST_F(UtilsTest, TrimOnlyWhitespace) {
    EXPECT_EQ(trim("   "), "");
}

TEST_F(UtilsTest, TrimTabsAndSpaces) {
    EXPECT_EQ(trim("\t  hello \t "), "hello");
}

TEST_F(UtilsTest, TrimNewlines) {
    EXPECT_EQ(trim("\nhello\n"), "hello");
}

TEST_F(UtilsTest, TrimMixedWhitespace) {
    EXPECT_EQ(trim(" \t\n hello \n\t "), "hello");
}

TEST_F(UtilsTest, ReadFileTrimEmptyFile) {
    auto temp_file = create_temp_file("");
    EXPECT_EQ(read_file_trim(temp_file.string()), "");
}

TEST_F(UtilsTest, ReadFileTrimSingleLine) {
    auto temp_file = create_temp_file("Hello World");
    EXPECT_EQ(read_file_trim(temp_file.string()), "Hello World");
}

TEST_F(UtilsTest, ReadFileTrimWithNewline) {
    auto temp_file = create_temp_file("Hello World\n");
    EXPECT_EQ(read_file_trim(temp_file.string()), "Hello World");
}

TEST_F(UtilsTest, ReadFileTrimWithCarriageReturn) {
    auto temp_file = create_temp_file("Hello World\r");
    EXPECT_EQ(read_file_trim(temp_file.string()), "Hello World");
}

TEST_F(UtilsTest, ReadFileTrimWithBothCRLF) {
    auto temp_file = create_temp_file("Hello World\r\n");
    EXPECT_EQ(read_file_trim(temp_file.string()), "Hello World");
}

TEST_F(UtilsTest, ReadFileTrimMultipleLines) {
    auto temp_file = create_temp_file("First Line\nSecond Line\nThird Line");
    EXPECT_EQ(read_file_trim(temp_file.string()), "First Line");
}

TEST_F(UtilsTest, ReadFileTrimNonExistentFile) {
    EXPECT_EQ(read_file_trim("/non/existent/file.txt"), "");
}

TEST_F(UtilsTest, ReadFileTrimWhitespaceOnly) {
    auto temp_file = create_temp_file("   \t   \n");
    EXPECT_EQ(read_file_trim(temp_file.string()), "   \t   ");
}

TEST_F(UtilsTest, ReadFileTrimEmptyLine) {
    auto temp_file = create_temp_file("\n");
    EXPECT_EQ(read_file_trim(temp_file.string()), "");
}

TEST_F(UtilsTest, IntegrationReadLinesAndTrim) {
    std::string content = "  line1  \n\tline2\t\n  line3  \n";
    auto temp_file = create_temp_file(content);

    auto lines = read_lines(temp_file.string());
    ASSERT_EQ(lines.size(), 3);

    // Test trimming each line
    EXPECT_EQ(trim(lines[0]), "line1");
    EXPECT_EQ(trim(lines[1]), "line2");
    EXPECT_EQ(trim(lines[2]), "line3");
}

TEST_F(UtilsTest, LargeFileHandling) {
    // Create a moderately large file
    std::string large_content(50000, 'X');
    auto temp_file = create_temp_file(large_content);

    // Test read_file with default limit
    auto content = read_file(temp_file.string());
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content.value().size(), large_content.size());

    // Test read_file with small limit
    auto limited_content = read_file(temp_file.string(), 1000);
    ASSERT_TRUE(limited_content.has_value());
    EXPECT_EQ(limited_content.value().size(), 1000);
}

TEST_F(UtilsTest, BinaryFileHandling) {
    // Create a file with binary data
    std::string binary_data;
    for (int i = 0; i < 256; ++i) {
        binary_data += static_cast<char>(i);
    }

    auto temp_file = temp_dir / "binary_test.bin";
    std::ofstream file(temp_file, std::ios::binary);
    file.write(binary_data.data(), binary_data.size());
    file.close();

    auto content = read_file(temp_file.string());
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content.value().size(), binary_data.size());
}

TEST_F(UtilsTest, FilePermissions) {
    auto temp_file = create_temp_file("test");

    // Test that we can read our own files
    auto content = read_file(temp_file.string());
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content.value(), "test");

    // Test read_lines on our own files
    auto lines = read_lines(temp_file.string());
    ASSERT_EQ(lines.size(), 1);
    EXPECT_EQ(lines[0], "test");
}

TEST_F(UtilsTest, EdgeCaseFileNames) {
    // Test with files that have special characters in names
    auto special_file = temp_dir / "file with spaces & special chars.txt";
    std::string content = "special content";
    std::ofstream file(special_file);
    file << content;
    file.close();

    auto read_content = read_file(special_file.string());
    ASSERT_TRUE(read_content.has_value());
    EXPECT_EQ(read_content.value(), content);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace utils
} // namespace sys_scan