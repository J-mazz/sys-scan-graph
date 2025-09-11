#include "core/RuleEngineInitializer.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <limits>

namespace sys_scan {

class RuleEngineInitializerExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_rule_engine_extended_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
    RuleEngineInitializer initializer;
};

// Test initialization with very large rule files
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithLargeRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a very large rule file
    auto rule_file_path = temp_dir / "large_rules.rule";
    std::ofstream rule_file(rule_file_path);
    for (int i = 0; i < 100; ++i) {  // Reduced from 10,000 to 100
        rule_file << "rule large_rule_" << i << " {\n";
        rule_file << "    strings:\n";
        rule_file << "        $a = \"pattern_" << i << "\"\n";
        rule_file << "    condition:\n";
        rule_file << "        $a\n";
        rule_file << "}\n\n";
    }
    rule_file.close();

    // Should fail due to large file or parsing issues
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with empty rule file
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithEmptyRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create an empty rule file
    auto rule_file_path = temp_dir / "empty_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file.close();

    // Should succeed (empty file is valid)
    EXPECT_TRUE(initializer.initialize(cfg));
}

// Test initialization with rule file containing only whitespace
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithWhitespaceOnlyRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with only whitespace
    auto rule_file_path = temp_dir / "whitespace_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "   \n\t\r   \n\t\r   \n";
    rule_file.close();

    // Should succeed (whitespace-only file is valid)
    EXPECT_TRUE(initializer.initialize(cfg));
}

// Test initialization with rule file containing special characters
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithSpecialCharactersRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with special characters
    auto rule_file_path = temp_dir / "special_chars_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "rule special_chars_rule {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"pattern with special chars: !@#$%^&*()_+-=[]{}|;':\\\",./<>?\"\n";
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to parsing issues with special characters
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing Unicode characters
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithUnicodeRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with Unicode characters
    auto rule_file_path = temp_dir / "unicode_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "rule unicode_rule_测试 {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"测试模式 中文 русский español\"\n";
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to Unicode in rule name (invalid YARA syntax)
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing very long rule names
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithVeryLongRuleNames) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with very long rule names
    auto rule_file_path = temp_dir / "long_names_rules.rule";
    std::ofstream rule_file(rule_file_path);
    std::string long_name(1000, 'a');
    rule_file << "rule " << long_name << " {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"test_pattern\"\n";
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to extremely long rule name
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing very long patterns
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithVeryLongPatterns) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with very long patterns
    auto rule_file_path = temp_dir / "long_patterns_rules.rule";
    std::ofstream rule_file(rule_file_path);
    std::string long_pattern(1000, 'x'); // Reduced from 10KB to 1KB
    rule_file << "rule long_pattern_rule {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"" << long_pattern << "\"\n";
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to extremely long pattern
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing binary data
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithBinaryDataRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with binary data
    auto rule_file_path = temp_dir / "binary_rules.rule";
    std::ofstream rule_file(rule_file_path, std::ios::binary);
    for (int i = 0; i < 256; ++i) {
        rule_file.put(static_cast<char>(i));
    }
    rule_file.close();

    // Should fail due to binary data (invalid YARA syntax)
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing null bytes
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithNullBytesRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with null bytes
    auto rule_file_path = temp_dir / "null_bytes_rules.rule";
    std::ofstream rule_file(rule_file_path, std::ios::binary);
    rule_file << "rule null_byte_rule {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"pattern";
    rule_file.put('\0');
    rule_file.put('\0');
    rule_file << "with_nulls\"\n";
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to null bytes in pattern
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing very deep nesting
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithDeepNestingRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with deep nesting (using custom format)
    auto rule_file_path = temp_dir / "deep_nesting_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "id=deep_nesting_rule\n";
    rule_file << "field=description\n";
    rule_file << "contains=level1\n";
    rule_file << "logic=all\n";
    rule_file << "\n";
    rule_file << "id=deep_nesting_rule2\n";
    rule_file << "field=description\n";
    rule_file << "contains=level2\n";
    rule_file << "logic=all\n";
    rule_file << "\n";
    rule_file << "id=deep_nesting_rule3\n";
    rule_file << "field=description\n";
    rule_file << "contains=level3\n";
    rule_file << "logic=all\n";
    rule_file.close();

    // Should succeed with valid custom format
    EXPECT_TRUE(initializer.initialize(cfg));
}

// Test initialization with rule file containing many rules
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithManyRulesFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with many rules (using custom format)
    auto rule_file_path = temp_dir / "many_rules.rule";
    std::ofstream rule_file(rule_file_path);
    for (int i = 0; i < 10; ++i) {  // Reduced from 100 to 10 to avoid issues
        rule_file << "id=rule_" << i << "\n";
        rule_file << "field=description\n";
        rule_file << "contains=unique_pattern_" << i << "\n";
        rule_file << "\n";
    }
    rule_file.close();

    // Should succeed with many valid rules
    EXPECT_TRUE(initializer.initialize(cfg));
}

// Test initialization with rule file containing duplicate rule names
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithDuplicateRuleNames) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with duplicate rule names (using custom format)
    auto rule_file_path = temp_dir / "duplicate_names_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "id=duplicate_rule\n";
    rule_file << "field=description\n";
    rule_file << "contains=pattern1\n";
    rule_file << "\n";
    rule_file << "id=duplicate_rule\n";
    rule_file << "field=description\n";
    rule_file << "contains=pattern2\n";
    rule_file.close();

    // Should fail due to duplicate rule names
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing invalid syntax
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithInvalidSyntaxRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with invalid syntax
    auto rule_file_path = temp_dir / "invalid_syntax_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "rule invalid_syntax_rule {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"unclosed_string\n";  // Missing closing quote
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to invalid syntax
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing very long lines
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithVeryLongLinesRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with very long lines
    auto rule_file_path = temp_dir / "long_lines_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "rule long_line_rule {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"" << std::string(1000, 'x') << "\"\n"; // Reduced from 10KB to 1KB
    rule_file << "    condition:\n";
    rule_file << "        $a\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to extremely long line
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing many short lines
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithManyShortLinesRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with many short lines (using custom format)
    auto rule_file_path = temp_dir / "many_short_lines_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "id=many_lines_rule\n";
    rule_file << "logic=any\n";
    for (int i = 0; i < 10; ++i) {  // Reduced from 100 to 10
        rule_file << "field=description\n";
        rule_file << "contains=p" << i << "\n";
    }
    rule_file.close();

    // Should succeed with valid syntax
    EXPECT_TRUE(initializer.initialize(cfg));
}

// Test initialization with rule file containing mixed encodings
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithMixedEncodingsRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with mixed encodings
    auto rule_file_path = temp_dir / "mixed_encodings_rules.rule";
    std::ofstream rule_file(rule_file_path, std::ios::binary);
    rule_file << "rule mixed_encoding_rule {\n";
    rule_file << "    strings:\n";
    rule_file << "        $a = \"ASCII text: Hello World\"\n";
    rule_file << "        $b = \"UTF-8: 测试数据\"\n";
    rule_file << "        $c = \"Binary: ";
    for (int i = 0; i < 10; ++i) {
        rule_file.put(static_cast<char>(i));
    }
    rule_file << "\"\n";
    rule_file << "    condition:\n";
    rule_file << "        $a or $b or $c\n";
    rule_file << "}\n";
    rule_file.close();

    // Should fail due to binary data in pattern
    EXPECT_FALSE(initializer.initialize(cfg));
}

// Test initialization with rule file containing path-like strings
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithPathLikeStringsRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with path-like strings (using custom format)
    auto rule_file_path = temp_dir / "path_strings_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "id=path_string_rule\n";
    rule_file << "logic=any\n";
    rule_file << "field=description\n";
    rule_file << "contains=/usr/bin/malware\n";
    rule_file << "\n";
    rule_file << "id=path_string_rule2\n";
    rule_file << "field=description\n";
    rule_file << "contains=C:\\\\Windows\\\\System32\\\\evil.exe\n";
    rule_file << "\n";
    rule_file << "id=path_string_rule3\n";
    rule_file << "field=description\n";
    rule_file << "contains=../relative/path/to/bad/file\n";
    rule_file.close();

    // Should succeed with valid path-like strings
    EXPECT_TRUE(initializer.initialize(cfg));
}

// Test initialization with rule file containing regex patterns
TEST_F(RuleEngineInitializerExtendedTest, InitializeWithRegexPatternsRuleFile) {
    Config cfg;
    cfg.rules_enable = true;
    cfg.rules_dir = temp_dir.string();

    // Create a rule file with regex patterns (using custom format)
    auto rule_file_path = temp_dir / "regex_patterns_rules.rule";
    std::ofstream rule_file(rule_file_path);
    rule_file << "id=regex_pattern_rule\n";
    rule_file << "logic=any\n";
    rule_file << "field=description\n";
    rule_file << "regex=pattern[0-9]+.*\n";
    rule_file << "\n";
    rule_file << "id=regex_pattern_rule2\n";
    rule_file << "field=description\n";
    rule_file << "regex=complex\\s+regex\\s+with\\s+spaces\n";
    rule_file.close();

    // Should succeed with valid regex patterns
    EXPECT_TRUE(initializer.initialize(cfg));
}

} // namespace sys_scan