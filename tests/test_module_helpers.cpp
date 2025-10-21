#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/ModuleHelpers.h"
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <cstring>

// Test fixture for ModuleHelpers
class ModuleHelpersTest : public ::testing::Test {
protected:
    std::string temp_dir;

    void SetUp() override {
        // Create temporary directory for test files
        char template_path[] = "/tmp/module_helpers_test_XXXXXX";
        temp_dir = mkdtemp(template_path);
        ASSERT_FALSE(temp_dir.empty()) << "Failed to create temp directory";
    }

    void TearDown() override {
        // Clean up temporary directory
        if (!temp_dir.empty()) {
            std::filesystem::remove_all(temp_dir);
        }
    }

    // Helper to create a test file with specific content
    std::string create_test_file(const std::string& filename, const std::string& content) {
        std::string filepath = temp_dir + "/" + filename;
        std::ofstream file(filepath, std::ios::binary);
        EXPECT_TRUE(file.is_open()) << "Failed to create test file: " << filepath;
        if (!file.is_open()) {
            return "";  // Should not reach here due to EXPECT_TRUE failure
        }
        file.write(content.c_str(), content.size());
        file.close();
        return filepath;
    }

    // Helper to create a minimal ELF file for testing
    std::string create_minimal_elf(const std::string& filename, bool is64bit = true) {
        std::vector<unsigned char> elf_header;
        if (is64bit) {
            // ELF64 header (64 bytes)
            elf_header = {
                0x7f, 'E', 'L', 'F',  // ELF magic
                2,                    // 64-bit
                1,                    // Little endian
                1,                    // Version
                0,                    // OS ABI
                0,                    // ABI version
                0,0,0,0,0,0,0,       // Padding
                1, 0,                 // ET_REL (relocatable)
                0x3e, 0,              // EM_X86_64
                1, 0, 0, 0,           // Version
                0, 0, 0, 0, 0, 0, 0, 0, // Entry point
                0, 0, 0, 0,           // Program header offset
                64, 0, 0, 0,          // Section header offset (64)
                0, 0, 0, 0,           // Flags
                64, 0,                 // ELF header size
                0, 0,                 // Program header entry size
                0, 0,                 // Program header count
                40, 0,                // Section header entry size
                3, 0,                 // Section header count
                1, 0                  // String table section index
            };
        } else {
            // ELF32 header (52 bytes)
            elf_header = {
                0x7f, 'E', 'L', 'F',  // ELF magic
                1,                    // 32-bit
                1,                    // Little endian
                1,                    // Version
                0,                    // OS ABI
                0,                    // ABI version
                0,0,0,0,0,0,0,       // Padding
                1, 0,                 // ET_REL (relocatable)
                0x03, 0,              // EM_386
                1, 0, 0, 0,           // Version
                0, 0, 0, 0,           // Entry point
                0, 0, 0, 0,           // Program header offset
                52, 0, 0, 0,          // Section header offset (52)
                0, 0, 0, 0,           // Flags
                52, 0,                 // ELF header size
                0, 0,                 // Program header entry size
                0, 0,                 // Program header count
                40, 0,                // Section header entry size
                3, 0,                 // Section header count
                1, 0                  // String table section index
            };
        }

        return create_test_file(filename, std::string(elf_header.begin(), elf_header.end()));
    }
};

// Test CompressionUtils
TEST_F(ModuleHelpersTest, CompressionUtils_IsCompressed) {
    // Test compressed file detection
    EXPECT_TRUE(sys_scan::CompressionUtils::is_compressed("test.ko.xz"));
    EXPECT_TRUE(sys_scan::CompressionUtils::is_compressed("test.ko.gz"));
    EXPECT_FALSE(sys_scan::CompressionUtils::is_compressed("test.ko"));
    EXPECT_FALSE(sys_scan::CompressionUtils::is_compressed("test.o"));
    EXPECT_FALSE(sys_scan::CompressionUtils::is_compressed("test.ko.xz.extra"));
}

TEST_F(ModuleHelpersTest, CompressionUtils_DecompressGz_NonExistentFile) {
    // Test decompressing non-existent gz file
    EXPECT_EQ(sys_scan::CompressionUtils::decompress_gz_bounded("/non/existent/file.gz"), "");
}

TEST_F(ModuleHelpersTest, CompressionUtils_DecompressXz_NonExistentFile) {
    // Test decompressing non-existent xz file
    EXPECT_EQ(sys_scan::CompressionUtils::decompress_xz_bounded("/non/existent/file.xz"), "");
}

// Test ElfModuleHeuristics
TEST_F(ModuleHelpersTest, ElfModuleHeuristics_ParseSections_InvalidFile) {
    // Test parsing sections from non-existent file
    auto sections = sys_scan::ElfModuleHeuristics::parse_sections("/non/existent/file");
    EXPECT_TRUE(sections.empty());
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_ParseSections_NonElfFile) {
    // Test parsing sections from non-ELF file
    std::string filepath = create_test_file("notelf.txt", "This is not an ELF file");
    auto sections = sys_scan::ElfModuleHeuristics::parse_sections(filepath);
    EXPECT_TRUE(sections.empty());
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_ParseSections_EmptyFile) {
    // Test parsing sections from empty file
    std::string filepath = create_test_file("empty.elf", "");
    auto sections = sys_scan::ElfModuleHeuristics::parse_sections(filepath);
    EXPECT_TRUE(sections.empty());
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_ParseSections_IncompleteHeader) {
    // Test parsing sections from file with incomplete ELF header
    std::string filepath = create_test_file("incomplete.elf", std::string("\x7f") + "ELF");
    auto sections = sys_scan::ElfModuleHeuristics::parse_sections(filepath);
    EXPECT_TRUE(sections.empty());
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasWxSection_EmptySections) {
    // Test W+X section detection with empty sections
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections;
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_wx_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasWxSection_NoWxSections) {
    // Test W+X section detection with sections that don't have W+X
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {"", 0x1, 100},  // Write only
        {"", 0x4, 200},  // Execute only
        {"", 0x0, 300}   // No flags
    };
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_wx_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasWxSection_WithWxSection) {
    // Test W+X section detection with W+X section present
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {"", 0x1, 100},  // Write only
        {"", 0x5, 200},  // Write + Execute (W+X)
        {"", 0x0, 300}   // No flags
    };
    EXPECT_TRUE(sys_scan::ElfModuleHeuristics::has_wx_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasLargeTextSection_EmptySections) {
    // Test large .text section detection with empty sections
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections;
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_large_text_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasLargeTextSection_NoTextSection) {
    // Test large .text section detection with no .text section
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".data", 0, 100},
        {".bss", 0, 200},
        {".rodata", 0, 300}
    };
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_large_text_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasLargeTextSection_SmallTextSection) {
    // Test large .text section detection with small .text section
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0, 1024},  // 1KB, not large
        {".data", 0, 100}
    };
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_large_text_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasLargeTextSection_LargeTextSection) {
    // Test large .text section detection with large .text section
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0, 6 * 1024 * 1024},  // 6MB, large
        {".data", 0, 100}
    };
    EXPECT_TRUE(sys_scan::ElfModuleHeuristics::has_large_text_section(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasSuspiciousSectionName_EmptySections) {
    // Test suspicious section name detection with empty sections
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections;
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_suspicious_section_name(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasSuspiciousSectionName_NoSuspiciousNames) {
    // Test suspicious section name detection with normal section names
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0, 100},
        {".data", 0, 200},
        {".bss", 0, 300},
        {".rodata", 0, 400}
    };
    EXPECT_FALSE(sys_scan::ElfModuleHeuristics::has_suspicious_section_name(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasSuspiciousSectionName_WithSuspiciousNames) {
    // Test suspicious section name detection with suspicious names
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0, 100},
        {".evil", 0, 200},  // Suspicious
        {".data", 0, 300}
    };
    EXPECT_TRUE(sys_scan::ElfModuleHeuristics::has_suspicious_section_name(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasSuspiciousSectionName_NumericSections) {
    // Test suspicious section name detection with numeric section names
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0, 100},
        {".123", 0, 200},   // Suspicious (numeric)
        {".data", 0, 300}
    };
    EXPECT_TRUE(sys_scan::ElfModuleHeuristics::has_suspicious_section_name(sections));
}

TEST_F(ModuleHelpersTest, ElfModuleHeuristics_HasSuspiciousSectionName_SingleChar) {
    // Test suspicious section name detection with single character names
    std::vector<sys_scan::ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0, 100},
        {"x", 0, 200},      // Suspicious (single char)
        {".data", 0, 300}
    };
    EXPECT_TRUE(sys_scan::ElfModuleHeuristics::has_suspicious_section_name(sections));
}

// Test SignatureAnalyzer
TEST_F(ModuleHelpersTest, SignatureAnalyzer_IsUnsignedModule_NonExistentFile) {
    // Test unsigned module detection on non-existent file
    EXPECT_TRUE(sys_scan::SignatureAnalyzer::is_unsigned_module("/non/existent/file"));
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_IsUnsignedModule_EmptyFile) {
    // Test unsigned module detection on empty file
    std::string filepath = create_test_file("empty.ko", "");
    EXPECT_TRUE(sys_scan::SignatureAnalyzer::is_unsigned_module(filepath));
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_IsUnsignedModule_SignedModule) {
    // Test unsigned module detection on file with signature marker
    std::string content = "Some module content\nModule signature appended\nSignature data";
    std::string filepath = create_test_file("signed.ko", content);
    EXPECT_FALSE(sys_scan::SignatureAnalyzer::is_unsigned_module(filepath));
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_IsUnsignedModule_UnsignedModule) {
    // Test unsigned module detection on file without signature marker
    std::string content = "Some module content without signature marker";
    std::string filepath = create_test_file("unsigned.ko", content);
    EXPECT_TRUE(sys_scan::SignatureAnalyzer::is_unsigned_module(filepath));
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_IsUnsignedModule_SignatureAtEnd) {
    // Test unsigned module detection with signature marker at end of large file
    std::string content = std::string(5000, 'A') + "\nModule signature appended\n";
    std::string filepath = create_test_file("signed_large.ko", content);
    EXPECT_FALSE(sys_scan::SignatureAnalyzer::is_unsigned_module(filepath));
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_ComputeSha256_NonExistentFile) {
    // Test SHA256 computation on non-existent file
    EXPECT_EQ(sys_scan::SignatureAnalyzer::compute_sha256("/non/existent/file"), "");
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_ComputeSha256_EmptyFile) {
    // Test SHA256 computation on empty file
    std::string filepath = create_test_file("empty.txt", "");
    std::string hash = sys_scan::SignatureAnalyzer::compute_sha256(filepath);
#ifdef SYS_SCAN_HAVE_OPENSSL
    // Expected SHA256 of empty string
    EXPECT_EQ(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
#else
    EXPECT_EQ(hash, "");
#endif
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_ComputeSha256_SmallFile) {
    // Test SHA256 computation on small file
    std::string content = "Hello, World!";
    std::string filepath = create_test_file("hello.txt", content);
    std::string hash = sys_scan::SignatureAnalyzer::compute_sha256(filepath);
#ifdef SYS_SCAN_HAVE_OPENSSL
    // Expected SHA256 of "Hello, World!"
    EXPECT_EQ(hash, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
#else
    EXPECT_EQ(hash, "");
#endif
}

TEST_F(ModuleHelpersTest, SignatureAnalyzer_ComputeSha256_LargeFile) {
    // Test SHA256 computation on large file (limited to 2MB)
    std::string content = std::string(100000, 'A');  // 100KB of 'A's
    std::string filepath = create_test_file("large.txt", content);
    std::string hash = sys_scan::SignatureAnalyzer::compute_sha256(filepath);
#ifdef SYS_SCAN_HAVE_OPENSSL
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.length(), 64);  // SHA256 hex is 64 characters
#else
    EXPECT_EQ(hash, "");
#endif
}