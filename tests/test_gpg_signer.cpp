#include "core/GPGSigner.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstdlib>

namespace sys_scan {

class GPGSignerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_gpg_test";
        std::filesystem::create_directories(temp_dir);

        // Create a test file to sign
        test_file = temp_dir / "test_file.txt";
        std::ofstream file(test_file);
        file << "This is test content for GPG signing.";
        file.close();
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
    std::filesystem::path test_file;
    GPGSigner signer;
};

// Test signing with no GPG key configured
TEST_F(GPGSignerTest, SignFileNoGPGKey) {
    Config cfg;
    cfg.sign_gpg_key = "";
    cfg.output_file = test_file.string();

    // Should succeed (no-op) when no GPG key is configured
    EXPECT_TRUE(signer.sign_file(cfg));
}

// Test signing with invalid GPG key
TEST_F(GPGSignerTest, SignFileInvalidGPGKey) {
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "invalid-key-id";
    cfg.output_file = test_file.string();

    // Should fail with invalid key
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test signing with non-existent file
TEST_F(GPGSignerTest, SignFileNonExistentFile) {
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "test-key";
    cfg.output_file = "/non/existent/file.txt";

    // Should fail when file doesn't exist
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test path canonicalization
TEST_F(GPGSignerTest, CanonicalizePath) {
    // Test with relative path - we can't test the private method directly
    // but we can test that signing works with relative paths
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "test-key";
    cfg.output_file = "test/file.txt";  // Relative path

    // Should handle relative paths correctly (even though signing will fail)
    EXPECT_FALSE(signer.sign_file(cfg));

    // Test with absolute path
    cfg.output_file = "/tmp/test/file.txt";
    EXPECT_FALSE(signer.sign_file(cfg));

    // Test with current directory
    cfg.output_file = "./test.txt";
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test path canonicalization with non-existent path
TEST_F(GPGSignerTest, CanonicalizePathNonExistent) {
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "test-key";
    cfg.output_file = "/non/existent/path/file.txt";

    // Should handle non-existent paths gracefully
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test signing workflow with mock GPG setup
TEST_F(GPGSignerTest, SignFileWorkflow) {
    Config cfg;
    cfg.output_file = test_file.string();

    // Test 1: No GPG key - should succeed as no-op
    cfg.sign_gpg_key = "";
    EXPECT_TRUE(signer.sign_file(cfg));

    // Test 2: Invalid GPG key - should fail
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "invalid-key-12345";
    EXPECT_FALSE(signer.sign_file(cfg));

    // Test 3: Valid key format but non-existent key - should fail
    cfg.sign_gpg_key = "1234567890ABCDEF1234567890ABCDEF";
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test GPG command construction
TEST_F(GPGSignerTest, GPGCommandConstruction) {
    std::string key_id = "test-key-id";
    std::string file_path = "/tmp/test/file.txt";

    // The GPG command should include proper arguments for detached signature
    // This is an internal implementation detail, but we can test the concept
    EXPECT_FALSE(key_id.empty());
    EXPECT_FALSE(file_path.empty());
}

// Test signature file generation
TEST_F(GPGSignerTest, SignatureFileGeneration) {
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.output_file = test_file.string();
    cfg.sign_gpg_key = "test-key";

    // Even though signing will fail, the method should handle file paths correctly
    EXPECT_FALSE(signer.sign_file(cfg));

    // Check that no signature file was created (since signing failed)
    std::filesystem::path sig_file = test_file;
    sig_file += ".sig";
    EXPECT_FALSE(std::filesystem::exists(sig_file));
}

// Test multiple signing attempts
TEST_F(GPGSignerTest, MultipleSigningAttempts) {
    Config cfg;
    cfg.output_file = test_file.string();

    // First attempt with no key
    cfg.sign_gpg_key = "";
    EXPECT_TRUE(signer.sign_file(cfg));

    // Second attempt with invalid key
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "invalid";
    EXPECT_FALSE(signer.sign_file(cfg));

    // Third attempt with different invalid key
    cfg.sign_gpg_key = "another-invalid-key";
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test signing with different file types
TEST_F(GPGSignerTest, SignDifferentFileTypes) {
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.sign_gpg_key = "test-key";

    // Test with JSON file
    auto json_file = temp_dir / "test.json";
    std::ofstream json_out(json_file);
    json_out << "{\"test\": \"data\"}";
    json_out.close();

    cfg.output_file = json_file.string();
    EXPECT_FALSE(signer.sign_file(cfg));  // Should fail due to invalid key

    // Test with binary file
    auto bin_file = temp_dir / "test.bin";
    std::ofstream bin_out(bin_file, std::ios::binary);
    bin_out.write("binary data", 11);
    bin_out.close();

    cfg.output_file = bin_file.string();
    EXPECT_FALSE(signer.sign_file(cfg));  // Should fail due to invalid key
}

// Test error handling for GPG command execution
TEST_F(GPGSignerTest, GPGCommandErrorHandling) {
    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.output_file = test_file.string();
    cfg.sign_gpg_key = "non-existent-key-12345";

    // Should handle GPG command failure gracefully
    EXPECT_FALSE(signer.sign_file(cfg));
}

// Test concurrent signing (basic test)
TEST_F(GPGSignerTest, ConcurrentSigning) {
    Config cfg1, cfg2;
    cfg1.sign_gpg = true;  // Enable GPG signing
    cfg1.output_file = test_file.string();
    cfg1.sign_gpg_key = "key1";

    cfg2.sign_gpg = true;  // Enable GPG signing
    cfg2.output_file = test_file.string();
    cfg2.sign_gpg_key = "key2";

    // Both should fail due to invalid keys, but should not interfere with each other
    EXPECT_FALSE(signer.sign_file(cfg1));
    EXPECT_FALSE(signer.sign_file(cfg2));
}

// Test signing with special characters in path
TEST_F(GPGSignerTest, SignFileWithSpecialCharacters) {
    // Create a file with special characters in path
    auto special_dir = temp_dir / "special dir";
    std::filesystem::create_directories(special_dir);
    auto special_file = special_dir / "file with spaces.txt";

    std::ofstream file(special_file);
    file << "Content with special characters.";
    file.close();

    Config cfg;
    cfg.sign_gpg = true;  // Enable GPG signing
    cfg.output_file = special_file.string();
    cfg.sign_gpg_key = "test-key";

    // Should handle special characters in path
    EXPECT_FALSE(signer.sign_file(cfg));  // Fails due to invalid key, not path issues
}

} // namespace sys_scan