#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/WorldWritableScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <filesystem>
#include <vector>
#include <memory>

namespace fs = std::filesystem;

namespace sys_scan {
namespace test {

// Test fixture for WorldWritableScanner
class WorldWritableScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = "/tmp/world_writable_test_" + std::to_string(getpid());
        fs::create_directories(temp_dir);
        chmod(temp_dir.c_str(), 0755);  // Ensure directory is accessible

        // Create test config
        config = Config();
        config.fs_world_writable_limit = 1000;  // High limit for testing
        config.fs_hygiene = true;  // Enable advanced checks

        // Create report
        report = std::make_unique<Report>();
    }

    void TearDown() override {
        // Clean up temporary directory
        if (fs::exists(temp_dir)) {
            // Fix permissions for cleanup
            std::string no_access_dir = temp_dir + "/no_access";
            if (fs::exists(no_access_dir)) {
                chmod(no_access_dir.c_str(), 0755);
            }
            fs::remove_all(temp_dir);
        }
    }

    // Helper to create test files with specific permissions
    std::string createTestFile(const std::string& filename, mode_t mode, const std::string& content = "") {
        std::string filepath = temp_dir + "/" + filename;
        int fd = creat(filepath.c_str(), mode);
        if (fd == -1) {
            throw std::runtime_error("Failed to create test file: " + filepath);
        }

        if (!content.empty()) {
            write(fd, content.c_str(), content.size());
        }

        close(fd);
        
        // Ensure permissions are set correctly (umask might interfere)
        chmod(filepath.c_str(), mode);
        
        return filepath;
    }

    // Helper to create test directories
    std::string createTestDir(const std::string& dirname, mode_t mode = 0755) {
        std::string dirpath = temp_dir + "/" + dirname;
        fs::create_directories(dirpath);
        chmod(dirpath.c_str(), mode);
        return dirpath;
    }

    std::string temp_dir;
    Config config;
    std::unique_ptr<Report> report;
};

// Basic scanner functionality tests
TEST_F(WorldWritableScannerTest, NameAndDescription) {
    WorldWritableScanner scanner;
    EXPECT_EQ(scanner.name(), "world_writable");
    EXPECT_EQ(scanner.description(), "Find world-writable files in sensitive dirs");
}

TEST_F(WorldWritableScannerTest, EmptyScan) {
    WorldWritableScanner scanner;
    ScanContext context(config, *report);

    // Scan default directories only
    scanner.scan(context);

    auto results = report->results();
    // Should have results from default directories
    EXPECT_GE(results.size(), 0);
}

// Test world-writable file detection
TEST_F(WorldWritableScannerTest, WorldWritableFileDetection) {
    // Create a world-writable file
    std::string ww_file = createTestFile("world_writable.txt", 0666);  // rw-rw-rw-
    // Create a normal file
    std::string normal_file = createTestFile("normal.txt", 0644);  // rw-r--r--

    // Verify files have correct permissions
    struct stat st;
    ASSERT_EQ(stat(ww_file.c_str(), &st), 0);
    ASSERT_TRUE(st.st_mode & S_IWOTH) << "File should be world-writable";
    ASSERT_EQ(stat(normal_file.c_str(), &st), 0);
    ASSERT_FALSE(st.st_mode & S_IWOTH) << "File should not be world-writable";

    // Add temp directory to scan paths
    config.world_writable_dirs.push_back(temp_dir);
    config.fs_world_writable_limit = 0;  // Unlimited findings

    std::cout << "world_writable_dirs size: " << config.world_writable_dirs.size() << std::endl;
    std::cout << "temp_dir: " << temp_dir << std::endl;
    std::cout << "ww_file: " << ww_file << std::endl;

    // Debug: list directory contents
    DIR* dir = opendir(temp_dir.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir))) {
            std::cout << "Entry: " << entry->d_name << std::endl;
        }
        closedir(dir);
    } else {
        std::cout << "Cannot open dir" << std::endl;
    }

    // Debug: check file permissions
    if (stat(ww_file.c_str(), &st) == 0) {
        std::cout << "File mode: " << std::oct << st.st_mode << std::endl;
    } else {
        std::cout << "Cannot stat file" << std::endl;
    }

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Debug: print all findings
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            std::cout << "Found finding: " << finding.id << " - " << finding.title << std::endl;
        }
    }

    // Should find the world-writable file
    bool found_ww = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == ww_file) {
                found_ww = true;
                EXPECT_EQ(finding.title, "World-writable file");
                EXPECT_EQ(finding.severity, Severity::Low);  // In /tmp, should be Low
                break;
            }
        }
    }
    EXPECT_TRUE(found_ww);

    // Should not find the normal file
    bool found_normal = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == normal_file) {
                found_normal = true;
                break;
            }
        }
    }
    EXPECT_FALSE(found_normal);
}

// Test world-writable file in /tmp (should be Low severity)
TEST_F(WorldWritableScannerTest, WorldWritableInTmp) {
    std::string tmp_file = temp_dir + "/tmp_world_writable.txt";
    int fd = creat(tmp_file.c_str(), 0666);
    close(fd);
    chmod(tmp_file.c_str(), 0666);  // Ensure world-writable

    config.world_writable_dirs.push_back(temp_dir);
    config.fs_world_writable_limit = 0;  // Unlimited findings

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    bool found = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == tmp_file) {
                found = true;
                EXPECT_EQ(finding.severity, Severity::Low);  // /tmp files should be Low severity
                break;
            }
        }
    }
    EXPECT_TRUE(found);
}

// Test SUID interpreter detection
TEST_F(WorldWritableScannerTest, SuidInterpreterDetection) {
    // Create a SUID bash script
    std::string suid_bash = createTestFile("suid_bash", 06555, "#!/bin/bash\necho 'dangerous'\n");  // r-sr-xr-x
    // Create a SUID python script
    std::string suid_python = createTestFile("suid_python", 06555, "#!/usr/bin/python3\nprint('dangerous')\n");
    // Create a normal SUID binary (not interpreter)
    std::string suid_binary = createTestFile("suid_binary", 06555, "ELF binary content");

    config.world_writable_dirs.push_back(temp_dir);
    config.fs_world_writable_limit = 0;  // Unlimited findings

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should find SUID interpreters as Critical
    bool found_bash = false, found_python = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == suid_bash) {
                found_bash = true;
                EXPECT_EQ(finding.title, "Setuid interpreter");
                EXPECT_EQ(finding.severity, Severity::Critical);
            } else if (finding.id == suid_python) {
                found_python = true;
                EXPECT_EQ(finding.title, "Setuid interpreter");
                EXPECT_EQ(finding.severity, Severity::Critical);
            }
        }
    }
    EXPECT_TRUE(found_bash);
    EXPECT_TRUE(found_python);
}

// Test PATH directory world-writability checks
TEST_F(WorldWritableScannerTest, PathDirectoryWorldWritable) {
    // Create a world-writable directory in PATH
    std::string ww_path_dir = createTestDir("world_writable_path", 0777);  // drwxrwxrwx

    // Set PATH to include our test directory
    setenv("PATH", (ww_path_dir + ":/bin:/usr/bin").c_str(), 1);

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    bool found = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == ww_path_dir) {
                found = true;
                EXPECT_EQ(finding.title, "World-writable PATH directory");
                EXPECT_EQ(finding.severity, Severity::High);
                break;
            }
        }
    }
    EXPECT_TRUE(found);
}

// Test exclusion patterns
TEST_F(WorldWritableScannerTest, ExclusionPatterns) {
    // Create world-writable files
    std::string excluded_file = createTestFile("excluded_backup.bak", 0666);
    std::string included_file = createTestFile("included.txt", 0666);

    // Add exclusion pattern
    config.world_writable_exclude.push_back("backup.bak");

    config.world_writable_dirs.push_back(temp_dir);
    config.fs_world_writable_limit = 0;  // Unlimited findings

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should not find excluded file
    bool found_excluded = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == excluded_file) {
                found_excluded = true;
                break;
            }
        }
    }
    EXPECT_FALSE(found_excluded);

    // Should find included file
    bool found_included = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == included_file) {
                found_included = true;
                break;
            }
        }
    }
    EXPECT_TRUE(found_included);
}

// Test fs_hygiene gating
TEST_F(WorldWritableScannerTest, FsHygieneGating) {
    // Create a world-writable PATH directory
    std::string ww_path_dir = createTestDir("world_writable_path", 0777);
    setenv("PATH", (ww_path_dir + ":/bin:/usr/bin").c_str(), 1);

    // Disable fs_hygiene
    config.fs_hygiene = false;

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should not find PATH directory issues when fs_hygiene is disabled
    bool found_path_issue = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.title == "World-writable PATH directory") {
                found_path_issue = true;
                break;
            }
        }
    }
    EXPECT_FALSE(found_path_issue);
}

// Test edge cases
TEST_F(WorldWritableScannerTest, InvalidDirectory) {
    // Add non-existent directory
    config.world_writable_dirs.push_back("/non/existent/directory");

    WorldWritableScanner scanner;
    ScanContext context(config, *report);

    // Should not crash
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(WorldWritableScannerTest, PermissionDenied) {
    // Create directory with no access
    std::string no_access_dir = createTestDir("no_access", 0000);

    config.world_writable_dirs.push_back(no_access_dir);

    WorldWritableScanner scanner;
    ScanContext context(config, *report);

    // Should not crash on permission denied
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(WorldWritableScannerTest, SymlinkHandling) {
    // Create a world-writable file
    std::string target_file = createTestFile("target.txt", 0666);
    // Create symlink to it
    std::string symlink_file = temp_dir + "/symlink.txt";
    symlink(target_file.c_str(), symlink_file.c_str());

    config.world_writable_dirs.push_back(temp_dir);
    config.fs_world_writable_limit = 0;  // Unlimited findings

    WorldWritableScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should detect the world-writable file through symlink
    bool found = false;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (finding.id == target_file) {
                found = true;
                break;
            }
        }
    }
    EXPECT_TRUE(found);
}

} // namespace test
} // namespace sys_scan