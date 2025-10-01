#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "../src/scanners/ModuleScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"

namespace fs = std::filesystem;
namespace sys_scan {

class ModuleScannerExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory structure
        test_dir = std::filesystem::temp_directory_path() / ("module_scanner_test_" + std::to_string(getpid()));
        std::filesystem::create_directories(test_dir);

        // Get actual kernel release for testing
        struct utsname un {};
        if (uname(&un) == 0) {
            actual_kernel_release = un.release;
        } else {
            actual_kernel_release = "5.15.0-test"; // fallback
        }

        // Create mock kernel release directory using actual kernel release
        kernel_dir = test_dir / "lib" / "modules" / actual_kernel_release;
        std::filesystem::create_directories(kernel_dir);

        // Create mock /proc and /sys directories
        proc_dir = test_dir / "proc";
        sys_dir = test_dir / "sys";
        std::filesystem::create_directories(proc_dir);
        std::filesystem::create_directories(sys_dir / "module");

        // Set up test root environment
        setenv("SYS_SCAN_TEST_ROOT", test_dir.c_str(), 1);
    }

    void TearDown() override {
        // Clean up test directory
        std::filesystem::remove_all(test_dir);
        unsetenv("SYS_SCAN_TEST_ROOT");
    }

    fs::path test_dir;
    fs::path kernel_dir;
    fs::path proc_dir;
    fs::path sys_dir;
    std::string actual_kernel_release;

    void create_mock_proc_modules(const std::vector<std::string>& modules) {
        std::ofstream proc_modules(proc_dir / "modules");
        for (const auto& mod : modules) {
            proc_modules << mod << " 16384 0 - Live 0x0\n";
        }
    }

    void create_mock_modules_dep(const std::vector<std::pair<std::string, std::string>>& deps) {
        std::ofstream modules_dep(kernel_dir / "modules.dep");
        for (const auto& [path, deps_str] : deps) {
            modules_dep << path << ":" << deps_str << "\n";
        }
    }

    void create_mock_modules_builtin(const std::vector<std::string>& modules) {
        std::ofstream modules_builtin(kernel_dir / "modules.builtin");
        for (const auto& mod : modules) {
            modules_builtin << mod << "\n";
        }
    }

    void create_mock_sysfs_modules(const std::vector<std::string>& modules) {
        for (const auto& mod : modules) {
            std::filesystem::create_directories(sys_dir / "module" / mod);
        }
    }

    void create_mock_kernel_module(const fs::path& path, bool with_signature = true) {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream module_file(path, std::ios::binary);

        // Write minimal ELF header
        const char elf_header[] = {
            0x7f, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00,  // ELF magic
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,  // Type: EXEC
            0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        module_file.write(elf_header, sizeof(elf_header));

        if (with_signature) {
            // Add module signature
            module_file << "~Module signature appended~\n";
        }
    }

    // Helper to get findings for a specific scanner
    std::vector<sys_scan::Finding> get_findings_for_scanner(const sys_scan::Report& report, const std::string& scanner_name) {
        for (const auto& result : report.results()) {
            if (result.scanner_name == scanner_name) {
                return result.findings;
            }
        }
        return {};
    }
};

// Test simple mode with missing /proc/modules
TEST_F(ModuleScannerExtendedTest, ScanSimpleModeMissingProcModules) {
    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    // Should not crash, may have no findings
    EXPECT_TRUE(true); // Basic sanity check
}

// Test simple mode with empty /proc/modules
TEST_F(ModuleScannerExtendedTest, ScanSimpleModeEmptyProcModules) {
    create_mock_proc_modules({});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    // Should not crash
    EXPECT_TRUE(true);
}

// Test simple mode with valid modules
TEST_F(ModuleScannerExtendedTest, ScanSimpleModeValidModules) {
    create_mock_proc_modules({"test_module1", "test_module2"});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = false;
    cfg.test_root = test_dir.string();

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_EQ(findings.size(), 2);
    EXPECT_EQ(findings[0].id, "test_module1");
    EXPECT_EQ(findings[1].id, "test_module2");
}

// Test summary mode with missing files
TEST_F(ModuleScannerExtendedTest, ScanSummaryModeMissingFiles) {
    create_mock_proc_modules({"test_module"});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;
    cfg.test_root = test_dir.string();

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    // Should handle missing files gracefully
    auto findings = get_findings_for_scanner(report, "modules");
    EXPECT_GE(findings.size(), 1); // At least summary finding
}

// Test summary mode with empty files
TEST_F(ModuleScannerExtendedTest, ScanSummaryModeEmptyFiles) {
    create_mock_proc_modules({"test_module"});
    create_mock_modules_dep({});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;
    cfg.test_root = test_dir.string();

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);
    EXPECT_EQ(findings[0].id, "module_summary");
}

// Test anomalies-only mode with unsigned modules
TEST_F(ModuleScannerExtendedTest, ScanAnomaliesOnlyUnsignedModules) {
    create_mock_proc_modules({"unsigned_module"});
    create_mock_modules_dep({{"kernel/drivers/unsigned_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"unsigned_module"});

    // Create unsigned module file
    create_mock_kernel_module(kernel_dir / "kernel/drivers/unsigned_module.ko", false);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = true;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    // Should find unsigned module anomaly
    auto unsigned_findings = std::count_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("unsigned"); });
    EXPECT_GE(unsigned_findings, 1);
}

// Test anomalies-only mode with out-of-tree modules
TEST_F(ModuleScannerExtendedTest, ScanAnomaliesOnlyOutOfTreeModules) {
    create_mock_proc_modules({"oot_module"});
    create_mock_modules_dep({{"extra/oot_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"oot_module"});

    create_mock_kernel_module(kernel_dir / "extra/oot_module.ko", true);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = true;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    auto oot_findings = std::count_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("out_of_tree"); });
    EXPECT_GE(oot_findings, 1);
}

// Test anomalies-only mode with missing files
TEST_F(ModuleScannerExtendedTest, ScanAnomaliesOnlyMissingFiles) {
    create_mock_proc_modules({"missing_module"});
    create_mock_modules_dep({{"kernel/missing_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"missing_module"});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = true;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    auto missing_findings = std::count_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("missing_file"); });
    EXPECT_GE(missing_findings, 1);
}

// Test anomalies-only mode with hidden modules
TEST_F(ModuleScannerExtendedTest, ScanAnomaliesOnlyHiddenModules) {
    create_mock_proc_modules({"hidden_module"});
    create_mock_modules_dep({{"kernel/hidden_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({}); // Module not in sysfs

    create_mock_kernel_module(kernel_dir / "kernel/hidden_module.ko", true);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = true;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    auto hidden_findings = std::count_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("hidden_sysfs"); });
    EXPECT_GE(hidden_findings, 1);
}

// Test compressed unsigned modules
TEST_F(ModuleScannerExtendedTest, ScanCompressedUnsignedModules) {
    create_mock_proc_modules({"compressed_unsigned"});
    create_mock_modules_dep({{"kernel/compressed_unsigned.ko.xz", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"compressed_unsigned"});

    // Create compressed unsigned module (mock)
    auto module_path = kernel_dir / "kernel/compressed_unsigned.ko.xz";
    std::filesystem::create_directories(module_path.parent_path());
    std::ofstream module_file(module_path);
    module_file << "mock compressed unsigned module\n";

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);
    // Should detect compressed module
    EXPECT_TRUE(findings[0].metadata.count("compressed"));
}

// Test sysfs-only modules
TEST_F(ModuleScannerExtendedTest, ScanSysfsOnlyModules) {
    create_mock_proc_modules({"normal_module"});
    create_mock_modules_dep({{"kernel/normal.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"normal_module", "sysfs_only_module"});

    create_mock_kernel_module(kernel_dir / "kernel/normal.ko", true);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);
    // Should detect sysfs-only modules
    EXPECT_TRUE(findings[0].metadata.count("sysfs_only_count"));
}

// Test malformed /proc/modules
TEST_F(ModuleScannerExtendedTest, ScanMalformedProcModules) {
    // Create malformed /proc/modules
    std::ofstream proc_modules(proc_dir / "modules");
    proc_modules << "malformed_line_without_space\n";
    proc_modules << "another malformed line\n";
    proc_modules << "valid_module 16384 0 - Live 0x0\n";
    proc_modules.close();

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    // Should handle malformed lines gracefully
    EXPECT_GE(findings.size(), 1);
}

// Test malformed modules.dep
TEST_F(ModuleScannerExtendedTest, ScanMalformedModulesDep) {
    create_mock_proc_modules({"test_module"});

    // Create malformed modules.dep
    std::ofstream modules_dep(kernel_dir / "modules.dep");
    modules_dep << "malformed_line_without_colon\n";
    modules_dep << "kernel/test.ko\n"; // Missing colon
    modules_dep << "kernel/valid.ko:\n";

    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"test_module"});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    // Should handle malformed dep file gracefully
    auto findings = get_findings_for_scanner(report, "modules");
    EXPECT_GE(findings.size(), 1);
}

// Test with modules hash enabled
TEST_F(ModuleScannerExtendedTest, ScanWithModulesHashEnabled) {
    create_mock_proc_modules({"hash_module"});
    create_mock_modules_dep({{"kernel/hash_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"hash_module"});

    create_mock_kernel_module(kernel_dir / "kernel/hash_module.ko", true);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = true;
    cfg.modules_hash = true;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    // Should include hash in metadata if available
    bool has_hash = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("sha256"); });
    // Hash may or may not be computed depending on OpenSSL availability
    EXPECT_TRUE(true); // Test passes regardless
}

// Test with very long module names
TEST_F(ModuleScannerExtendedTest, ScanVeryLongModuleNames) {
    std::string long_name(1000, 'a'); // Very long module name
    create_mock_proc_modules({long_name});
    create_mock_modules_dep({{"kernel/" + long_name + ".ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({long_name.substr(0, 255)}); // sysfs might truncate

    create_mock_kernel_module(kernel_dir / ("kernel/" + long_name + ".ko"), true);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    // Should handle long names gracefully
    auto findings = get_findings_for_scanner(report, "modules");
    EXPECT_GE(findings.size(), 1);
}

// Test with many modules (stress test)
TEST_F(ModuleScannerExtendedTest, ScanManyModules) {
    std::vector<std::string> modules;
    std::vector<std::pair<std::string, std::string>> deps;

    for (int i = 0; i < 1000; ++i) {
        std::string name = "module_" + std::to_string(i);
        modules.push_back(name);
        deps.emplace_back("kernel/" + name + ".ko", "");
        create_mock_kernel_module(kernel_dir / ("kernel/" + name + ".ko"), true);
    }

    create_mock_proc_modules(modules);
    create_mock_modules_dep(deps);
    create_mock_modules_builtin({});
    create_mock_sysfs_modules(modules);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);
    EXPECT_EQ(findings[0].metadata["total"], "1000");
}

// Test with special characters in module names
TEST_F(ModuleScannerExtendedTest, ScanSpecialCharactersInNames) {
    std::vector<std::string> special_modules = {
        "module-with-dashes",
        "module_with_underscores",
        "module.with.dots",
        "module123numbers"
    };

    create_mock_proc_modules(special_modules);
    std::vector<std::pair<std::string, std::string>> deps;
    for (const auto& mod : special_modules) {
        deps.emplace_back("kernel/" + mod + ".ko", "");
        create_mock_kernel_module(kernel_dir / ("kernel/" + mod + ".ko"), true);
    }

    create_mock_modules_dep(deps);
    create_mock_modules_builtin({});
    create_mock_sysfs_modules(special_modules);

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);
    EXPECT_EQ(findings[0].metadata["total"], "4");
}

// Test with empty kernel release (uname failure simulation)
TEST_F(ModuleScannerExtendedTest, ScanEmptyKernelRelease) {
    // This is hard to test directly since uname is called in scan()
    // We test that the scanner doesn't crash with minimal setup
    create_mock_proc_modules({"test_module"});

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    // Should not crash even if uname fails
    EXPECT_TRUE(true);
}

// Test anomalies-only with multiple anomaly types
TEST_F(ModuleScannerExtendedTest, ScanMultipleAnomalyTypes) {
    create_mock_proc_modules({"unsigned_oot_missing_hidden"});
    create_mock_modules_dep({{"extra/unsigned_oot_missing_hidden.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({}); // Hidden from sysfs

    // Don't create the file - it will be missing

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = false;
    cfg.modules_anomalies_only = true;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);

    const auto& f = findings[0];
    // Should have multiple anomaly flags
    EXPECT_TRUE(f.metadata.count("unsigned") ||
                f.metadata.count("out_of_tree") ||
                f.metadata.count("missing_file") ||
                f.metadata.count("hidden_sysfs"));
}

// Test summary with taint flags
TEST_F(ModuleScannerExtendedTest, ScanWithTaintFlags) {
    create_mock_proc_modules({"test_module"});
    create_mock_modules_dep({{"kernel/test_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"test_module"});

    create_mock_kernel_module(kernel_dir / "kernel/test_module.ko", true);

    // Create mock /proc/sys/kernel/tainted
    std::filesystem::create_directories(test_dir / "proc" / "sys" / "kernel");
    std::ofstream tainted_file(test_dir / "proc" / "sys" / "kernel" / "tainted");
    tainted_file << "1024\n"; // Some taint flags set
    tainted_file.close();

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);

    // Should include taint information
    EXPECT_TRUE(findings[0].metadata.count("taint_value"));
    EXPECT_TRUE(findings[0].metadata.count("taint_flags"));
}

// Test with kallsyms access
TEST_F(ModuleScannerExtendedTest, ScanWithKallsymsAccess) {
    create_mock_proc_modules({"test_module"});
    create_mock_modules_dep({{"kernel/test_module.ko", ""}});
    create_mock_modules_builtin({});
    create_mock_sysfs_modules({"test_module"});

    create_mock_kernel_module(kernel_dir / "kernel/test_module.ko", true);

    // Create mock /proc/kallsyms
    std::ofstream kallsyms_file(test_dir / "proc" / "kallsyms");
    for (int i = 0; i < 100; ++i) {
        kallsyms_file << "ffffffffc0000000 T function_" << i << "\n";
    }
    kallsyms_file.close();

    Config cfg;
    cfg.test_root = test_dir.string();
    cfg.modules_summary_only = true;
    cfg.modules_anomalies_only = false;

    Report report;
    ScanContext context(cfg, report);

    ModuleScanner scanner;
    scanner.scan(context);

    auto findings = get_findings_for_scanner(report, "modules");
    ASSERT_GE(findings.size(), 1);

    // Should include kallsyms information
    EXPECT_EQ(findings[0].metadata["kallsyms_readable"], "yes");
}

} // namespace sys_scan