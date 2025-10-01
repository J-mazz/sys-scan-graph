#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <string>
#include "../src/scanners/KernelHardeningScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"

namespace fs = std::filesystem;

class KernelHardeningScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory structure
        test_dir = std::filesystem::temp_directory_path() / "kernel_test";
        std::filesystem::create_directories(test_dir);

        // Create sys and proc directory structures
        sys_kernel_dir = test_dir / "sys" / "kernel" / "security";
        std::filesystem::create_directories(sys_kernel_dir);

        sys_firmware_dir = test_dir / "sys" / "firmware";
        std::filesystem::create_directories(sys_firmware_dir / "efi" / "efivars");

        proc_sys_kernel_dir = test_dir / "proc" / "sys" / "kernel";
        std::filesystem::create_directories(proc_sys_kernel_dir);

        proc_sys_net_ipv4_dir = test_dir / "proc" / "sys" / "net" / "ipv4";
        std::filesystem::create_directories(proc_sys_net_ipv4_dir);

        proc_sys_net_dir = test_dir / "proc" / "sys" / "net" / "ipv4" / "conf" / "all";
        std::filesystem::create_directories(proc_sys_net_dir);

        dev_dir = test_dir / "dev";
        std::filesystem::create_directories(dev_dir);
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    fs::path test_dir;
    fs::path sys_kernel_dir;
    fs::path sys_firmware_dir;
    fs::path proc_sys_kernel_dir;
    fs::path proc_sys_net_ipv4_dir;
    fs::path proc_sys_net_dir;
    fs::path dev_dir;

    // Helper to create test files with content
    void createFile(const fs::path& path, const std::string& content) {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream file(path);
        file << content;
        file.close();
    }

    // Helper to run scanner and get findings
    std::vector<sys_scan::Finding> runScanner(bool hardening_enabled = true) {
        sys_scan::Config config;
        config.hardening = hardening_enabled;
        config.test_root = test_dir.string();

        sys_scan::Report report;
        sys_scan::ScanContext context(config, report);

        sys_scan::KernelHardeningScanner scanner;
        scanner.scan(context);

        // Get findings from the report
        for (const auto& result : report.results()) {
            if (result.scanner_name == scanner.name()) {
                return result.findings;
            }
        }
        return {};
    }
};

// Test scanner disabled when hardening is false
TEST_F(KernelHardeningScannerTest, ScanDisabledWhenHardeningDisabled) {
    createFile(sys_kernel_dir / "lockdown", "none [integrity] confidentiality");

    auto findings = runScanner(false);
    EXPECT_TRUE(findings.empty());
}

// Test kernel lockdown - none mode (bad)
TEST_F(KernelHardeningScannerTest, ScanLockdownNone) {
    createFile(sys_kernel_dir / "lockdown", "none [none] confidentiality");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto lockdown = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:lockdown:disabled"; });
    ASSERT_NE(lockdown, findings.end());
    EXPECT_EQ(lockdown->severity, sys_scan::Severity::Medium);
    EXPECT_THAT(lockdown->title, ::testing::HasSubstr("inactive"));
}

// Test kernel lockdown - integrity mode (good)
TEST_F(KernelHardeningScannerTest, ScanLockdownIntegrity) {
    createFile(sys_kernel_dir / "lockdown", "integrity [integrity] confidentiality");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto lockdown = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:lockdown:integrity"; });
    ASSERT_NE(lockdown, findings.end());
    EXPECT_EQ(lockdown->severity, sys_scan::Severity::Info);
    EXPECT_THAT(lockdown->title, ::testing::HasSubstr("integrity mode"));
}

// Test kernel lockdown - confidentiality mode (good)
TEST_F(KernelHardeningScannerTest, ScanLockdownConfidentiality) {
    createFile(sys_kernel_dir / "lockdown", "confidentiality [confidentiality] integrity");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto lockdown = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:lockdown:confidentiality"; });
    ASSERT_NE(lockdown, findings.end());
    EXPECT_EQ(lockdown->severity, sys_scan::Severity::Info);
    EXPECT_THAT(lockdown->title, ::testing::HasSubstr("confidentiality mode"));
}

// Test kernel lockdown - malformed content
TEST_F(KernelHardeningScannerTest, ScanLockdownMalformed) {
    createFile(sys_kernel_dir / "lockdown", "malformed content without brackets");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto lockdown = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:lockdown:disabled"; });
    ASSERT_NE(lockdown, findings.end());
    EXPECT_EQ(lockdown->severity, sys_scan::Severity::Medium);
}

// Test kernel lockdown - empty file
TEST_F(KernelHardeningScannerTest, ScanLockdownEmpty) {
    createFile(sys_kernel_dir / "lockdown", "");

    auto findings = runScanner();
    // Should not crash, but no lockdown findings expected
    auto lockdown_disabled = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id.find("kernel:lockdown:") == 0; });
    EXPECT_EQ(lockdown_disabled, findings.end());
}

// Test EFI firmware detection
TEST_F(KernelHardeningScannerTest, ScanEfiPresent) {
    // Create EFI directory
    std::filesystem::create_directories(sys_firmware_dir / "efi");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto efi = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:secureboot:efi"; });
    ASSERT_NE(efi, findings.end());
    EXPECT_EQ(efi->severity, sys_scan::Severity::Info);
    EXPECT_THAT(efi->title, ::testing::HasSubstr("EFI firmware detected"));
}

// Test EFI with dbx revocation list
TEST_F(KernelHardeningScannerTest, ScanEfiWithDbx) {
    std::filesystem::create_directories(sys_firmware_dir / "efi");
    createFile(sys_firmware_dir / "efi" / "efivars" / "dbx", "dbx content");

    auto findings = runScanner();

    auto efi = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:secureboot:efi"; });
    ASSERT_NE(efi, findings.end());

    // Should not have dbx-missing finding
    auto dbx_missing = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:secureboot:dbx-missing"; });
    EXPECT_EQ(dbx_missing, findings.end());
}

// Test EFI without dbx revocation list
TEST_F(KernelHardeningScannerTest, ScanEfiWithoutDbx) {
    std::filesystem::create_directories(sys_firmware_dir / "efi");
    // No dbx file created

    auto findings = runScanner();

    auto dbx_missing = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:secureboot:dbx-missing"; });
    ASSERT_NE(dbx_missing, findings.end());
    EXPECT_EQ(dbx_missing->severity, sys_scan::Severity::Low);
    EXPECT_THAT(dbx_missing->title, ::testing::HasSubstr("dbx revocation list not detected"));
}

// Test IMA policy with appraisal
TEST_F(KernelHardeningScannerTest, ScanImaPolicyWithAppraisal) {
    createFile(sys_kernel_dir / "ima" / "policy", "measure func=BPRM_CHECK\nappraise func=BPRM_CHECK\n");

    auto findings = runScanner();

    auto ima = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:ima:policy"; });
    ASSERT_NE(ima, findings.end());
    EXPECT_EQ(ima->severity, sys_scan::Severity::Info);
    EXPECT_THAT(ima->description, ::testing::HasSubstr("includes appraisal"));
    EXPECT_EQ(ima->metadata.at("appraise"), "yes");
}

// Test IMA policy without appraisal
TEST_F(KernelHardeningScannerTest, ScanImaPolicyWithoutAppraisal) {
    createFile(sys_kernel_dir / "ima" / "policy", "measure func=BPRM_CHECK\nmeasure func=FILE_CHECK\n");

    auto findings = runScanner();

    auto ima = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:ima:policy"; });
    ASSERT_NE(ima, findings.end());
    EXPECT_EQ(ima->severity, sys_scan::Severity::Info);
    EXPECT_THAT(ima->description, ::testing::HasSubstr("lacks explicit appraisal"));
    EXPECT_EQ(ima->metadata.at("appraise"), "no");
}

// Test TPM present (/dev/tpm0)
TEST_F(KernelHardeningScannerTest, ScanTpmPresentTpm0) {
    createFile(dev_dir / "tpm0", "");  // Empty file to simulate device

    auto findings = runScanner();

    auto tpm = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:tpm:present"; });
    ASSERT_NE(tpm, findings.end());
    EXPECT_EQ(tpm->severity, sys_scan::Severity::Info);
    EXPECT_THAT(tpm->title, ::testing::HasSubstr("TPM device present"));
}

// Test TPM present (/dev/tpmrm0)
TEST_F(KernelHardeningScannerTest, ScanTpmPresentTprm0) {
    createFile(dev_dir / "tpmrm0", "");  // Empty file to simulate device

    auto findings = runScanner();

    auto tpm = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:tpm:present"; });
    ASSERT_NE(tpm, findings.end());
    EXPECT_EQ(tpm->severity, sys_scan::Severity::Info);
}

// Test TPM absent
TEST_F(KernelHardeningScannerTest, ScanTpmAbsent) {
    // No TPM devices created

    auto findings = runScanner();

    auto tpm_absent = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:tpm:absent"; });
    ASSERT_NE(tpm_absent, findings.end());
    EXPECT_EQ(tpm_absent->severity, sys_scan::Severity::Low);
    EXPECT_THAT(tpm_absent->title, ::testing::HasSubstr("No TPM device"));
}

// Test sysctl kptr_restrict = 1 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlKptrRestrictGood) {
    createFile(proc_sys_kernel_dir / "kptr_restrict", "1\n");

    auto findings = runScanner();

    auto kptr = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:kptr_restrict"; });
    ASSERT_NE(kptr, findings.end());
    EXPECT_EQ(kptr->severity, sys_scan::Severity::Info);
    EXPECT_THAT(kptr->description, ::testing::HasSubstr("restricted"));
    EXPECT_EQ(kptr->metadata.at("value"), "1");
    EXPECT_EQ(kptr->metadata.at("expected"), "1");
}

// Test sysctl kptr_restrict = 0 (bad)
TEST_F(KernelHardeningScannerTest, ScanSysctlKptrRestrictBad) {
    createFile(proc_sys_kernel_dir / "kptr_restrict", "0\n");

    auto findings = runScanner();

    auto kptr = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:kptr_restrict"; });
    ASSERT_NE(kptr, findings.end());
    EXPECT_EQ(kptr->severity, sys_scan::Severity::Low);
    EXPECT_THAT(kptr->description, ::testing::HasSubstr("not restricted"));
    EXPECT_EQ(kptr->metadata.at("value"), "0");
}

// Test sysctl dmesg_restrict = 1 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlDmesgRestrictGood) {
    createFile(proc_sys_kernel_dir / "dmesg_restrict", "1\n");

    auto findings = runScanner();

    auto dmesg = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:dmesg_restrict"; });
    ASSERT_NE(dmesg, findings.end());
    EXPECT_EQ(dmesg->severity, sys_scan::Severity::Info);
    EXPECT_THAT(dmesg->description, ::testing::HasSubstr("restricted"));
}

// Test sysctl kexec_load_disabled = 1 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlKexecDisabledGood) {
    createFile(proc_sys_kernel_dir / "kexec_load_disabled", "1\n");

    auto findings = runScanner();

    auto kexec = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:kexec_disabled"; });
    ASSERT_NE(kexec, findings.end());
    EXPECT_EQ(kexec->severity, sys_scan::Severity::Info);
    EXPECT_THAT(kexec->description, ::testing::HasSubstr("disabled"));
}

// Test sysctl sysrq = 0 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlSysrqGood) {
    createFile(proc_sys_kernel_dir / "sysrq", "0\n");

    auto findings = runScanner();

    auto sysrq = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:sysrq"; });
    ASSERT_NE(sysrq, findings.end());
    EXPECT_EQ(sysrq->severity, sys_scan::Severity::Info);
    EXPECT_THAT(sysrq->description, ::testing::HasSubstr("disabled"));
}

// Test network sysctls - tcp_syncookies = 1 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlTcpSyncookiesGood) {
    createFile(proc_sys_net_ipv4_dir / "tcp_syncookies", "1\n");

    auto findings = runScanner();

    auto syncookies = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:tcp_syncookies"; });
    ASSERT_NE(syncookies, findings.end());
    EXPECT_EQ(syncookies->severity, sys_scan::Severity::Info);
    EXPECT_THAT(syncookies->description, ::testing::HasSubstr("on"));
}

// Test network sysctls - rp_filter = 1 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlRpFilterGood) {
    createFile(proc_sys_net_dir / "rp_filter", "1\n");

    auto findings = runScanner();

    auto rp_filter = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:rp_filter"; });
    ASSERT_NE(rp_filter, findings.end());
    EXPECT_EQ(rp_filter->severity, sys_scan::Severity::Info);
    EXPECT_THAT(rp_filter->description, ::testing::HasSubstr("strict"));
}

// Test network sysctls - accept_redirects = 0 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlAcceptRedirectsGood) {
    createFile(proc_sys_net_dir / "accept_redirects", "0\n");

    auto findings = runScanner();

    auto redirects = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:accept_redirects"; });
    ASSERT_NE(redirects, findings.end());
    EXPECT_EQ(redirects->severity, sys_scan::Severity::Info);
    EXPECT_THAT(redirects->description, ::testing::HasSubstr("blocked"));
}

// Test network sysctls - accept_source_route = 0 (good)
TEST_F(KernelHardeningScannerTest, ScanSysctlAcceptSourceRouteGood) {
    createFile(proc_sys_net_dir / "accept_source_route", "0\n");

    auto findings = runScanner();

    auto source_route = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:accept_source_route"; });
    ASSERT_NE(source_route, findings.end());
    EXPECT_EQ(source_route->severity, sys_scan::Severity::Info);
    EXPECT_THAT(source_route->description, ::testing::HasSubstr("blocked"));
}

// Test sysctl with whitespace trimming
TEST_F(KernelHardeningScannerTest, ScanSysctlWithWhitespace) {
    createFile(proc_sys_kernel_dir / "kptr_restrict", "1 \n");

    auto findings = runScanner();

    auto kptr = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:sysctl:kptr_restrict"; });
    ASSERT_NE(kptr, findings.end());
    EXPECT_EQ(kptr->metadata.at("value"), "1");
}

// Test missing sysctl files are skipped
TEST_F(KernelHardeningScannerTest, ScanMissingSysctlFiles) {
    // Don't create any sysctl files

    auto findings = runScanner();

    // Should not crash, and no sysctl findings should be present
    auto sysctl_findings = std::count_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id.find("kernel:sysctl:") == 0; });
    EXPECT_EQ(sysctl_findings, 0);
}

// Test comprehensive scan with all features
TEST_F(KernelHardeningScannerTest, ScanComprehensive) {
    // Set up all hardening features
    createFile(sys_kernel_dir / "lockdown", "integrity [integrity] confidentiality");
    std::filesystem::create_directories(sys_firmware_dir / "efi");
    createFile(sys_kernel_dir / "ima" / "policy", "measure func=BPRM_CHECK\nappraise func=BPRM_CHECK\n");
    createFile(dev_dir / "tpm0", "");
    createFile(proc_sys_kernel_dir / "kptr_restrict", "1\n");
    createFile(proc_sys_kernel_dir / "dmesg_restrict", "1\n");
    createFile(proc_sys_kernel_dir / "kexec_load_disabled", "1\n");
    createFile(proc_sys_kernel_dir / "sysrq", "0\n");
    createFile(proc_sys_net_ipv4_dir / "tcp_syncookies", "1\n");
    createFile(proc_sys_net_dir / "rp_filter", "1\n");
    createFile(proc_sys_net_dir / "accept_redirects", "0\n");
    createFile(proc_sys_net_dir / "accept_source_route", "0\n");

    auto findings = runScanner();

    // Should have findings for all features
    EXPECT_GE(findings.size(), 13); // lockdown + EFI + dbx-missing + IMA + TPM + 8 sysctls = 13

    // Verify key findings are present
    auto lockdown = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:lockdown:integrity"; });
    EXPECT_NE(lockdown, findings.end());

    auto efi = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:secureboot:efi"; });
    EXPECT_NE(efi, findings.end());

    auto ima = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:ima:policy"; });
    EXPECT_NE(ima, findings.end());

    auto tpm = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "kernel:tpm:present"; });
    EXPECT_NE(tpm, findings.end());
}