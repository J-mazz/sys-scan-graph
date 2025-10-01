#include "core/ArgumentParser.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <vector>
#include <string>

namespace sys_scan {

class ArgumentParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }
};

// Test signing options
TEST_F(ArgumentParserTest, ParseSigningOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--sign-gpg", "ABC123", "--slsa-level", "2"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.sign_gpg);
    EXPECT_EQ(cfg.sign_gpg_key, "ABC123");
    // Note: --slsa-level sets environment variable, not config
}

// Test basic argument parsing
TEST_F(ArgumentParserTest, ParseBasicArguments) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--output", "test.json", "--compact"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, "test.json");
    EXPECT_TRUE(cfg.compact);
}

// Test help flag
TEST_F(ArgumentParserTest, ParseHelpFlag) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--help"};

    // Help should return false (indicating early exit)
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv), cfg));
}

// Test version flag
TEST_F(ArgumentParserTest, ParseVersionFlag) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--version"};

    // Version should return false (indicating early exit)
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv), cfg));
}

// Test enable/disable flags
TEST_F(ArgumentParserTest, ParseEnableDisableFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--enable", "processes,network", "--disable", "modules"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "processes") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "network") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "modules") != cfg.disable_scanners.end());
}

// Test output format flags
TEST_F(ArgumentParserTest, ParseOutputFormatFlags) {
    ArgumentParser parser;
    Config cfg;

    // Test pretty format
    const char* argv1[] = {"sys-scan", "--pretty"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv1), cfg));
    EXPECT_TRUE(cfg.pretty);

    // Test compact format
    Config cfg2;
    const char* argv2[] = {"sys-scan", "--compact"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv2), cfg2));
    EXPECT_TRUE(cfg2.compact);

    // Test NDJSON format
    Config cfg3;
    const char* argv3[] = {"sys-scan", "--ndjson"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv3), cfg3));
    EXPECT_TRUE(cfg3.ndjson);

    // Test SARIF format
    Config cfg4;
    const char* argv4[] = {"sys-scan", "--sarif"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv4), cfg4));
    EXPECT_TRUE(cfg4.sarif);
}

// Test severity filtering
TEST_F(ArgumentParserTest, ParseSeverityFilter) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--min-severity", "medium"};

    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.min_severity, "medium");
}

// Test fail-on flags
TEST_F(ArgumentParserTest, ParseFailOnFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--fail-on", "high", "--fail-on-count", "5"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.fail_on_severity, "high");
    EXPECT_EQ(cfg.fail_on_count, 5);
}

// Test scanner-specific flags
TEST_F(ArgumentParserTest, ParseScannerSpecificFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--all-processes", "--modules-summary", "--integrity"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.all_processes);
    EXPECT_TRUE(cfg.modules_summary_only);
    EXPECT_TRUE(cfg.integrity);
}

// Test additional scanner-specific flags
TEST_F(ArgumentParserTest, ParseAdditionalScannerFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--modules-anomalies-only", "--modules-hash", "--integrity-ima", "--integrity-pkg-verify", "--fs-hygiene", "--process-hash", "--process-inventory"};

    EXPECT_TRUE(parser.parse(8, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.modules_anomalies_only);
    EXPECT_TRUE(cfg.modules_hash);
    EXPECT_TRUE(cfg.integrity_ima);
    EXPECT_TRUE(cfg.integrity_pkg_verify);
    EXPECT_TRUE(cfg.fs_hygiene);
    EXPECT_TRUE(cfg.process_hash);
    EXPECT_TRUE(cfg.process_inventory);
}

// Test integrity scanner limits
TEST_F(ArgumentParserTest, ParseIntegrityLimits) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--integrity-pkg-limit", "100", "--integrity-pkg-rehash-limit", "50"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.integrity_pkg_limit, 100);
    EXPECT_EQ(cfg.integrity_pkg_rehash_limit, 50);
}

// Test filesystem scanner options
TEST_F(ArgumentParserTest, ParseFilesystemOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--fs-world-writable-limit", "200", "--world-writable-dirs", "/tmp,/var/tmp", "--world-writable-exclude", "pattern1,pattern2"};

    EXPECT_TRUE(parser.parse(7, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.fs_world_writable_limit, 200);
    EXPECT_EQ(cfg.world_writable_dirs.size(), 2);
    EXPECT_EQ(cfg.world_writable_exclude.size(), 2);
}

// Test network scanner options
TEST_F(ArgumentParserTest, ParseNetworkOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--network-debug", "--network-listen-only", "--network-proto", "tcp", "--network-states", "LISTEN,ESTABLISHED"};

    EXPECT_TRUE(parser.parse(7, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.network_debug);
    EXPECT_TRUE(cfg.network_listen_only);
    EXPECT_EQ(cfg.network_proto, "tcp");
    EXPECT_EQ(cfg.network_states.size(), 2);
}

// Test network advanced options
TEST_F(ArgumentParserTest, ParseNetworkAdvancedOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_net_adv[] = {"sys-scan", "--network-advanced", "--network-fanout", "10", "--network-fanout-unique", "5"};

    EXPECT_TRUE(parser.parse(6, const_cast<char**>(argv_net_adv), cfg));
    EXPECT_TRUE(cfg.network_advanced);
    EXPECT_EQ(cfg.network_fanout_threshold, 10);
    EXPECT_EQ(cfg.network_fanout_unique_threshold, 5);
}

// Test IOC scanner options
TEST_F(ArgumentParserTest, ParseIOCOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_ioc_opts[] = {"sys-scan", "--ioc-env-trust", "--ioc-exec-trace", "30"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv_ioc_opts), cfg));
    EXPECT_TRUE(cfg.ioc_env_trust);
    EXPECT_TRUE(cfg.ioc_exec_trace);
    EXPECT_EQ(cfg.ioc_exec_trace_seconds, 30);
}

// Test parallel execution options
TEST_F(ArgumentParserTest, ParseParallelOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_parallel_opts[] = {"sys-scan", "--parallel", "--parallel-threads", "8"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv_parallel_opts), cfg));
    EXPECT_TRUE(cfg.parallel);
    EXPECT_EQ(cfg.parallel_max_threads, 8);
}

// Test container options
TEST_F(ArgumentParserTest, ParseContainerOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_container_opts[] = {"sys-scan", "--containers", "--container-id", "abc123"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv_container_opts), cfg));
    EXPECT_TRUE(cfg.containers);
    EXPECT_EQ(cfg.container_id_filter, "abc123");
}

// Test rule engine options
TEST_F(ArgumentParserTest, ParseRuleEngineOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_rules_opts[] = {"sys-scan", "--rules-enable", "--rules-dir", "/path/to/rules", "--rules-allow-legacy"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv_rules_opts), cfg));
    EXPECT_TRUE(cfg.rules_enable);
    EXPECT_EQ(cfg.rules_dir, "/path/to/rules");
    EXPECT_TRUE(cfg.rules_allow_legacy);
}

// Test compliance options
TEST_F(ArgumentParserTest, ParseComplianceOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_compliance_opts[] = {"sys-scan", "--compliance", "--compliance-standards", "cis,pci"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv_compliance_opts), cfg));
    EXPECT_TRUE(cfg.compliance);
    EXPECT_EQ(cfg.compliance_standards.size(), 2);
}

// Test privilege options
TEST_F(ArgumentParserTest, ParsePrivilegeOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv_privilege[] = {"sys-scan", "--drop-priv", "--keep-cap-dac", "--seccomp", "--seccomp-strict"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv_privilege), cfg));
    EXPECT_TRUE(cfg.drop_priv);
    EXPECT_TRUE(cfg.keep_cap_dac);
    EXPECT_TRUE(cfg.seccomp);
    EXPECT_TRUE(cfg.seccomp_strict);
}

// Test metadata suppression options
TEST_F(ArgumentParserTest, ParseMetadataOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--no-user-meta", "--no-cmdline-meta", "--no-hostname-meta"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.no_user_meta);
    EXPECT_TRUE(cfg.no_cmdline_meta);
    EXPECT_TRUE(cfg.no_hostname_meta);
}

// Test output options
TEST_F(ArgumentParserTest, ParseOutputOptions) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--write-env", "/tmp/env.txt", "--fast-scan", "--timings", "--canonical"};

    EXPECT_TRUE(parser.parse(6, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.write_env_file, "/tmp/env.txt");
    EXPECT_TRUE(cfg.fast_scan);
    EXPECT_TRUE(cfg.timings);
    EXPECT_TRUE(cfg.canonical);
}

// Test hardening option
TEST_F(ArgumentParserTest, ParseHardeningOption) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--hardening"};

    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.hardening);
}

// Test integrity rehash option
TEST_F(ArgumentParserTest, ParseIntegrityRehashOption) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--integrity-pkg-rehash"};

    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.integrity_pkg_rehash);
}

// Test invalid integer for different flags
TEST_F(ArgumentParserTest, ParseInvalidIntegerForDifferentFlags) {
    ArgumentParser parser;
    Config cfg;

    // Test invalid --fs-world-writable-limit
    const char* argv1[] = {"sys-scan", "--fs-world-writable-limit", "invalid"};
    EXPECT_FALSE(parser.parse(3, const_cast<char**>(argv1), cfg));

    // Test invalid --network-fanout
    Config cfg2;
    const char* argv2[] = {"sys-scan", "--network-fanout", "notanumber"};
    EXPECT_FALSE(parser.parse(3, const_cast<char**>(argv2), cfg2));

    // Test invalid --parallel-threads
    Config cfg3;
    const char* argv3[] = {"sys-scan", "--parallel-threads", "abc"};
    EXPECT_FALSE(parser.parse(3, const_cast<char**>(argv3), cfg3));
}

// Test missing values for required arguments
TEST_F(ArgumentParserTest, ParseMissingValues) {
    ArgumentParser parser;
    Config cfg;

    // Missing value for --output
    const char* argv1[] = {"sys-scan", "--output"};
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv1), cfg));

    // Missing value for --min-severity
    Config cfg2;
    const char* argv2[] = {"sys-scan", "--min-severity"};
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv2), cfg2));

    // Missing value for --network-proto
    Config cfg3;
    const char* argv3[] = {"sys-scan", "--network-proto"};
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv3), cfg3));
}

// Test CSV parsing edge cases
TEST_F(ArgumentParserTest, ParseCSVEdgeCases) {
    ArgumentParser parser;
    Config cfg;

    // Empty CSV
    const char* argv1[] = {"sys-scan", "--enable", ""};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv1), cfg));
    EXPECT_TRUE(cfg.enable_scanners.empty());

    // CSV with empty values
    Config cfg2;
    const char* argv2[] = {"sys-scan", "--enable", "a,,b,"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv2), cfg2));
    EXPECT_EQ(cfg2.enable_scanners.size(), 2);
    EXPECT_TRUE(std::find(cfg2.enable_scanners.begin(), cfg2.enable_scanners.end(), "a") != cfg2.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg2.enable_scanners.begin(), cfg2.enable_scanners.end(), "b") != cfg2.enable_scanners.end());

    // Single value CSV
    Config cfg3;
    const char* argv3[] = {"sys-scan", "--enable", "single"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv3), cfg3));
    EXPECT_EQ(cfg3.enable_scanners.size(), 1);
    EXPECT_EQ(cfg3.enable_scanners[0], "single");
}

} // namespace sys_scan