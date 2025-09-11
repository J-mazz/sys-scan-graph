#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/RuleEngine.h"
#include "../src/core/Config.h"
#include "../src/core/Scanner.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace sys_scan {

class RuleEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for rule files
        temp_dir = fs::temp_directory_path() / "sys_scan_rule_test";
        fs::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files and directory
        fs::remove_all(temp_dir);
    }

    fs::path create_rule_file(const std::string& content, const std::string& filename = "") {
        auto rule_file = temp_dir / (filename.empty() ? ("test_" + std::to_string(rand()) + ".rule") : filename);
        std::ofstream file(rule_file);
        file << content;
        file.close();
        return rule_file;
    }

    fs::path temp_dir;
    RuleEngine engine;
};

TEST_F(RuleEngineTest, EmptyDirectory) {
    std::string warnings;
    engine.load_dir("", warnings);
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, NonExistentDirectory) {
    std::string warnings;
    engine.load_dir("/non/existent/directory", warnings);
    EXPECT_EQ(warnings, "rules_dir_missing");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].code, "rules_dir_missing");
}

TEST_F(RuleEngineTest, EmptyRuleFile) {
    auto rule_file = create_rule_file("");
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, RuleWithoutId) {
    std::string rule_content = R"(
field=id
contains=test
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_TRUE(warnings.empty()); // No warnings for rules without ID (they're just skipped)
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, BasicRuleWithId) {
    std::string rule_content = R"(
id=test_rule
field=id
contains=TEST
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, RuleWithUnsupportedVersion) {
    std::string rule_content = R"(
id=version_test
rule_version=2
field=id
contains=test
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_EQ(warnings, "version_test:unsupported_version=2;");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].rule_id, "version_test");
    EXPECT_EQ(engine.warnings()[0].code, "unsupported_version");
    EXPECT_EQ(engine.warnings()[0].detail, "2");
}

TEST_F(RuleEngineTest, RuleWithNoConditions) {
    std::string rule_content = R"(
id=no_conditions_rule
scope=*
severity_override=medium
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_EQ(warnings, "no_conditions_rule:no_conditions;");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].rule_id, "no_conditions_rule");
    EXPECT_EQ(engine.warnings()[0].code, "no_conditions");
}

TEST_F(RuleEngineTest, RuleWithLegacyFields) {
    std::string rule_content = R"(
id=legacy_rule
field=id
contains=LEGACY
equals=exact_match
severity_override=critical
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, RuleWithMultiConditions) {
    std::string rule_content = R"(
id=multi_condition_rule
condition0.field=id
condition0.contains=TEST
condition1.field=title
condition1.equals=Test Finding
logic=any
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, RuleWithRegex) {
    std::string rule_content = R"(
id=regex_rule
field=description
regex=error.*occurred
severity_override=medium
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(engine.warnings().empty());
}

TEST_F(RuleEngineTest, RuleWithBadRegex) {
    std::string rule_content = R"(
id=bad_regex_rule
field=description
regex=[invalid regex
severity_override=low
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_EQ(warnings, "bad_regex_rule:bad_regex;");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].rule_id, "bad_regex_rule");
    EXPECT_EQ(engine.warnings()[0].code, "bad_regex");
}

TEST_F(RuleEngineTest, RuleWithTooLongRegex) {
    std::string long_regex(600, 'a'); // Exceeds MAX_REGEX_LENGTH
    std::string rule_content = "id=long_regex_rule\nfield=description\nregex=" + long_regex + "\nseverity_override=low\n";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_EQ(warnings, "long_regex_rule:regex_too_long;");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].rule_id, "long_regex_rule");
    EXPECT_EQ(engine.warnings()[0].code, "regex_too_long");
}

TEST_F(RuleEngineTest, RuleWithTooManyConditions) {
    std::string rule_content = "id=many_conditions_rule\n";
    for (int i = 0; i < 30; ++i) { // Exceeds MAX_CONDITIONS_PER_RULE
        rule_content += "condition" + std::to_string(i) + ".field=id\n";
        rule_content += "condition" + std::to_string(i) + ".contains=test" + std::to_string(i) + "\n";
    }
    rule_content += "severity_override=medium\n";

    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_EQ(warnings, "many_conditions_rule:too_many_conditions;");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].rule_id, "many_conditions_rule");
    EXPECT_EQ(engine.warnings()[0].code, "too_many_conditions");
}

TEST_F(RuleEngineTest, MaxRulesExceeded) {
    // Create more than MAX_RULES files
    for (int i = 0; i < RuleEngine::MAX_RULES + 5; ++i) {
        std::string rule_content = "id=rule_" + std::to_string(i) + "\nfield=id\ncontains=test\n";
        create_rule_file(rule_content, "rule_" + std::to_string(i) + ".rule");
    }

    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);
    EXPECT_EQ(warnings, "global:max_rules_exceeded=1000;");
    ASSERT_EQ(engine.warnings().size(), 1);
    EXPECT_EQ(engine.warnings()[0].code, "max_rules_exceeded");
}

TEST_F(RuleEngineTest, ApplyRuleWithMatchingCondition) {
    std::string rule_content = R"(
id=match_rule
field=id
contains=TEST
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "TEST-001";
    finding.title = "Test Finding";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);

    EXPECT_EQ(finding.severity, Severity::High);
}

TEST_F(RuleEngineTest, ApplyRuleWithNonMatchingCondition) {
    std::string rule_content = R"(
id=no_match_rule
field=id
contains=DIFFERENT
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "TEST-001";
    finding.title = "Test Finding";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);

    EXPECT_EQ(finding.severity, Severity::Low); // Should remain unchanged
}

TEST_F(RuleEngineTest, ApplyRuleWithScopeMatch) {
    std::string rule_content = R"(
id=scoped_rule
scope=test_scanner
field=id
contains=TEST
severity_override=critical
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "TEST-001";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::Critical);
}

TEST_F(RuleEngineTest, ApplyRuleWithScopeMismatch) {
    std::string rule_content = R"(
id=scoped_rule
scope=different_scanner
field=id
contains=TEST
severity_override=critical
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "TEST-001";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::Low); // Should remain unchanged
}

TEST_F(RuleEngineTest, ApplyRuleWithWildcardScope) {
    std::string rule_content = R"(
id=wildcard_rule
scope=*
field=id
contains=TEST
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "TEST-001";
    finding.severity = Severity::Low;

    engine.apply("any_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::High);
}

TEST_F(RuleEngineTest, ApplyRuleWithRegexMatch) {
    std::string rule_content = R"(
id=regex_match_rule
field=description
regex=error.*found
severity_override=medium
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.description = "An error was found in the system";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::Medium);
}

TEST_F(RuleEngineTest, ApplyRuleWithMetadataField) {
    std::string rule_content = R"(
id=metadata_rule
field=custom_field
contains=special
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.metadata["custom_field"] = "special_value";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::High);
}

TEST_F(RuleEngineTest, ApplyRuleWithMitreTechniques) {
    std::string rule_content = R"(
id=mitre_rule
field=id
contains=MITRE
mitre=T1059,T1071
severity_override=medium
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "MITRE-TEST";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::Medium);
    EXPECT_EQ(finding.metadata["mitre_techniques"], "T1059,T1071");
}

TEST_F(RuleEngineTest, ApplyRuleWithMultipleMitreTechniques) {
    std::string rule_content = R"(
id=mitre_rule
field=id
contains=MITRE
mitre=T1059,T1071
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "MITRE-TEST";
    finding.metadata["mitre_techniques"] = "T1001,T1002"; // Existing techniques

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.metadata["mitre_techniques"], "T1001,T1002,T1059,T1071");
}

TEST_F(RuleEngineTest, ApplyRuleWithLogicAny) {
    std::string rule_content = R"(
id=logic_any_rule
condition0.field=id
condition0.contains=TEST
condition1.field=title
condition1.contains=ALERT
logic=any
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding1;
    finding1.id = "TEST-001";
    finding1.title = "Normal Title";
    finding1.severity = Severity::Low;

    Finding finding2;
    finding2.id = "NORMAL-001";
    finding2.title = "ALERT Title";
    finding2.severity = Severity::Low;

    engine.apply("test_scanner", finding1);
    EXPECT_EQ(finding1.severity, Severity::High); // Matches first condition

    engine.apply("test_scanner", finding2);
    EXPECT_EQ(finding2.severity, Severity::High); // Matches second condition
}

TEST_F(RuleEngineTest, ApplyRuleWithLogicAll) {
    std::string rule_content = R"(
id=logic_all_rule
condition0.field=id
condition0.contains=TEST
condition1.field=title
condition1.contains=ALERT
logic=all
severity_override=critical
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding1;
    finding1.id = "TEST-001";
    finding1.title = "ALERT Title";
    finding1.severity = Severity::Low;

    Finding finding2;
    finding2.id = "TEST-001";
    finding2.title = "Normal Title";
    finding2.severity = Severity::Low;

    engine.apply("test_scanner", finding1);
    EXPECT_EQ(finding1.severity, Severity::Critical); // Matches both conditions

    engine.apply("test_scanner", finding2);
    EXPECT_EQ(finding2.severity, Severity::Low); // Matches only first condition
}

TEST_F(RuleEngineTest, WarningsAggregatedFormat) {
    std::string rule_content1 = R"(
id=rule1
rule_version=2
field=id
contains=test
)";
    std::string rule_content2 = R"(
id=rule2
field=id
contains=test
rule_version=3
)";

    create_rule_file(rule_content1, "rule1.rule");
    create_rule_file(rule_content2, "rule2.rule");

    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    std::string aggregated = engine.warnings_aggregated();
    EXPECT_TRUE(aggregated.find("rule1:unsupported_version=2") != std::string::npos);
    EXPECT_TRUE(aggregated.find("rule2:unsupported_version=3") != std::string::npos);
}

TEST_F(RuleEngineTest, EmptyRuleEngineApply) {
    // Test applying rules when no rules are loaded
    Finding finding;
    finding.id = "TEST-001";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::Low); // Should remain unchanged
}

TEST_F(RuleEngineTest, RuleWithEmptyCondition) {
    std::string rule_content = R"(
id=empty_condition_rule
condition0.field=id
# No constraints - should not match
severity_override=high
)";
    create_rule_file(rule_content);
    std::string warnings;
    engine.load_dir(temp_dir.string(), warnings);

    Finding finding;
    finding.id = "TEST-001";
    finding.severity = Severity::Low;

    engine.apply("test_scanner", finding);
    EXPECT_EQ(finding.severity, Severity::Low); // Should not match due to empty condition
}

TEST_F(RuleEngineTest, GlobalRuleEngineInstance) {
    RuleEngine& global_engine = rule_engine();
    EXPECT_EQ(&global_engine, &rule_engine()); // Should return same instance
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan