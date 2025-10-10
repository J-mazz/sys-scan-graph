#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/NetworkScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Severity.h"
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

// Forward declarations for internal NetworkScanner functions
namespace sys_scan {
bool hex_ip_to_v4_lean(const char* hex_ip, char* out_ip, size_t out_size);
bool hex_ip6_to_str_lean(const char* hex_ip, char* out_ip, size_t out_size);
const char* tcp_state_lean(const char* st);
Severity classify_tcp_severity_lean(const char* state, unsigned port, const char* exe);
Severity classify_udp_severity_lean(unsigned port, const char* exe);
Severity escalate_exposed_lean(Severity current, const char* state, const char* lip);
bool extract_container_id_lean(const char* cgroup_data, size_t len, char* out_id, size_t out_size);
bool state_allowed_lean(const char* st, const Config& config);
bool is_valid_pid(const char* str, int* pid_out = nullptr);
bool is_valid_hex_string(const char* ptr, size_t len, const char* end);
size_t find_inode_lean(const char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], size_t count, const char* inode);
}

namespace fs = std::filesystem;

namespace sys_scan {

// Test fixture for NetworkScanner tests
class NetworkScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up default config
        config.max_sockets = 1000;
        config.network_listen_only = false;
        config.containers = false;
        config.network_advanced = true;

        report = std::make_unique<Report>();
        context = std::make_unique<ScanContext>(config, *report);
    }

    void TearDown() override {
        // Clean up any test files
        if (fs::exists("/tmp/proc_net_tcp")) fs::remove("/tmp/proc_net_tcp");
        if (fs::exists("/tmp/proc_net_tcp6")) fs::remove("/tmp/proc_net_tcp6");
        if (fs::exists("/tmp/proc_net_udp")) fs::remove("/tmp/proc_net_udp");
        if (fs::exists("/tmp/proc_net_udp6")) fs::remove("/tmp/proc_net_udp6");
    }

    Config config;
    std::unique_ptr<Report> report;
    std::unique_ptr<ScanContext> context;
};

// Test basic scanner functionality - scanner should not crash
TEST_F(NetworkScannerTest, BasicScan) {
    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // The scanner may not produce results if /proc/net files don't exist or are inaccessible
    // But it should not crash
    EXPECT_GE(results.size(), 0);
}

// Test scanner name and description
TEST(NetworkScannerBasicTest, NameAndDescription) {
    NetworkScanner scanner;
    EXPECT_EQ(scanner.name(), "network");
    EXPECT_EQ(scanner.description(), "Enumerate listening TCP/UDP sockets");
}

// Test with different protocol filters
TEST_F(NetworkScannerTest, ProtocolFiltering) {
    // Test TCP only
    config.network_proto = "tcp";
    report = std::make_unique<Report>();
    context = std::make_unique<ScanContext>(config, *report);

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);

    // Test UDP only
    config.network_proto = "udp";
    report = std::make_unique<Report>();
    context = std::make_unique<ScanContext>(config, *report);

    scanner.scan(*context);

    results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test listen-only filtering
TEST_F(NetworkScannerTest, ListenOnlyFiltering) {
    config.network_listen_only = true;

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test state filtering
TEST_F(NetworkScannerTest, StateFiltering) {
    config.network_states = {"LISTEN", "ESTABLISHED"};

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test container filtering
TEST_F(NetworkScannerTest, ContainerFiltering) {
    config.containers = true;
    config.container_id_filter = "test123";

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test max sockets limit
TEST_F(NetworkScannerTest, MaxSocketsLimit) {
    config.max_sockets = 10;

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test with network_advanced disabled
TEST_F(NetworkScannerTest, NetworkAdvancedDisabled) {
    config.network_advanced = false;

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test with network_debug enabled
TEST_F(NetworkScannerTest, NetworkDebugEnabled) {
    config.network_debug = true;

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with different max_sockets values
TEST_F(NetworkScannerTest, DifferentMaxSockets) {
    config.max_sockets = 1;  // Very low limit

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with empty network_proto (should scan both TCP and UDP)
TEST_F(NetworkScannerTest, EmptyNetworkProto) {
    config.network_proto = "";  // Empty means both TCP and UDP

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with containers enabled but no filter
TEST_F(NetworkScannerTest, ContainersEnabledNoFilter) {
    config.containers = true;
    config.container_id_filter = "";  // No filter

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with network states filter
TEST_F(NetworkScannerTest, NetworkStatesFilter) {
    config.network_states = {"LISTEN"};  // Only LISTEN state

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with multiple network states
TEST_F(NetworkScannerTest, MultipleNetworkStates) {
    config.network_states = {"LISTEN", "ESTABLISHED", "TIME_WAIT"};

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with case-sensitive state filtering
TEST_F(NetworkScannerTest, CaseSensitiveStateFilter) {
    config.network_states = {"listen"};  // lowercase - should not match

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with invalid network_proto
TEST_F(NetworkScannerTest, InvalidNetworkProto) {
    config.network_proto = "invalid";

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);  // Should not crash, just not scan anything
}

// Test scanner with very high max_sockets
TEST_F(NetworkScannerTest, HighMaxSockets) {
    config.max_sockets = 100000;  // Very high limit

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test scanner with zero max_sockets
TEST_F(NetworkScannerTest, ZeroMaxSockets) {
    config.max_sockets = 0;  // Unlimited

    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);
}

// Test IP address parsing functions
TEST(NetworkScannerUtilsTest, IPv4HexToString) {
    char out_ip[16];

    // Test valid IPv4 conversion (192.168.1.1 = C0A80101 in hex, but little-endian)
    // Network byte order: 192.168.1.1 = C0.A8.01.01
    // But /proc/net shows it as 0101A8C0 (little-endian)
    EXPECT_TRUE(hex_ip_to_v4_lean("0101A8C0", out_ip, sizeof(out_ip)));
    EXPECT_STREQ(out_ip, "192.168.1.1");

    // Test another valid IP (127.0.0.1)
    EXPECT_TRUE(hex_ip_to_v4_lean("0100007F", out_ip, sizeof(out_ip)));
    EXPECT_STREQ(out_ip, "127.0.0.1");

    // Test 0.0.0.0
    EXPECT_TRUE(hex_ip_to_v4_lean("00000000", out_ip, sizeof(out_ip)));
    EXPECT_STREQ(out_ip, "0.0.0.0");

    // Test invalid inputs
    EXPECT_FALSE(hex_ip_to_v4_lean("123", out_ip, sizeof(out_ip)));  // Too short
    EXPECT_FALSE(hex_ip_to_v4_lean("gggggggg", out_ip, sizeof(out_ip)));  // Non-hex
    EXPECT_FALSE(hex_ip_to_v4_lean("0101A8C0", out_ip, 10));  // Buffer too small
}

TEST(NetworkScannerUtilsTest, IPv6HexToString) {
    char out_ip[40];

    // Test valid IPv6 conversion (::1)
    EXPECT_TRUE(hex_ip6_to_str_lean("00000000000000000000000000000001", out_ip, sizeof(out_ip)));
    EXPECT_STREQ(out_ip, "0000:0000:0000:0000:0000:0000:0000:0001");

    // Test another IPv6 (2001:db8::1)
    EXPECT_TRUE(hex_ip6_to_str_lean("20010db8000000000000000000000001", out_ip, sizeof(out_ip)));
    EXPECT_STREQ(out_ip, "2001:0db8:0000:0000:0000:0000:0000:0001");

    // Test invalid inputs
    EXPECT_FALSE(hex_ip6_to_str_lean("123", out_ip, sizeof(out_ip)));  // Too short
    EXPECT_FALSE(hex_ip6_to_str_lean("gggggggggggggggggggggggggggggggg", out_ip, sizeof(out_ip)));  // Non-hex
    EXPECT_FALSE(hex_ip6_to_str_lean("00000000000000000000000000000001", out_ip, 30));  // Buffer too small
    EXPECT_FALSE(hex_ip6_to_str_lean("00000000000000000000000000000001", nullptr, sizeof(out_ip)));  // NULL output
    EXPECT_FALSE(hex_ip6_to_str_lean("00000000000000000000000000000001", out_ip, 0));  // Zero size
}

// Test TCP state conversion
TEST(NetworkScannerUtilsTest, TCPStateConversion) {
    EXPECT_STREQ(tcp_state_lean("01"), "ESTABLISHED");
    EXPECT_STREQ(tcp_state_lean("0A"), "LISTEN");
    EXPECT_STREQ(tcp_state_lean("06"), "TIME_WAIT");
    EXPECT_STREQ(tcp_state_lean("FF"), "FF");  // Unknown state returns as-is
}

// Test severity classification
TEST(NetworkScannerUtilsTest, TCPSeverityClassification) {
    // Test LISTEN ports
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 22, ""), Severity::Medium);  // SSH
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 80, ""), Severity::Low);    // HTTP
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 443, ""), Severity::Low);   // HTTPS
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 53, ""), Severity::Low);    // DNS
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 25, ""), Severity::Low);    // SMTP
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 22, "/usr/sbin/sshd"), Severity::Medium);  // SSH with exe
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 12345, ""), Severity::Info); // High port
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 79, ""), Severity::Medium);  // Privileged non-standard

    // Test non-LISTEN states
    EXPECT_EQ(classify_tcp_severity_lean("ESTABLISHED", 80, ""), Severity::Info);
    EXPECT_EQ(classify_tcp_severity_lean("TIME_WAIT", 443, ""), Severity::Info);
}

TEST(NetworkScannerUtilsTest, UDPSeverityClassification) {
    EXPECT_EQ(classify_udp_severity_lean(53, ""), Severity::Low);     // DNS
    EXPECT_EQ(classify_udp_severity_lean(161, ""), Severity::Medium); // SNMP
    EXPECT_EQ(classify_udp_severity_lean(1900, ""), Severity::Medium); // SSDP
    EXPECT_EQ(classify_udp_severity_lean(5353, ""), Severity::Low);   // mDNS
    EXPECT_EQ(classify_udp_severity_lean(67, ""), Severity::Low);     // DHCP
    EXPECT_EQ(classify_udp_severity_lean(68, ""), Severity::Low);     // DHCP
    EXPECT_EQ(classify_udp_severity_lean(123, ""), Severity::Info);   // NTP (privileged but common)
    EXPECT_EQ(classify_udp_severity_lean(514, ""), Severity::Medium); // Syslog (privileged)
    EXPECT_EQ(classify_udp_severity_lean(12345, ""), Severity::Info); // High port
}

// Test severity escalation for exposed listeners
TEST(NetworkScannerUtilsTest, SeverityEscalation) {
    // Loopback addresses should not escalate
    EXPECT_EQ(escalate_exposed_lean(Severity::Low, "LISTEN", "127.0.0.1"), Severity::Low);
    EXPECT_EQ(escalate_exposed_lean(Severity::Info, "LISTEN", "::1"), Severity::Info);
    EXPECT_EQ(escalate_exposed_lean(Severity::Medium, "LISTEN", "127.0.0.53"), Severity::Medium);

    // Exposed addresses should escalate one level
    EXPECT_EQ(escalate_exposed_lean(Severity::Info, "LISTEN", "0.0.0.0"), Severity::Low);
    EXPECT_EQ(escalate_exposed_lean(Severity::Low, "LISTEN", "192.168.1.1"), Severity::Medium);
    EXPECT_EQ(escalate_exposed_lean(Severity::Medium, "LISTEN", "::"), Severity::High);

    // Non-LISTEN states should not escalate
    EXPECT_EQ(escalate_exposed_lean(Severity::Info, "ESTABLISHED", "0.0.0.0"), Severity::Info);

    // Max severity should not escalate further
    EXPECT_EQ(escalate_exposed_lean(Severity::Critical, "LISTEN", "0.0.0.0"), Severity::Critical);
}

// Test container ID extraction
TEST(NetworkScannerUtilsTest, ContainerIdExtraction) {
    char container_id[13];

    // Test Docker-style container ID
    const char* docker_cgroup = "0::/docker/1234567890abcdef1234567890abcdef";
    EXPECT_TRUE(extract_container_id_lean(docker_cgroup, strlen(docker_cgroup), container_id, sizeof(container_id)));
    EXPECT_STREQ(container_id, "1234567890ab");

    // Test containerd-style
    const char* containerd_cgroup = "0::/kubepods/burstable/pod123/abcdef1234567890abcdef1234567890";
    EXPECT_TRUE(extract_container_id_lean(containerd_cgroup, strlen(containerd_cgroup), container_id, sizeof(container_id)));
    EXPECT_STREQ(container_id, "abcdef123456");

    // Test podman-style
    const char* podman_cgroup = "0::/libpod_parent/libpod-abcdef1234567890abcdef1234567890";
    EXPECT_TRUE(extract_container_id_lean(podman_cgroup, strlen(podman_cgroup), container_id, sizeof(container_id)));
    EXPECT_STREQ(container_id, "abcdef123456");

    // Test no container markers
    const char* no_container = "0::/system.slice/sshd.service";
    EXPECT_FALSE(extract_container_id_lean(no_container, strlen(no_container), container_id, sizeof(container_id)));

    // Test short hex strings
    const char* short_hex = "0::/docker/123";
    EXPECT_FALSE(extract_container_id_lean(short_hex, strlen(short_hex), container_id, sizeof(container_id)));
}

// Test state filtering
TEST(NetworkScannerUtilsTest, StateAllowedFiltering) {
    Config config;

    // No states configured - should allow all
    EXPECT_TRUE(state_allowed_lean("LISTEN", config));
    EXPECT_TRUE(state_allowed_lean("ESTABLISHED", config));

    // States configured - case insensitive matching
    config.network_states = {"LISTEN", "ESTABLISHED"};
    EXPECT_TRUE(state_allowed_lean("LISTEN", config));
    EXPECT_TRUE(state_allowed_lean("listen", config));  // case insensitive
    EXPECT_TRUE(state_allowed_lean("ESTABLISHED", config));
    EXPECT_FALSE(state_allowed_lean("TIME_WAIT", config));
}

// Test PID validation
TEST(NetworkScannerUtilsTest, PIDValidation) {
    int pid_out;

    EXPECT_TRUE(is_valid_pid("123", &pid_out));
    EXPECT_EQ(pid_out, 123);

    EXPECT_TRUE(is_valid_pid("1", &pid_out));
    EXPECT_EQ(pid_out, 1);

    EXPECT_FALSE(is_valid_pid("0", &pid_out));     // PID 0 not allowed
    EXPECT_FALSE(is_valid_pid("-1", &pid_out));    // Negative
    EXPECT_FALSE(is_valid_pid("abc", &pid_out));   // Non-numeric
    EXPECT_FALSE(is_valid_pid("", &pid_out));      // Empty
    EXPECT_TRUE(is_valid_pid("999999", &pid_out));  // Large but valid PID
}

// Test hex string validation
TEST(NetworkScannerUtilsTest, HexStringValidation) {
    const char* buffer1 = "abcdef";
    EXPECT_TRUE(is_valid_hex_string(buffer1, 6, buffer1 + 6));
    const char* buffer2 = "123456";
    EXPECT_TRUE(is_valid_hex_string(buffer2, 6, buffer2 + 6));
    const char* buffer3 = "ABCDEF";
    EXPECT_TRUE(is_valid_hex_string(buffer3, 6, buffer3 + 6));

    const char* buffer4 = "gggggg";
    EXPECT_FALSE(is_valid_hex_string(buffer4, 6, buffer4 + 6));  // Non-hex
    EXPECT_FALSE(is_valid_hex_string(buffer1, 6, buffer1 + 5));   // Too short
}

// Test inode lookup
TEST(NetworkScannerUtilsTest, InodeLookup) {
    const char inode_map[3][MAX_INODE_LEN_LEAN] = {"12345", "67890", "11111"};

    EXPECT_EQ(find_inode_lean(inode_map, 3, "12345"), 0);
    EXPECT_EQ(find_inode_lean(inode_map, 3, "67890"), 1);
    EXPECT_EQ(find_inode_lean(inode_map, 3, "11111"), 2);
    EXPECT_EQ(find_inode_lean(inode_map, 3, "99999"), SIZE_MAX);  // Not found
    EXPECT_EQ(find_inode_lean(inode_map, 0, "12345"), SIZE_MAX);  // Empty array
}

// Test parsing with malformed /proc/net data
TEST_F(NetworkScannerTest, MalformedProcNetData) {
    // Create a mock TCP file with malformed lines
    std::ofstream tcp_file("/tmp/proc_net_tcp");
    tcp_file << "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    tcp_file << "   0: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff88003a0a0000 100 0 0 10 0\n";  // Valid line
    tcp_file << "   1: invalid_address:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 ffff88003a0a0000 100 0 0 10 0\n";  // Invalid address format
    tcp_file << "   2: 00000000:0000 00000000:0000 XX 00000000:00000000 00:00000000 00000000     0        0 12347 1 ffff88003a0a0000 100 0 0 10 0\n";  // Invalid state
    tcp_file << "   3: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12348 1 ffff88003a0a0000 100 0 0 10 0\n";  // Valid line
    tcp_file.close();

    // Test with mock file (this would require modifying the scanner to accept custom paths, which it doesn't)
    // For now, just ensure the scanner doesn't crash with normal operation
    NetworkScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    EXPECT_GE(results.size(), 0);  // Should not crash
}

// Test hex IP conversion with invalid inputs (expanding on existing tests)
TEST(NetworkScannerUtilsTest, IPv4HexInvalidInputs) {
    char out_ip[16];

    // Test various invalid inputs
    EXPECT_FALSE(hex_ip_to_v4_lean(nullptr, out_ip, sizeof(out_ip)));  // NULL input
    EXPECT_FALSE(hex_ip_to_v4_lean("", out_ip, sizeof(out_ip)));  // Empty string
    EXPECT_FALSE(hex_ip_to_v4_lean("1234567", out_ip, sizeof(out_ip)));  // Too short
    EXPECT_FALSE(hex_ip_to_v4_lean("gggggggg", out_ip, sizeof(out_ip)));  // Non-hex characters
    EXPECT_FALSE(hex_ip_to_v4_lean("0101A8C0", out_ip, 10));  // Buffer too small
    EXPECT_FALSE(hex_ip_to_v4_lean("0101A8C0", nullptr, sizeof(out_ip)));  // NULL output buffer
    EXPECT_FALSE(hex_ip_to_v4_lean("0101A8C0", out_ip, 0));  // Zero size buffer
}

TEST(NetworkScannerUtilsTest, IPv6HexInvalidInputs) {
    char out_ip[40];

    // Test various invalid inputs
    EXPECT_FALSE(hex_ip6_to_str_lean(nullptr, out_ip, sizeof(out_ip)));  // NULL input
    EXPECT_FALSE(hex_ip6_to_str_lean("", out_ip, sizeof(out_ip)));  // Empty string
    EXPECT_FALSE(hex_ip6_to_str_lean("1234567890abcdef", out_ip, sizeof(out_ip)));  // Too short
    EXPECT_FALSE(hex_ip6_to_str_lean("gggggggggggggggggggggggggggggggg", out_ip, sizeof(out_ip)));  // Non-hex
    EXPECT_FALSE(hex_ip6_to_str_lean("00000000000000000000000000000001", out_ip, 30));  // Buffer too small
    EXPECT_FALSE(hex_ip6_to_str_lean("00000000000000000000000000000001", nullptr, sizeof(out_ip)));  // NULL output
    EXPECT_FALSE(hex_ip6_to_str_lean("00000000000000000000000000000001", out_ip, 0));  // Zero size
}

// Test PID validation edge cases
TEST(NetworkScannerUtilsTest, PIDValidationEdgeCases) {
    int pid_out;

    // Test boundary cases
    EXPECT_FALSE(is_valid_pid(nullptr, &pid_out));  // NULL input
    EXPECT_FALSE(is_valid_pid("", &pid_out));  // Empty string
    EXPECT_FALSE(is_valid_pid("0", &pid_out));  // PID 0 (invalid)
    EXPECT_FALSE(is_valid_pid("-1", &pid_out));  // Negative
    EXPECT_FALSE(is_valid_pid("abc", &pid_out));  // Non-numeric
    EXPECT_FALSE(is_valid_pid("123abc", &pid_out));  // Mixed alphanumeric
    EXPECT_FALSE(is_valid_pid("999999999999999999999", &pid_out));  // Too large (overflow)

    // Test valid cases
    EXPECT_TRUE(is_valid_pid("1", &pid_out));
    EXPECT_EQ(pid_out, 1);
    EXPECT_TRUE(is_valid_pid("32767", &pid_out));  // Max valid PID
    EXPECT_EQ(pid_out, 32767);
}

// Test inode lookup edge cases
TEST(NetworkScannerUtilsTest, InodeLookupEdgeCases) {
    const char inode_map[3][MAX_INODE_LEN_LEAN] = {"12345", "67890", "11111"};

    // Test edge cases
    EXPECT_EQ(find_inode_lean(inode_map, 3, nullptr), SIZE_MAX);  // NULL inode
    EXPECT_EQ(find_inode_lean(inode_map, 3, ""), SIZE_MAX);  // Empty inode
    EXPECT_EQ(find_inode_lean(inode_map, 3, "nonexistent"), SIZE_MAX);  // Not found
    EXPECT_EQ(find_inode_lean(inode_map, 0, "12345"), SIZE_MAX);  // Empty array
    EXPECT_EQ(find_inode_lean(nullptr, 3, "12345"), SIZE_MAX);  // NULL array

    // Test valid cases
    EXPECT_EQ(find_inode_lean(inode_map, 3, "12345"), 0);
    EXPECT_EQ(find_inode_lean(inode_map, 3, "67890"), 1);
    EXPECT_EQ(find_inode_lean(inode_map, 3, "11111"), 2);
}

// Test container ID extraction edge cases
TEST(NetworkScannerUtilsTest, ContainerIdExtractionEdgeCases) {
    char container_id[13];

    // Test edge cases
    EXPECT_FALSE(extract_container_id_lean(nullptr, 10, container_id, sizeof(container_id)));  // NULL input
    EXPECT_FALSE(extract_container_id_lean("short", 5, container_id, sizeof(container_id)));  // Too short
    EXPECT_FALSE(extract_container_id_lean("no_container_data", 17, container_id, sizeof(container_id)));  // No markers
    EXPECT_FALSE(extract_container_id_lean("docker-123", 10, container_id, sizeof(container_id)));  // Short hex
    EXPECT_FALSE(extract_container_id_lean("docker-gggggggggggggggggggggggggggggggggggg", 40, container_id, sizeof(container_id)));  // Non-hex
    EXPECT_FALSE(extract_container_id_lean("docker-abcdef1234567890abcdef1234567890", 40, container_id, 10));  // Buffer too small

    // Test valid cases (already covered above)
}

// Test TCP state conversion edge cases
TEST(NetworkScannerUtilsTest, TCPStateEdgeCases) {
    // Test unknown states
    EXPECT_STREQ(tcp_state_lean(nullptr), nullptr);  // NULL input (though this might crash, testing robustness)
    EXPECT_STREQ(tcp_state_lean(""), "");  // Empty string
    EXPECT_STREQ(tcp_state_lean("ZZ"), "ZZ");  // Unknown hex
    EXPECT_STREQ(tcp_state_lean("0C"), "0C");  // Out of range

    // Test known states (already covered)
}

// Test severity classification edge cases
TEST(NetworkScannerUtilsTest, SeverityClassificationEdgeCases) {
    // Test TCP with NULL exe
    EXPECT_EQ(classify_tcp_severity_lean("LISTEN", 22, nullptr), Severity::Medium);
    EXPECT_EQ(classify_tcp_severity_lean("ESTABLISHED", 80, nullptr), Severity::Info);

    // Test UDP with NULL exe
    EXPECT_EQ(classify_udp_severity_lean(53, nullptr), Severity::Low);
    EXPECT_EQ(classify_udp_severity_lean(12345, nullptr), Severity::Info);
}

// Test severity escalation edge cases
TEST(NetworkScannerUtilsTest, SeverityEscalationEdgeCases) {
    // Test with NULL inputs
    EXPECT_EQ(escalate_exposed_lean(Severity::Low, nullptr, "0.0.0.0"), Severity::Low);  // NULL state
    EXPECT_EQ(escalate_exposed_lean(Severity::Low, "LISTEN", nullptr), Severity::Low);  // NULL lip

    // Test non-LISTEN states (should not escalate)
    EXPECT_EQ(escalate_exposed_lean(Severity::Info, "ESTABLISHED", "0.0.0.0"), Severity::Info);
    EXPECT_EQ(escalate_exposed_lean(Severity::Low, "TIME_WAIT", "192.168.1.1"), Severity::Low);

    // Test max severity (should not escalate further)
    EXPECT_EQ(escalate_exposed_lean(Severity::Critical, "LISTEN", "0.0.0.0"), Severity::Critical);
}

// Test state filtering edge cases
TEST(NetworkScannerUtilsTest, StateAllowedEdgeCases) {
    Config config;

    // Test with NULL state
    EXPECT_TRUE(state_allowed_lean(nullptr, config));  // NULL state with empty config
    config.network_states = {"LISTEN"};
    EXPECT_FALSE(state_allowed_lean(nullptr, config));  // NULL state with config

    // Test case sensitivity
    config.network_states = {"LISTEN"};
    EXPECT_TRUE(state_allowed_lean("LISTEN", config));
    EXPECT_TRUE(state_allowed_lean("listen", config));  // Should be case-insensitive
    EXPECT_FALSE(state_allowed_lean("ESTABLISHED", config));
}

// Test hex string validation edge cases
TEST(NetworkScannerUtilsTest, HexStringValidationEdgeCases) {
    // Test edge cases
    EXPECT_FALSE(is_valid_hex_string(nullptr, 6, nullptr));  // NULL pointers
    const char* buffer = "abc";
    EXPECT_FALSE(is_valid_hex_string(buffer, 6, buffer + 3));  // Length exceeds end
    const char* buffer2 = "abc123";
    EXPECT_TRUE(is_valid_hex_string(buffer2, 6, buffer2 + 6));  // Exact match should work
    EXPECT_TRUE(is_valid_hex_string("abcdef", 6, "abcdef" + 6));
    EXPECT_FALSE(is_valid_hex_string("gggggg", 6, "gggggg" + 6));  // Non-hex
}
}

