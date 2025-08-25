#pragma once
#include <string>
#include <vector>
#include <optional>

namespace sys_scan {

struct Config {
    std::vector<std::string> enable_scanners; // if non-empty, only these
    std::vector<std::string> disable_scanners;
    std::string output_file;
    std::string min_severity = ""; // none means all
    std::string fail_on_severity = ""; // exit non-zero if any finding >= this
    bool pretty = false;
    bool all_processes = false;
    std::vector<std::string> world_writable_dirs;
    std::vector<std::string> world_writable_exclude; // substring patterns
    int max_processes = 0; // 0 = unlimited after filtering
    int max_sockets = 0; // 0 = unlimited
    bool compact = false; // inverse of pretty; if both false default pretty output currently
    bool network_debug = false; // dump raw lines if parsing issues
    bool network_listen_only = false; // only include LISTEN TCP sockets (and UDP equivalents)
    std::string network_proto; // "tcp" | "udp" | empty=both
    std::vector<std::string> network_states; // filter TCP states if non-empty
    // IOC tuning
    std::vector<std::string> ioc_allow; // substrings or prefixes that downgrade env-only IOC severity
    bool modules_summary_only = false; // if true, emit single summary with counts and notable modules
    // Extended tuning
    std::string ioc_allow_file; // file with newline-delimited allowlist patterns (comments starting with #)
    int fail_on_count = 0; // if >0, exit non-zero if total findings >= this
    bool process_hash = false; // hash process executable (SHA256) if OpenSSL available
    bool process_inventory = false; // list every process as finding (otherwise only anomalies via IOC scanner)
    bool modules_anomalies_only = false; // only emit unsigned / out-of-tree module findings
    // SUID expected baseline management
    std::vector<std::string> suid_expected_add; // user-specified additional expected SUID paths
    std::string suid_expected_file; // file containing newline-delimited expected SUID paths
};

Config& config();
void set_config(const Config& c);

int severity_rank(const std::string& sev); // compatibility wrapper (enum implemented in Severity.h)

}
