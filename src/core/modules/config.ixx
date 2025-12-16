module;
#include <string>
#include <vector>
#include <optional>
export module sys_scan.config;

export namespace sys_scan {

struct Config {
    std::vector<std::string> enable_scanners;
    std::vector<std::string> disable_scanners;
    std::string output_file = "";
    std::string min_severity = "";
    std::string fail_on_severity = "";
    bool pretty = false;
    bool all_processes = false;
    std::vector<std::string> world_writable_dirs;
    std::vector<std::string> world_writable_exclude;
    int max_processes = 0;
    int max_sockets = 0;
    bool compact = false;
    bool network_debug = false;
    bool network_listen_only = false;
    std::string network_proto = "";
    std::vector<std::string> network_states;
    // IOC tuning
    std::vector<std::string> ioc_allow;
    bool modules_summary_only = false;
    // Extended tuning
    std::string ioc_allow_file = "";
    int fail_on_count = -1;
    bool process_hash = false;
    bool process_inventory = false;
    bool modules_anomalies_only = false;
    // SUID expected baseline management
    std::vector<std::string> suid_expected_add;
    std::string suid_expected_file = "";
    // Output formatting extensions
    bool canonical = false;
    bool ndjson = false;
    bool sarif = false;
    bool parallel = false;
    int parallel_max_threads = 0;
    bool hardening = false;
    bool containers = false;
    std::string container_id_filter = "";
    bool modules_hash = false;
    bool ioc_env_trust = false;
    bool ioc_exec_trace = false;
    int ioc_exec_trace_seconds = 0;
    bool network_advanced = false;
    int network_fanout_threshold = 100;
    int network_fanout_unique_threshold = 50;
    bool fs_hygiene = false;
    int fs_world_writable_limit = 0;
    bool integrity = false;
    bool integrity_ima = false;
    bool integrity_pkg_verify = false;
    int integrity_pkg_limit = 200;
    bool integrity_pkg_rehash = false;
    int integrity_pkg_rehash_limit = 50;
    bool integrity_critical_only = false;
    int integrity_sample_pct = 0;
    int integrity_max_mismatches = 0;
    // Rule engine
    bool rules_enable = false;
    std::string rules_dir = "";
    bool rules_allow_legacy = false;
    std::vector<std::string> yara_scan_roots;
    // PII suppression flags
    bool no_user_meta = false;
    bool no_cmdline_meta = false;
    bool no_hostname_meta = false;
    // Integrity & provenance
    bool sign_gpg = false;
    std::string sign_gpg_key = "";
    bool drop_priv = false;
    bool keep_cap_dac = false;
    bool seccomp = false;
    bool seccomp_strict = false;
    std::string write_env_file = "";
    // Compliance
    bool compliance = false;
    std::vector<std::string> compliance_standards;
    bool fast_scan = false;
    bool timings = false;
    std::string test_root = "";
    bool test_mode = false;
};

// Note: Singleton 'config()' removed. Use Dependency Injection.

}
