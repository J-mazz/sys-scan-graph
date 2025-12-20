module;
#include <string>
#include <vector>
// GCOVR_EXCL_START
export module sys_scan.config;

export namespace sys_scan {

struct Config {
    // Scanner selection
    std::vector<std::string> enable_scanners;
    std::vector<std::string> disable_scanners;

    // Output
    std::string output_file = "";  // empty => stdout
    bool canonical = false;

    // Scanner behaviour flags actually used in code paths
    bool hardening = true;
    bool process_inventory = true;
    bool all_processes = false;
    bool no_user_meta = false;
    bool network_listen_only = false;
    bool fast_scan = false;
    bool modules_summary_only = false;
    bool containers = false;
    bool integrity = false;
    bool ioc_exec_trace = false;
    int  ioc_exec_trace_seconds = 0;
    bool rules_enable = false;
    std::vector<std::string> yara_scan_roots;

    // Parallel execution controls
    bool parallel = false;
    std::size_t parallel_max_threads = 0; // 0 => use hardware_concurrency fallback

    // Test root for fixtures/offline snapshots
    std::string test_root = "";
};
}
// GCOVR_EXCL_STOP
