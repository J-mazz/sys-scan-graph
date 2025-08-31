#include "ArgumentParser.h"
#include "BuildInfo.h"
#include <iostream>
#include <algorithm>
#include <cstdlib>

namespace sys_scan {

ArgumentParser::ArgumentParser() {
    specs_ = {
        {"--enable", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--disable", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--output", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--min-severity", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--fail-on", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--pretty", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--compact", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--canonical", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--ndjson", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--sarif", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--all-processes", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--modules-summary", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--modules-anomalies-only", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--modules-hash", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--integrity", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--integrity-ima", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--integrity-pkg-verify", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--integrity-pkg-limit", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--integrity-pkg-rehash", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--integrity-pkg-rehash-limit", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--fs-hygiene", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--fs-world-writable-limit", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--world-writable-dirs", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--world-writable-exclude", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--process-hash", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--process-inventory", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--max-processes", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--max-sockets", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--network-debug", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--network-listen-only", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--network-proto", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--network-states", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--network-advanced", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--network-fanout", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--network-fanout-unique", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--ioc-allow", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--ioc-allow-file", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--ioc-env-trust", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--ioc-exec-trace", FlagSpec::ArgKind::OptionalInt, [&](const std::string& v){ /* handled in parse */ }},
        {"--suid-expected", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--suid-expected-file", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--parallel", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--parallel-threads", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }},
        {"--hardening", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--containers", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--container-id", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--rules-enable", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--rules-dir", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--rules-allow-legacy", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--sign-gpg", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--slsa-level", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--compliance", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--compliance-standards", FlagSpec::ArgKind::CSV, [&](const std::string& v){ /* handled in parse */ }},
        {"--drop-priv", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--keep-cap-dac", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--seccomp", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--seccomp-strict", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--no-user-meta", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--no-cmdline-meta", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--no-hostname-meta", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--write-env", FlagSpec::ArgKind::String, [&](const std::string& v){ /* handled in parse */ }},
        {"--fast-scan", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--timings", FlagSpec::ArgKind::None, [&](const std::string&){ /* handled in parse */ }},
        {"--fail-on-count", FlagSpec::ArgKind::Int, [&](const std::string& v){ /* handled in parse */ }}
    };
}

bool ArgumentParser::parse(int argc, char** argv, Config& cfg) {
    for(int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if(arg == "--help") {
            print_help();
            return false; // Signal to exit
        }

        if(arg == "--version") {
            print_version();
            return false; // Signal to exit
        }

        auto* spec = find_spec(arg);
        if(!spec) {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_help();
            return false;
        }

        std::string value;
        switch(spec->kind) {
            case FlagSpec::ArgKind::None:
                break;
            case FlagSpec::ArgKind::String:
            case FlagSpec::ArgKind::Int:
            case FlagSpec::ArgKind::CSV: {
                if(i + 1 >= argc) {
                    std::cerr << "Missing value for " << arg << "\n";
                    return false;
                }
                value = argv[++i];
                break;
            }
            case FlagSpec::ArgKind::OptionalInt: {
                if(i + 1 < argc && argv[i + 1][0] != '-') {
                    value = argv[++i];
                }
                break;
            }
        }

        // Apply the flag to config
        if(arg == "--enable") {
            cfg.enable_scanners = split_csv(value);
        } else if(arg == "--disable") {
            cfg.disable_scanners = split_csv(value);
        } else if(arg == "--output") {
            cfg.output_file = value;
        } else if(arg == "--min-severity") {
            cfg.min_severity = value;
        } else if(arg == "--fail-on") {
            cfg.fail_on_severity = value;
        } else if(arg == "--pretty") {
            cfg.pretty = true;
        } else if(arg == "--compact") {
            cfg.compact = true;
        } else if(arg == "--canonical") {
            cfg.canonical = true;
        } else if(arg == "--ndjson") {
            cfg.ndjson = true;
        } else if(arg == "--sarif") {
            cfg.sarif = true;
        } else if(arg == "--all-processes") {
            cfg.all_processes = true;
        } else if(arg == "--modules-summary") {
            cfg.modules_summary_only = true;
        } else if(arg == "--modules-anomalies-only") {
            cfg.modules_anomalies_only = true;
        } else if(arg == "--modules-hash") {
            cfg.modules_hash = true;
        } else if(arg == "--integrity") {
            cfg.integrity = true;
        } else if(arg == "--integrity-ima") {
            cfg.integrity_ima = true;
        } else if(arg == "--integrity-pkg-verify") {
            cfg.integrity_pkg_verify = true;
        } else if(arg == "--integrity-pkg-limit") {
            try {
                cfg.integrity_pkg_limit = need_int(value, "--integrity-pkg-limit");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--integrity-pkg-rehash") {
            cfg.integrity_pkg_rehash = true;
        } else if(arg == "--integrity-pkg-rehash-limit") {
            try {
                cfg.integrity_pkg_rehash_limit = need_int(value, "--integrity-pkg-rehash-limit");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--fs-hygiene") {
            cfg.fs_hygiene = true;
        } else if(arg == "--fs-world-writable-limit") {
            try {
                cfg.fs_world_writable_limit = need_int(value, "--fs-world-writable-limit");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--world-writable-dirs") {
            cfg.world_writable_dirs = split_csv(value);
        } else if(arg == "--world-writable-exclude") {
            cfg.world_writable_exclude = split_csv(value);
        } else if(arg == "--process-hash") {
            cfg.process_hash = true;
        } else if(arg == "--process-inventory") {
            cfg.process_inventory = true;
        } else if(arg == "--max-processes") {
            try {
                cfg.max_processes = need_int(value, "--max-processes");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--max-sockets") {
            try {
                cfg.max_sockets = need_int(value, "--max-sockets");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--network-debug") {
            cfg.network_debug = true;
        } else if(arg == "--network-listen-only") {
            cfg.network_listen_only = true;
        } else if(arg == "--network-proto") {
            cfg.network_proto = value;
        } else if(arg == "--network-states") {
            cfg.network_states = split_csv(value);
        } else if(arg == "--network-advanced") {
            cfg.network_advanced = true;
        } else if(arg == "--network-fanout") {
            try {
                cfg.network_fanout_threshold = need_int(value, "--network-fanout");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--network-fanout-unique") {
            try {
                cfg.network_fanout_unique_threshold = need_int(value, "--network-fanout-unique");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--ioc-allow") {
            cfg.ioc_allow = split_csv(value);
        } else if(arg == "--ioc-allow-file") {
            cfg.ioc_allow_file = value;
        } else if(arg == "--ioc-env-trust") {
            cfg.ioc_env_trust = true;
        } else if(arg == "--ioc-exec-trace") {
            cfg.ioc_exec_trace = true;
            if(!value.empty()) {
                try {
                    cfg.ioc_exec_trace_seconds = need_int(value, "--ioc-exec-trace");
                } catch(const std::invalid_argument&) {
                    return false;
                }
            }
        } else if(arg == "--suid-expected") {
            cfg.suid_expected_add = split_csv(value);
        } else if(arg == "--suid-expected-file") {
            cfg.suid_expected_file = value;
        } else if(arg == "--parallel") {
            cfg.parallel = true;
        } else if(arg == "--parallel-threads") {
            try {
                cfg.parallel_max_threads = need_int(value, "--parallel-threads");
            } catch(const std::invalid_argument&) {
                return false;
            }
        } else if(arg == "--hardening") {
            cfg.hardening = true;
        } else if(arg == "--containers") {
            cfg.containers = true;
        } else if(arg == "--container-id") {
            cfg.container_id_filter = value;
        } else if(arg == "--rules-enable") {
            cfg.rules_enable = true;
        } else if(arg == "--rules-dir") {
            cfg.rules_dir = value;
        } else if(arg == "--rules-allow-legacy") {
            cfg.rules_allow_legacy = true;
        } else if(arg == "--sign-gpg") {
            cfg.sign_gpg = true;
            cfg.sign_gpg_key = value;
        } else if(arg == "--slsa-level") {
            setenv("SYS_SCAN_SLSA_LEVEL_RUNTIME", value.c_str(), 1);
        } else if(arg == "--compliance") {
            cfg.compliance = true;
        } else if(arg == "--compliance-standards") {
            cfg.compliance_standards = split_csv(value);
        } else if(arg == "--drop-priv") {
            cfg.drop_priv = true;
        } else if(arg == "--keep-cap-dac") {
            cfg.keep_cap_dac = true;
        } else if(arg == "--seccomp") {
            cfg.seccomp = true;
        } else if(arg == "--seccomp-strict") {
            cfg.seccomp_strict = true;
        } else if(arg == "--no-user-meta") {
            cfg.no_user_meta = true;
        } else if(arg == "--no-cmdline-meta") {
            cfg.no_cmdline_meta = true;
        } else if(arg == "--no-hostname-meta") {
            cfg.no_hostname_meta = true;
        } else if(arg == "--write-env") {
            cfg.write_env_file = value;
        } else if(arg == "--fast-scan") {
            cfg.fast_scan = true;
        } else if(arg == "--timings") {
            cfg.timings = true;
        } else if(arg == "--fail-on-count") {
            try {
                cfg.fail_on_count = need_int(value, "--fail-on-count");
            } catch(const std::invalid_argument&) {
                return false;
            }
        }
    }

    return true;
}

void ArgumentParser::print_help() const {
    std::cout << "sys-scan options:\n";
    struct Line { std::string name; std::string help; };
    static const std::vector<Line> lines = {
        {"--enable name[,name...]", "Only run specified scanners"},
        {"--disable name[,name...]", "Disable specified scanners"},
        {"--output FILE", "Write JSON to FILE (default stdout)"},
        {"--min-severity SEV", "Filter out findings below SEV"},
        {"--fail-on SEV", "Exit non-zero if finding >= SEV"},
        {"--fail-on-count N", "Exit non-zero if finding count >= N"},
        {"--pretty", "Pretty-print JSON"},
        {"--compact", "Minified JSON output"},
        {"--canonical", "RFC8785-like canonical ordering"},
        {"--ndjson", "Emit NDJSON (meta, summary, findings)"},
        {"--sarif", "Emit SARIF 2.1.0 JSON"},
        {"--all-processes", "Include kernel/thread processes with no cmdline"},
        {"--modules-summary", "Collapse modules into summary"},
        {"--modules-anomalies-only", "Only unsigned/out-of-tree/missing/hidden modules"},
        {"--modules-hash", "Include SHA256 for module files"},
        {"--integrity", "Enable integrity scanners"},
        {"--integrity-ima", "Include IMA measurement stats"},
        {"--integrity-pkg-verify", "Run package manager verify (dpkg/rpm)"},
        {"--integrity-pkg-limit N", "Limit detailed package mismatch findings"},
        {"--integrity-pkg-rehash", "Recompute SHA256 for mismatched package files"},
        {"--integrity-pkg-rehash-limit N", "Cap package files rehashed"},
        {"--fs-hygiene", "Filesystem hygiene checks"},
        {"--fs-world-writable-limit N", "Cap world-writable file findings"},
        {"--world-writable-dirs dirs", "Extra directories for world-writable scan"},
        {"--world-writable-exclude pats", "Substrings to ignore in world-writable paths"},
        {"--process-hash", "Hash process executables"},
        {"--process-inventory", "Emit every process as a finding"},
        {"--max-processes N", "Limit process findings after filtering"},
        {"--max-sockets N", "Limit network socket findings"},
        {"--network-debug", "Emit raw network lines"},
        {"--network-listen-only", "Only include LISTEN sockets"},
        {"--network-proto tcp|udp", "Filter to protocol"},
        {"--network-states list", "Comma-separated TCP states"},
        {"--network-advanced", "Advanced network analytics"},
        {"--network-fanout N", "Total connections fanout threshold"},
        {"--network-fanout-unique N", "Unique remote IP fanout threshold"},
        {"--ioc-allow list", "IOC allow substrings (comma-separated)"},
        {"--ioc-allow-file FILE", "File with IOC allow patterns"},
        {"--ioc-env-trust", "Correlate env vars with executable trust"},
        {"--ioc-exec-trace [S]", "Short-lived exec trace (optional seconds)"},
        {"--suid-expected list", "Extra expected SUID paths"},
        {"--suid-expected-file FILE", "File listing expected SUID paths"},
        {"--parallel", "Run scanners in parallel"},
        {"--parallel-threads N", "Max parallel threads"},
        {"--hardening", "Extended hardening scanners"},
        {"--containers", "Container / namespace detection"},
        {"--container-id ID", "Limit process/network to container id"},
        {"--rules-enable", "Enable rule engine enrichment"},
        {"--rules-dir DIR", "Directory with .rule files"},
        {"--rules-allow-legacy", "Allow unsupported rule versions"},
        {"--sign-gpg KEYID", "Detached signature (requires --output)"},
        {"--slsa-level N", "SLSA provenance level"},
        {"--compliance", "Enable compliance scanners"},
        {"--compliance-standards list", "Subset of compliance standards"},
        {"--drop-priv", "Drop Linux capabilities early"},
        {"--keep-cap-dac", "Retain CAP_DAC_READ_SEARCH when dropping"},
        {"--seccomp", "Apply seccomp profile"},
        {"--seccomp-strict", "Fail if seccomp apply fails"},
        {"--no-user-meta", "Suppress user identity in meta"},
        {"--no-cmdline-meta", "Suppress cmdline in meta"},
        {"--no-hostname-meta", "Suppress hostname in meta"},
        {"--write-env FILE", ".env provenance output"},
        {"--fast-scan", "Fast scan mode (disable heavy scanners)"},
        {"--timings", "Include scanner timing information"},
        {"--version", "Print version & exit"},
        {"--help", "Show this help"}
    };
    for(const auto& l : lines) {
        std::cout << "  " << l.name;
        if(l.name.size() < 30) {
            for(size_t i = l.name.size(); i < 30; ++i) std::cout << ' ';
        } else {
            std::cout << ' ';
        }
        std::cout << l.help << "\n";
    }
}

void ArgumentParser::print_version() const {
    std::cout << "sys-scan " << sys_scan::buildinfo::APP_VERSION
              << " (git=" << sys_scan::buildinfo::GIT_COMMIT
              << ", compiler=" << sys_scan::buildinfo::COMPILER_ID << " " << sys_scan::buildinfo::COMPILER_VERSION
              << ", cxx_std=" << sys_scan::buildinfo::CXX_STANDARD << ")\n";
}

std::vector<std::string> ArgumentParser::split_csv(const std::string& s) const {
    std::vector<std::string> out;
    std::string cur;
    for(char c : s) {
        if(c == ',') {
            if(!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if(!cur.empty()) out.push_back(cur);
    return out;
}

int ArgumentParser::need_int(const std::string& v, const char* flag) const {
    try {
        return std::stoi(v);
    } catch(...) {
        std::cerr << "Invalid integer for " << flag << "\n";
        throw std::invalid_argument("Invalid integer value");
    }
}

ArgumentParser::FlagSpec* ArgumentParser::find_spec(const std::string& flag) {
    for(auto& s : specs_) {
        if(flag == s.name) return &s;
    }
    return nullptr;
}

} // namespace sys_scan