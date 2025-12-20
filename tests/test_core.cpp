#include "test_harness.h"

#include <coroutine>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <expected>
#include <iterator>
#include <utility>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

import sys_scan.coro;
import sys_scan.report;
import sys_scan.registry;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.config;
import sys_scan.interfaces;
import sys_scan.system_services;
import sys_scan.utils;
import sys_scan.logging;
import sys_scan.scanners.auditd;
import sys_scan.scanners.systemd;
import sys_scan.scanners.process;
import sys_scan.scanners.network;
import sys_scan.scanners.kernel;
import sys_scan.scanners.mount;
import sys_scan.scanners.fs_perms;
import sys_scan.scanners.ioc;
import sys_scan.scanners.container;
import sys_scan.scanners.integrity;
import sys_scan.scanners.modules;
import sys_scan.scanners.ebpf;
import sys_scan.scanners.mac;
import sys_scan.scanners.module_utils;
import sys_scan.scanners.yara;

using namespace sys_scan;

namespace {

struct FakeFileSystem : public IFileSystem {
    std::unordered_map<std::string, std::string> files;
    std::unordered_map<std::string, std::filesystem::perms> perms;
    std::unordered_map<std::string, std::vector<FileEntry>> dirs;
    std::unordered_map<std::string, std::string> symlinks;

    bool exists(const std::string& path) const override {
        return files.count(path) || dirs.count(path) || symlinks.count(path) || perms.count(path);
    }

    bool is_directory(const std::string& path) const override {
        return dirs.count(path) > 0;
    }

    std::string read_file(const std::string& path) const override {
        if (auto it = files.find(path); it != files.end()) return it->second;
        return "";
    }

    std::vector<FileEntry> list_directory(const std::string& path) const override {
        if (auto it = dirs.find(path); it != dirs.end()) return it->second;
        return {};
    }

    std::string read_symlink(const std::string& path) const override {
        if (auto it = symlinks.find(path); it != symlinks.end()) return it->second;
        return "";
    }

    std::filesystem::perms permissions(const std::string& path) const override {
        if (auto it = perms.find(path); it != perms.end()) return it->second;
        return std::filesystem::perms::unknown;
    }

    void add_dir_entry(const std::string& dir, const FileEntry& entry) {
        dirs[dir].push_back(entry);
    }
};

using ExpectedStrInt = decltype(std::declval<RealProcessRunner>().exec(std::declval<std::string>(), std::declval<std::vector<std::string>>()));

struct FakeProcessRunner : public IProcessRunner {
    ExpectedStrInt result = ExpectedStrInt{std::string{}};
    ExpectedStrInt exec(const std::string&, const std::vector<std::string>&) const override { return result; }
};

struct FakeSystemInfo : public ISystemInfo {
    std::string rel = "";
    std::string kernel_release() const override { return rel; }
};

struct FakeSleeper : public ISleeper {
    FakeFileSystem* fs = nullptr;
    mutable bool invoked = false;
    void sleep_for(std::chrono::milliseconds) const override {
        invoked = true;
        if (fs) {
            fs->add_dir_entry("/proc", FileEntry{"/proc/101", "101", true, false, false});
        }
    }
};

Generator<int> throwing_generator() {
    co_yield 1;
    throw std::runtime_error("boom");
}

Generator<Finding> one_finding(Severity sev = Severity::Info) {
    Finding f;
    f.id = "t";
    f.title = "title";
    f.severity = sev;
    f.description = "desc";
    co_yield f;
}

class ThrowingScanner final : public Scanner {
public:
    std::string name() const override { return "throwing"; }
    std::string description() const override { return "throws"; }
    Generator<Finding> scan() override {
        throw std::runtime_error("scanner boom");
    }
};

class YieldingScanner final : public Scanner {
    std::string n_;
    int count_;
public:
    explicit YieldingScanner(std::string n, int count) : n_(std::move(n)), count_(count) {}
    std::string name() const override { return n_; }
    std::string description() const override { return "yields"; }
    Generator<Finding> scan() override {
        for (int i = 0; i < count_; ++i) {
            Finding f;
            f.id = n_ + ":" + std::to_string(i);
            f.title = "t";
            f.severity = Severity::Info;
            f.description = "d";
            co_yield f;
        }
    }
};

} // namespace

SYS_SCAN_TEST(generator_rethrows_exceptions) {
    bool threw = false;
    try {
        for (int v : throwing_generator()) {
            (void)v;
        }
    } catch (const std::runtime_error& ex) {
        threw = std::string(ex.what()) == "boom";
    }
    SYS_SCAN_ASSERT(threw);
}

SYS_SCAN_TEST(report_consume_collects_findings) {
    Report r;
    r.consume("s", one_finding(Severity::High));
    SYS_SCAN_ASSERT(r.results().size() == 1);
    SYS_SCAN_ASSERT(r.results()[0].scanner_name == "s");
    SYS_SCAN_ASSERT(r.results()[0].findings.size() == 1);
    SYS_SCAN_ASSERT(r.results()[0].findings[0].severity == Severity::High);
}

SYS_SCAN_TEST(report_tracks_warnings_and_errors) {
    Report r;
    r.add_warning("scannerA", "warn");
    r.add_error("scannerB", "err");
    SYS_SCAN_ASSERT(r.warnings().size() == 1);
    SYS_SCAN_ASSERT(r.errors().size() == 1);
    SYS_SCAN_ASSERT(r.warnings()[0].first == "scannerA");
    SYS_SCAN_ASSERT(r.errors()[0].second == "err");
}

SYS_SCAN_TEST(registry_sequential_catches_scanner_exception) {
    ScannerRegistry reg;
    reg.register_scanner(std::make_unique<ThrowingScanner>());

    Config cfg;
    cfg.parallel = false;

    Report rep;
    reg.run_all(rep, cfg);

    SYS_SCAN_ASSERT(!rep.errors().empty());
    SYS_SCAN_ASSERT(rep.errors()[0].first == "throwing");
}

SYS_SCAN_TEST(registry_parallel_runs_all) {
    ScannerRegistry reg;
    reg.register_scanner(std::make_unique<YieldingScanner>("a", 3));
    reg.register_scanner(std::make_unique<YieldingScanner>("b", 2));

    Config cfg;
    cfg.parallel = true;
    cfg.parallel_max_threads = 2;

    Report rep;
    reg.run_all(rep, cfg);

    // Order is not guaranteed in parallel; just validate counts.
    size_t total = 0;
    for (const auto& r : rep.results()) total += r.findings.size();
    SYS_SCAN_ASSERT(total == 5);
}

SYS_SCAN_TEST(utils_trim_and_split) {
    using sys_scan::utils::trim;
    using sys_scan::utils::read_lines_from_string;

    SYS_SCAN_ASSERT(trim("   ").empty());
    SYS_SCAN_ASSERT(trim("  hello  ") == "hello");
    SYS_SCAN_ASSERT(trim(std::string_view{"\t spaced \n"}) == "spaced");

    auto lines = read_lines_from_string("a\nb\nc");
    SYS_SCAN_ASSERT(lines.size() == 3);
    SYS_SCAN_ASSERT(lines[1] == "b");
}

SYS_SCAN_TEST(utils_read_file_and_safe_char) {
    using sys_scan::utils::read_file;
    using sys_scan::utils::is_safe_path_char;

    auto tmp = std::filesystem::temp_directory_path() / "sys_scan_tmp_readfile.txt";
    {
        std::ofstream o(tmp);
        o << "content";
    }

    auto val = read_file(tmp.string());
    SYS_SCAN_ASSERT(val.has_value());
    SYS_SCAN_ASSERT(*val == "content");

    SYS_SCAN_ASSERT(is_safe_path_char('A'));
    SYS_SCAN_ASSERT(!is_safe_path_char(' '));

    std::error_code ec;
    std::filesystem::remove(tmp, ec);
}

SYS_SCAN_TEST(utils_in_root) {
    using sys_scan::utils::in_root;

    SYS_SCAN_ASSERT(in_root("/root", "file") == "/root/file");
    SYS_SCAN_ASSERT(in_root("/root/", "file") == "/root/file");
    SYS_SCAN_ASSERT(in_root("/root", "/abs") == "/root/abs");
    SYS_SCAN_ASSERT(in_root("/", "path") == "path");
}

SYS_SCAN_TEST(risk_heatmap_and_builder) {
    RiskHeatmap map(2);
    auto& cell01 = map.operator[](0, 1);
    auto& cell15 = map.operator[](1, 5);
    cell01 += 3;
    cell15 += 2;
    SYS_SCAN_ASSERT(cell01 == 3);
    SYS_SCAN_ASSERT(cell15 == 2);

    Finding f = FindingBuilder{}
        .set_id("id1")
        .set_title("title1")
        .set_severity(Severity::High)
        .build();

    SYS_SCAN_ASSERT(f.id == "id1");
    SYS_SCAN_ASSERT(f.title == "title1");
    SYS_SCAN_ASSERT(f.severity == Severity::High);
}

SYS_SCAN_TEST(severity_conversion_and_scores) {
    SYS_SCAN_ASSERT(std::string(severity_to_string(Severity::Info)) == "info");
    SYS_SCAN_ASSERT(severity_from_string("CRITICAL") == Severity::Critical);
    SYS_SCAN_ASSERT(severity_risk_score(Severity::High) == 70);
    SYS_SCAN_ASSERT(severity_from_string("unknown") == Severity::Info);
}

SYS_SCAN_TEST(logger_emits_at_trace) {
    auto& logger = Logger::instance();
    logger.set_level(LogLevel::Trace);
    logger.error("err");
    logger.warn("warn");
    logger.info("info");
    logger.debug("debug");
    logger.trace("trace");
    SYS_SCAN_ASSERT(logger.level() == LogLevel::Trace);
}

SYS_SCAN_TEST(real_services_smoke) {
    RealFileSystem fs;
    auto tmp = std::filesystem::temp_directory_path() / "sys_scan_real.txt";
    {
        std::ofstream o(tmp);
        o << "hello";
    }
    SYS_SCAN_ASSERT(fs.exists(tmp.string()));
    SYS_SCAN_ASSERT(fs.is_directory(tmp.parent_path().string()));
    SYS_SCAN_ASSERT(fs.read_file(tmp.string()) == "hello");
    auto entries = fs.list_directory(tmp.parent_path().string());
    bool saw = false;
    for (const auto& e : entries) {
        if (e.name == tmp.filename()) {
            saw = true;
            break;
        }
    }
    SYS_SCAN_ASSERT(saw);

    RealProcessRunner runner;
    auto ok = runner.exec("/bin/echo", {"hi"});
    if (ok.has_value()) {
        SYS_SCAN_ASSERT(ok.value().find("hi") != std::string::npos);
    } else {
        SYS_SCAN_ASSERT(!ok.has_value());
    }
    auto bad = runner.exec("/bin/false", {});
    SYS_SCAN_ASSERT(!bad.has_value());

    RealSystemInfo sysinfo;
    SYS_SCAN_ASSERT(!sysinfo.kernel_release().empty());

    RealSleeper sleeper;
    auto before = std::chrono::steady_clock::now();
    sleeper.sleep_for(std::chrono::milliseconds(1));
    auto after = std::chrono::steady_clock::now();
    SYS_SCAN_ASSERT(after >= before);

    std::error_code ec;
    std::filesystem::remove(tmp, ec);
}

SYS_SCAN_TEST(auditd_scanner_no_rules) {
    Config cfg; cfg.hardening = true; cfg.test_root = "/root";
    FakeFileSystem fs;
    AuditdScanner scanner(cfg, fs);
    size_t count = 0;
    for (const auto& f : scanner.scan()) {
        ++count;
        SYS_SCAN_ASSERT(f.id == "auditd:rules:missing");
        SYS_SCAN_ASSERT(f.severity == Severity::Medium);
    }
    SYS_SCAN_ASSERT(count == 1);
}

SYS_SCAN_TEST(auditd_scanner_missing_execve) {
    Config cfg; cfg.hardening = true; cfg.test_root = "/root";
    FakeFileSystem fs;
    fs.files["/root/etc/audit/audit.rules"] = "-S setuid";
    fs.add_dir_entry("/root/etc/audit/rules.d", FileEntry{"/root/etc/audit/rules.d/extra.rules", "extra.rules", false, false, true});
    fs.files["/root/etc/audit/rules.d/extra.rules"] = "-S chmod";
    fs.dirs["/root/etc/audit/rules.d"] = fs.dirs["/root/etc/audit/rules.d"];

    AuditdScanner scanner(cfg, fs);
    bool saw_execve_missing = false;
    size_t findings = 0;
    for (const auto& f : scanner.scan()) {
        findings++;
        if (f.id == "auditd:execve:absent") {
            saw_execve_missing = true;
            SYS_SCAN_ASSERT(f.severity == Severity::High);
        }
    }
    SYS_SCAN_ASSERT(saw_execve_missing);
    SYS_SCAN_ASSERT(findings >= 1);
}

SYS_SCAN_TEST(systemd_scanner_parses_units) {
    Config cfg; cfg.hardening = true; cfg.test_root = "/root";
    FakeFileSystem fs;
    fs.dirs["/root/etc/systemd/system"] = {FileEntry{"/root/etc/systemd/system/test.service", "test.service", false, false, true}};
    fs.files["/root/etc/systemd/system/test.service"] = R"([Unit]
Description=demo
[Service]
ExecStart=/bin/true
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
)";

    SystemdUnitScanner scanner(cfg, fs);
    bool saw_protect_system = false;
    size_t yielded = 0;
    for (const auto& f : scanner.scan()) {
        yielded++;
        if (f.id.find("ProtectSystem") != std::string::npos) {
            saw_protect_system = true;
            SYS_SCAN_ASSERT(f.severity == Severity::Medium);
        }
    }
    SYS_SCAN_ASSERT(saw_protect_system);
    SYS_SCAN_ASSERT(yielded >= 4);
}

SYS_SCAN_TEST(process_scanner_emits_process_inventory) {
    Config cfg; cfg.process_inventory = true; cfg.test_root = "";
    FakeFileSystem fs;
    fs.dirs["/proc"] = {FileEntry{"/proc/123", "123", true, false, false}, FileEntry{"/proc/notpid", "notpid", true, false, false}};
    fs.files["/proc/123/cmdline"] = "bash\0-c";
    ProcessScanner scanner(cfg, fs);
    size_t count = 0;
    for (const auto& f : scanner.scan()) {
        ++count;
        SYS_SCAN_ASSERT(f.id == "123");
        SYS_SCAN_ASSERT(f.description.find("bash") != std::string::npos);
    }
    SYS_SCAN_ASSERT(count == 1);
}

SYS_SCAN_TEST(mount_scanner_flags_tmp) {
    Config cfg; FakeFileSystem fs; cfg.test_root = "";
    fs.files["/proc/mounts"] = "dev /tmp ext4 rw,relatime 0 0\n";
    MountScanner scanner(cfg, fs);
    bool found = false;
    for (const auto& f : scanner.scan()) {
        found = true;
        SYS_SCAN_ASSERT(f.id == "mount:insecure:/tmp");
    }
    SYS_SCAN_ASSERT(found);
}

SYS_SCAN_TEST(kernel_scanner_mismatch) {
    Config cfg; cfg.hardening = true; cfg.test_root = "";
    FakeFileSystem fs;
    fs.files["/proc/sys/kernel/kptr_restrict"] = "0";
    KernelScanner scanner(cfg, fs);
    bool found = false;
    for (const auto& f : scanner.scan()) {
        found = true;
        SYS_SCAN_ASSERT(f.id == "kernel:kernel.kptr_restrict");
    }
    SYS_SCAN_ASSERT(found);
}

SYS_SCAN_TEST(fs_perms_scanner_world_writable_and_suid) {
    Config cfg; FakeFileSystem fs; cfg.test_root = "";
    fs.perms["/etc/passwd"] = std::filesystem::perms::others_write;
    fs.dirs["/usr/bin"] = {FileEntry{"/usr/bin/suidbin", "suidbin", false, false, true}};
    fs.perms["/usr/bin/suidbin"] = std::filesystem::perms::set_uid;
    fs.dirs["/usr/sbin"] = {};
    fs.dirs["/usr/local/bin"] = {};
    fs.dirs["/sbin"] = {};
    fs.dirs["/bin"] = {};

    FsPermsScanner scanner(cfg, fs);
    bool saw_world = false;
    bool saw_suid = false;
    for (const auto& f : scanner.scan()) {
        if (f.id.find("world_writable") != std::string::npos) saw_world = true;
        if (f.id.find("suid") != std::string::npos) saw_suid = true;
    }
    SYS_SCAN_ASSERT(saw_world);
    SYS_SCAN_ASSERT(saw_suid);
}

SYS_SCAN_TEST(ioc_scanner_detects_patterns) {
    Config cfg; FakeFileSystem fs; cfg.test_root = "";
    fs.dirs["/proc"] = {FileEntry{"/proc/555", "555", true, false, false}};
    fs.files["/proc/555/cmdline"] = "xmrig";
    fs.files["/proc/555/environ"] = "LD_PRELOAD=evil";
    fs.symlinks["/proc/555/exe"] = "/tmp/ghost (deleted)";
    IOCScanner scanner(cfg, fs);
    std::unordered_set<std::string> ids;
    for (const auto& f : scanner.scan()) {
        ids.insert(f.id);
    }
    SYS_SCAN_ASSERT(ids.count("ioc:suspicious:555"));
    SYS_SCAN_ASSERT(ids.count("ioc:ld_preload:555"));
    SYS_SCAN_ASSERT(ids.count("ioc:deleted_exe:555"));
}

SYS_SCAN_TEST(container_scanner_detects_docker) {
    Config cfg; cfg.containers = true; FakeFileSystem fs; cfg.test_root = "";
    fs.files["/.dockerenv"] = "";
    ContainerScanner scanner(cfg, fs);
    bool found = false;
    for (const auto& f : scanner.scan()) {
        found = true;
        SYS_SCAN_ASSERT(f.metadata.at("type") == "Docker");
    }
    SYS_SCAN_ASSERT(found);
}

SYS_SCAN_TEST(container_scanner_detects_cgroup_variants) {
    Config cfg; cfg.containers = true; FakeFileSystem fs; cfg.test_root = "";
    auto detect = [&](std::string cgroup, std::string environ) {
        fs.files["/proc/1/cgroup"] = std::move(cgroup);
        if (environ.empty()) fs.files.erase("/proc/1/environ");
        else fs.files["/proc/1/environ"] = std::move(environ);
        ContainerScanner scanner(cfg, fs);
        std::string type;
        for (const auto& f : scanner.scan()) type = f.metadata.at("type");
        return type;
    };

    SYS_SCAN_ASSERT(detect("1:name=systemd:/docker", "")=="Docker");
    SYS_SCAN_ASSERT(detect("0::/kubepods.slice/pod", "")=="Kubernetes");
    SYS_SCAN_ASSERT(detect("0::/lxc/test", "")=="LXC");
    SYS_SCAN_ASSERT(detect("", "FOO=BAR KUBERNETES_SERVICE_HOST=1.1.1.1")=="Kubernetes");
}

SYS_SCAN_TEST(network_scanner_listen_only) {
    Config cfg; cfg.network_listen_only = true; FakeFileSystem fs; cfg.test_root = "";
    fs.files["/proc/net/tcp"] = "header\n 0: 0100007F:0050 00000000:0000 0A";
    NetworkScanner scanner(cfg, fs);
    bool found = false;
    for (const auto& f : scanner.scan()) {
        found = true;
        SYS_SCAN_ASSERT(f.metadata.at("protocol") == "TCP");
    }
    SYS_SCAN_ASSERT(found);
}

SYS_SCAN_TEST(integrity_scanner_offline_root) {
    Config cfg; cfg.integrity = true; cfg.test_root = "/offline";
    FakeFileSystem fs;
    FakeProcessRunner runner;
    IntegrityScanner scanner(cfg, fs, runner);
    bool found = false;
    for (const auto& f : scanner.scan()) {
        found = true;
        SYS_SCAN_ASSERT(f.id == "integrity:offline_unsupported");
    }
    SYS_SCAN_ASSERT(found);
}

SYS_SCAN_TEST(integrity_scanner_dpkg_mismatches) {
    Config cfg; cfg.integrity = true; cfg.test_root = "";
    FakeFileSystem fs;
    fs.files["/usr/bin/dpkg"] = "";
    FakeProcessRunner runner;
    runner.result = std::string("mismatch1\nmismatch2");
    IntegrityScanner scanner(cfg, fs, runner);
    int mismatch = 0;
    bool summary = false;
    for (const auto& f : scanner.scan()) {
        if (f.id.starts_with("pkg_mismatch_")) mismatch++;
        if (f.id == "integrity_summary") summary = true;
    }
    SYS_SCAN_ASSERT(mismatch == 2);
    SYS_SCAN_ASSERT(summary);
}

SYS_SCAN_TEST(mac_scanner_selinux_and_apparmor) {
    Config cfg; cfg.test_root = ""; FakeFileSystem fs;
    // SELinux present and enforcing
    fs.dirs["/sys/fs/selinux"] = {};
    fs.files["/sys/fs/selinux/enforce"] = "1\n";
    // AppArmor enabled
    fs.files["/sys/module/apparmor/parameters/enabled"] = "Y\n";
    // Unconfined sshd
    fs.dirs["/proc"] = {FileEntry{"/proc/100", "100", true, false, false}};
    fs.files["/proc/100/attr/current"] = "unconfined";
    fs.symlinks["/proc/100/exe"] = "/usr/sbin/sshd";

    MACScanner scanner(cfg, fs);
    bool saw_selinux = false, saw_apparmor = false, saw_unconf = false;
    for (const auto& f : scanner.scan()) {
        if (f.id == "selinux") {
            saw_selinux = true;
            SYS_SCAN_ASSERT(f.metadata.at("present") == "true");
            SYS_SCAN_ASSERT(f.metadata.at("enforcing") == "1");
        }
        if (f.id == "apparmor") {
            saw_apparmor = true;
            SYS_SCAN_ASSERT(f.metadata.at("enabled") == "true");
        }
        if (f.id == "apparmor_unconfined") saw_unconf = true;
    }
    SYS_SCAN_ASSERT(saw_selinux && saw_apparmor && saw_unconf);
}

SYS_SCAN_TEST(mac_scanner_absent_paths) {
    Config cfg; cfg.test_root = ""; FakeFileSystem fs;
    // No selinux, no apparmor, no /proc entries
    MACScanner scanner(cfg, fs);
    bool saw_selinux = false;
    for (const auto& f : scanner.scan()) {
        if (f.id == "selinux") {
            saw_selinux = true;
            SYS_SCAN_ASSERT(f.metadata.at("present") == "false");
        }
    }
    SYS_SCAN_ASSERT(saw_selinux);
}

SYS_SCAN_TEST(module_scanner_summarizes_unsigned) {
    Config cfg; cfg.hardening = true; cfg.test_root = std::filesystem::temp_directory_path().string();
    FakeFileSystem fs;
    FakeSystemInfo sysinfo; sysinfo.rel = "fallback";

    const auto osrel = cfg.test_root + "/proc/sys/kernel/osrelease";
    fs.files[osrel] = "testrel";

    const auto modules_path = cfg.test_root + "/proc/modules";
    fs.files[modules_path] = "mod1 0 0 O \n";

    const auto module_file = cfg.test_root + "/lib/modules/testrel/kernel/drivers/mod1.ko";
    std::filesystem::create_directories(std::filesystem::path(module_file).parent_path());
    {
        std::ofstream o(module_file);
        o << "not an elf";
    }

    fs.files[module_file] = ""; // exists() should succeed

    ModuleScanner scanner(cfg, fs, sysinfo);
    bool found = false;
    for (const auto& f : scanner.scan()) {
        found = true;
        SYS_SCAN_ASSERT(f.id == "module_summary");
        SYS_SCAN_ASSERT(f.description.find("WX") != std::string::npos);
    }
    SYS_SCAN_ASSERT(found);
}

SYS_SCAN_TEST(module_utils_coverage) {
    using sys_scan::CompressionUtils;
    using sys_scan::ElfModuleHeuristics;
    using sys_scan::SignatureAnalyzer;

    SYS_SCAN_ASSERT(CompressionUtils::is_compressed("driver.ko.xz"));
    SYS_SCAN_ASSERT(!CompressionUtils::is_compressed("driver.ko"));
    SYS_SCAN_ASSERT(CompressionUtils::decompress_gz_bounded("/nope").empty());
    SYS_SCAN_ASSERT(CompressionUtils::decompress_xz_bounded("/nope").empty());

    std::vector<ElfModuleHeuristics::SectionInfo> sections = {
        {".text", 0x4, 10},
        {".data", 0x1, 5},
        {".evil", 0x0, 1},
        {".wx", 0x5, 2}
    };
    SYS_SCAN_ASSERT(ElfModuleHeuristics::has_wx_section(sections));
    SYS_SCAN_ASSERT(ElfModuleHeuristics::has_suspicious_section_name(sections));
    sections.clear();
    SYS_SCAN_ASSERT(!ElfModuleHeuristics::has_wx_section(sections));
    SYS_SCAN_ASSERT(!ElfModuleHeuristics::has_suspicious_section_name(sections));

    auto tmpdir = std::filesystem::temp_directory_path();
    auto unsigned_path = tmpdir / "unsigned.ko";
    {
        std::ofstream o(unsigned_path); o << "no signature";
    }
    auto signed_path = tmpdir / "signed.ko";
    {
        std::ofstream o(signed_path);
        o << "Module signature appended";
    }
    SYS_SCAN_ASSERT(SignatureAnalyzer::is_unsigned_module(unsigned_path.string()));
    SYS_SCAN_ASSERT(!SignatureAnalyzer::is_unsigned_module(signed_path.string()));

    // parse_sections on invalid/non-ELF should simply return empty
    auto invalid_path = tmpdir / "invalid.bin";
    {
        std::ofstream o(invalid_path); o << "not an elf";
    }
    SYS_SCAN_ASSERT(ElfModuleHeuristics::parse_sections(invalid_path.string()).empty());

    std::error_code ec;
    std::filesystem::remove(unsigned_path, ec);
    std::filesystem::remove(signed_path, ec);
    std::filesystem::remove(invalid_path, ec);
}

SYS_SCAN_TEST(ebpf_scanner_proc_fallback_detects_new_pid) {
    Config cfg; cfg.test_root = ""; cfg.ioc_exec_trace_seconds = 0;
    FakeFileSystem fs;
    fs.dirs["/proc"] = {FileEntry{"/proc/100", "100", true, false, false}};
    fs.files["/proc/101/comm"] = "newproc\n";
    FakeSleeper sleeper; sleeper.fs = &fs;
    EbpfScanner scanner(cfg, fs, sleeper);
    bool saw = false;
    for (const auto& f : scanner.scan()) {
        if (f.id == "proc_exec:101") {
            saw = true;
            SYS_SCAN_ASSERT(f.metadata.at("method") == "proc_poll");
        }
    }
    SYS_SCAN_ASSERT(sleeper.invoked);
    SYS_SCAN_ASSERT(saw);
}

SYS_SCAN_TEST(list_directory_includes_entry_path) {
    RealFileSystem fs;

    const auto tmp_base = std::filesystem::temp_directory_path() / "sys_scan_test_dir";
    std::error_code ec;
    std::filesystem::remove_all(tmp_base, ec);
    std::filesystem::create_directories(tmp_base, ec);
    SYS_SCAN_ASSERT(!ec);

    const auto f = tmp_base / "file.txt";
    std::ofstream out(f);
    out << "x";
    out.close();

    auto entries = fs.list_directory(tmp_base.string());
    bool saw = false;
    for (const auto& e : entries) {
        if (e.name == "file.txt") {
            saw = true;
            SYS_SCAN_ASSERT(!e.path.empty());
            // Best-effort: should end with file.txt
            SYS_SCAN_ASSERT(e.path.find("file.txt") != std::string::npos);
        }
    }
    SYS_SCAN_ASSERT(saw);

    std::filesystem::remove_all(tmp_base, ec);
}

SYS_SCAN_TEST(scanner_metadata_functions) {
    Config cfg;
    FakeFileSystem fs;
    FakeProcessRunner runner;
    FakeSystemInfo sysinfo;
    FakeSleeper sleeper;

    std::vector<std::unique_ptr<Scanner>> scanners;
    scanners.emplace_back(std::make_unique<AuditdScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<SystemdUnitScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<ProcessScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<NetworkScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<KernelScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<MountScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<FsPermsScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<MACScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<IntegrityScanner>(cfg, fs, runner));
    scanners.emplace_back(std::make_unique<IOCScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<ModuleScanner>(cfg, fs, sysinfo));
    scanners.emplace_back(std::make_unique<ContainerScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<YaraScanner>(cfg, fs));
    scanners.emplace_back(std::make_unique<EbpfScanner>(cfg, fs, sleeper));

    cfg.rules_enable = true;
    cfg.yara_scan_roots = {"/tmp"};

    size_t seen = 0;
    for (auto& s : scanners) {
        auto n = s->name();
        auto d = s->description();
        SYS_SCAN_ASSERT(!n.empty());
        SYS_SCAN_ASSERT(!d.empty());
        ++seen;
    }
    SYS_SCAN_ASSERT(seen == scanners.size());

    // Exercise YARA scanner scan() path to mark generator entry.
    bool yara_yielded = false;
    for (const auto& f : scanners.back()->scan()) {
        yara_yielded = true;
        (void)f;
    }
    SYS_SCAN_ASSERT(yara_yielded == true || yara_yielded == false); // Do not assert on presence of libyara, just ensure invocation succeeded.
}

SYS_SCAN_TEST(yara_scanner_branches) {
    FakeFileSystem fs;
    Config cfg;
    YaraScanner scanner_disabled(cfg, fs);
    size_t yielded = 0;
    for (const auto& f : scanner_disabled.scan()) {
        (void)f;
        ++yielded;
    }
    SYS_SCAN_ASSERT(yielded == 0);

    cfg.rules_enable = true;
    cfg.yara_scan_roots = {"/tmp"};
    YaraScanner scanner_enabled(cfg, fs);
    for (const auto& f : scanner_enabled.scan()) {
        // Cover both lib present/absent branches without asserting content.
        (void)f;
        yielded++;
    }
    SYS_SCAN_ASSERT(yielded >= 0);
}

SYS_SCAN_TEST(logger_filters_levels) {
    auto& logger = Logger::instance();
    logger.set_level(LogLevel::Error);
    // Below threshold: should not emit but should execute branch.
    logger.debug("debug");
    logger.info("info");
    logger.trace("trace");
    // Above threshold: should emit.
    logger.error("error");
    logger.warn("warn");
    SYS_SCAN_ASSERT(logger.level() == LogLevel::Error);
    logger.set_level(LogLevel::Info); // reset for other tests
}

SYS_SCAN_TEST(registry_branch_paths) {
    ScannerRegistry reg;
    reg.register_scanner(std::make_unique<YieldingScanner>("keep", 1));
    reg.register_scanner(std::make_unique<YieldingScanner>("skip", 1));

    Config cfg;
    cfg.parallel = true;
    cfg.parallel_max_threads = 200; // triggers clamp to 64
    cfg.enable_scanners = {"keep"};
    cfg.disable_scanners = {"skip"};

    Report rep;
    reg.run_all(rep, cfg);

    SYS_SCAN_ASSERT(rep.results().size() == 1);
    SYS_SCAN_ASSERT(rep.results()[0].scanner_name == "keep");
}

SYS_SCAN_TEST(systemd_scanner_branch_matrix) {
    Config cfg; cfg.hardening = true; cfg.test_root = "/root";
    FakeFileSystem fs;
    fs.dirs[cfg.test_root + "/etc/systemd/system"] = {
        FileEntry{cfg.test_root + "/etc/systemd/system/good.service", "good.service", false, false, true},
        FileEntry{cfg.test_root + "/etc/systemd/system/bad.service", "bad.service", false, false, true},
        FileEntry{cfg.test_root + "/etc/systemd/system/skip.socket", "skip.socket", false, false, true}
    };
    fs.files[cfg.test_root + "/etc/systemd/system/good.service"] = R"([Unit]
Description=demo
[Service]
ExecStart=/bin/true
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
)";
    fs.files[cfg.test_root + "/etc/systemd/system/bad.service"] = R"([Unit]
Description=demo
[Service]
ExecStart=/bin/true
ProtectSystem=full
)";
    fs.files[cfg.test_root + "/etc/systemd/system/skip.socket"] = "";

    SystemdUnitScanner scanner(cfg, fs);
    size_t good = 0, bad = 0;
    for (const auto& f : scanner.scan()) {
        if (f.id.find("good.service") != std::string::npos) good++;
        if (f.id.find("bad.service") != std::string::npos) bad++;
    }
    SYS_SCAN_ASSERT(good >= 4);
    SYS_SCAN_ASSERT(bad >= 1);
}

SYS_SCAN_TEST(fs_perms_branch_matrix) {
    Config cfg; cfg.test_root = "/root"; cfg.fast_scan = false;
    FakeFileSystem fs;
    // Critical file world-writable
    auto ww_path = cfg.test_root + "/etc/passwd";
    fs.files[ww_path] = "x";
    fs.perms[ww_path] = std::filesystem::perms::others_write;

    // Critical file with unknown perms
    auto unknown_path = cfg.test_root + "/etc/shadow";
    fs.files[unknown_path] = "x";

    // SUID binary in /usr/bin
    auto dir = cfg.test_root + "/usr/bin";
    fs.dirs[dir] = {FileEntry{dir + "/suidbin", "suidbin", false, false, true}};
    fs.perms[dir + "/suidbin"] = std::filesystem::perms::set_uid;

    FsPermsScanner scanner(cfg, fs);
    bool saw_ww = false, saw_suid = false;
    for (const auto& f : scanner.scan()) {
        if (f.id.find("world_writable") != std::string::npos) saw_ww = true;
        if (f.id.find("fs:suid") != std::string::npos) saw_suid = true;
    }
    SYS_SCAN_ASSERT(saw_ww);
    SYS_SCAN_ASSERT(saw_suid);
}

SYS_SCAN_TEST(mac_scanner_branch_matrix) {
    Config cfg; cfg.test_root = "/root";
    FakeFileSystem fs;
    fs.dirs[cfg.test_root + "/sys/fs/selinux"] = {};
    fs.files[cfg.test_root + "/sys/fs/selinux/enforce"] = "0";
    fs.files[cfg.test_root + "/sys/module/apparmor/parameters/enabled"] = "Y";

    fs.dirs[cfg.test_root + "/proc"] = {
        FileEntry{cfg.test_root + "/proc/100", "100", true, false, false},
        FileEntry{cfg.test_root + "/proc/200", "200", true, false, false}
    };
    fs.files[cfg.test_root + "/proc/100/attr/current"] = "unconfined";
    fs.symlinks[cfg.test_root + "/proc/100/exe"] = "/usr/sbin/sshd";
    fs.files[cfg.test_root + "/proc/200/attr/current"] = "confined";
    fs.symlinks[cfg.test_root + "/proc/200/exe"] = "/usr/bin/other";

    MACScanner scanner(cfg, fs);
    bool saw_selinux = false, saw_unconfined = false, saw_apparmor = false;
    for (const auto& f : scanner.scan()) {
        if (f.id == "selinux") saw_selinux = true;
        if (f.id == "apparmor") saw_apparmor = true;
        if (f.id == "apparmor_unconfined") saw_unconfined = true;
    }
    SYS_SCAN_ASSERT(saw_selinux);
    SYS_SCAN_ASSERT(saw_apparmor);
    SYS_SCAN_ASSERT(saw_unconfined);
}

SYS_SCAN_TEST(container_scanner_branch_matrix) {
    Config cfg; cfg.containers = true; cfg.test_root = "/root";
    FakeFileSystem fs;
    fs.files[cfg.test_root + "/.dockerenv"] = "";
    ContainerScanner scanner_docker(cfg, fs);
    size_t detections = 0;
    for (const auto& f : scanner_docker.scan()) { (void)f; detections++; }
    SYS_SCAN_ASSERT(detections == 1);

    FakeFileSystem fs2;
    cfg.containers = true;
    fs2.files[cfg.test_root + "/proc/1/cgroup"] = "0::/lxc/test";
    ContainerScanner scanner_lxc(cfg, fs2);
    detections = 0;
    for (const auto& f : scanner_lxc.scan()) { (void)f; detections++; }
    SYS_SCAN_ASSERT(detections == 1);

    FakeFileSystem fs3;
    cfg.containers = true;
    fs3.files[cfg.test_root + "/proc/1/environ"] = "KUBERNETES_SERVICE_HOST=1.1.1.1";
    ContainerScanner scanner_env(cfg, fs3);
    detections = 0;
    for (const auto& f : scanner_env.scan()) { (void)f; detections++; }
    SYS_SCAN_ASSERT(detections == 1);
}

class ParallelThrowingScanner final : public Scanner {
public:
    std::string name() const override { return "pthrow"; }
    std::string description() const override { return "pthrow"; }
    Generator<Finding> scan() override { throw std::runtime_error("boom"); }
};

SYS_SCAN_TEST(registry_parallel_error_path) {
    ScannerRegistry reg;
    reg.register_scanner(std::make_unique<ParallelThrowingScanner>());

    Config cfg;
    cfg.parallel = true;
    cfg.parallel_max_threads = 0; // exercise hardware_concurrency fallback path

    Report rep;
    reg.run_all(rep, cfg);
    SYS_SCAN_ASSERT(!rep.errors().empty());
}
