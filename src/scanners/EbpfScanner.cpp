// Implementation file for EbpfScanner: provide method definitions only to avoid ODR violations.
#include "EbpfScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#ifdef SYS_SCAN_HAVE_EBPF
#include "process_exec.skel.h"
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#endif
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <set>
#include <optional>

namespace sys_scan
{
    std::string EbpfScanner::name() const { return "ebpf_exec_trace"; }
    std::string EbpfScanner::description() const { return "Short-lived execve trace via eBPF"; }

#ifdef SYS_SCAN_HAVE_EBPF
    namespace
    {
        // RAII wrapper definitions
        struct SkelDeleter
        {
            void operator()(process_exec_bpf* p) const noexcept
            {
                if (p) process_exec_bpf__destroy(p);
            }
        };

        using SkelPtr = std::unique_ptr<process_exec_bpf, SkelDeleter>;

        struct RingDeleter
        {
            void operator()(ring_buffer* rb) const noexcept
            {
                if (rb) ring_buffer__free(rb);
            }
        };

        using RingPtr = std::unique_ptr<ring_buffer, RingDeleter>;

        // Event structures
        struct ExecEvent
        {
            unsigned int type;
            unsigned int pid;
            char comm[16];
        };

        struct ConnEvent
        {
            unsigned int type;
            unsigned int pid;
            unsigned int daddr;
            unsigned short dport;
            char comm[16];
            unsigned char is_ipv6;
            unsigned int daddr6[4];
        };

        struct Aggregated
        {
            std::vector<ExecEvent> execs;
            std::vector<ConnEvent> conns;

            // Pre-allocate with optimal initial capacity
            Aggregated() {
                execs.reserve(1024);  // Increased from 512 for better performance
                conns.reserve(1024);
            }
        };

        // Event handler callback
        int handle_event(void* ctx, void* data, size_t len)
        {
            auto agg = static_cast<Aggregated*>(ctx);
            if (len == sizeof(ExecEvent))
            {
                auto* ee = static_cast<ExecEvent*>(data);
                if (ee->type == 1)
                {
                    agg->execs.push_back(*ee);
                    return 0;
                }
            }
            if (len == sizeof(ConnEvent))
            {
                auto* ce = static_cast<ConnEvent*>(data);
                if (ce->type == 2)
                {
                    agg->conns.push_back(*ce);
                    return 0;
                }
            }
            return 0;
        }

        void log_bpf_error(const std::string& stage, int err_code)
        {
            std::string sys_err;
            if (err_code < 0)
            {
                sys_err = std::string(strerror(-err_code));
            }
            else if (err_code > 0)
            {
                sys_err = std::string(strerror(err_code));
            }
            Logger::instance().error("eBPF " + stage + " failed: code=" +
                std::to_string(err_code) + (sys_err.empty() ? "" : " (" + sys_err + ")"));
        }

        Finding create_exec_finding(const ExecEvent& e)
        {
            Finding f;
            f.id = "exec.trace";
            f.severity = Severity::Info;

            // Pre-calculate string sizes to avoid reallocations
            constexpr size_t base_title_size = 6 + 16 + 5 + 10; // "exec: " + comm + " pid=" + pid_str
            std::string pid_str = std::to_string(e.pid);
            size_t total_size = base_title_size + pid_str.length();

            f.title.reserve(total_size);
            f.title = "exec: ";
            f.title += e.comm;
            f.title += " pid=";
            f.title += pid_str;

            f.description = "Observed exec event";

            // Use more efficient metadata insertion
            f.metadata.reserve(5);
            f.metadata.emplace("pid", std::move(pid_str));
            f.metadata.emplace("comm", std::string(e.comm, strnlen(e.comm, sizeof(e.comm))));
            f.metadata.emplace("source", "ebpf");
            f.metadata.emplace("collector", "exec");

            return f;
        }

        Finding create_conn_finding(const ConnEvent& c)
        {
            Finding f;
            f.id = "net.connect";
            f.severity = Severity::Info;

            // Optimize IP conversion - reuse buffer to avoid repeated allocations
            thread_local char ipbuf[INET6_ADDRSTRLEN];
            const char* ip_str;
            if (c.is_ipv6) {
                inet_ntop(AF_INET6, c.daddr6, ipbuf, sizeof(ipbuf));
                ip_str = ipbuf;
            } else {
                inet_ntop(AF_INET, &c.daddr, ipbuf, sizeof(ipbuf));
                ip_str = ipbuf;
            }

            unsigned short port_n = ntohs(c.dport);
            std::string port_str = std::to_string(port_n);
            std::string pid_str = std::to_string(c.pid);

            // Pre-calculate title size for efficient allocation
            constexpr size_t base_size = 9 + 16 + 5 + INET6_ADDRSTRLEN + 1 + 5; // "connect: " + comm + " pid=" + ip + ":" + port
            size_t total_size = base_size + pid_str.length() + port_str.length() + strlen(ip_str);

            f.title.reserve(total_size);
            f.title = "connect: ";
            f.title += c.comm;
            f.title += " pid=";
            f.title += pid_str;
            f.title += " dst=";
            f.title += ip_str;
            f.title += ":";
            f.title += port_str;

            f.description = "Observed outbound connection attempt";

            // Use more efficient metadata insertion with move semantics
            f.metadata.reserve(6);
            f.metadata.emplace("pid", std::move(pid_str));
            f.metadata.emplace("comm", std::string(c.comm, strnlen(c.comm, sizeof(c.comm))));
            f.metadata.emplace("dst_ip", ip_str);
            f.metadata.emplace("dst_port", std::move(port_str));
            f.metadata.emplace("source", "ebpf");
            f.metadata.emplace("collector", "tcp_v4_connect");

            return f;
        }
    }
#endif

    // Alternative detection method when eBPF is not available
    void EbpfScanner::scan_proc_filesystem(ScanContext& context, int duration)
    {
        // Monitor /proc for process execution events using polling
        Logger::instance().info("Monitoring /proc filesystem for process events");

        auto start_time = std::chrono::steady_clock::now();
        std::set<pid_t> known_pids;

        // Get initial snapshot of running processes
        if (auto initial_pids = get_running_pids(); initial_pids) {
            known_pids = std::move(*initial_pids);
        }

        // Poll for new processes during the monitoring duration
        while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(duration)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            auto current_pids = get_running_pids();
            if (!current_pids) continue;

            // Find new processes
            for (pid_t pid : *current_pids) {
                if (known_pids.find(pid) == known_pids.end()) {
                    // New process detected
                    if (auto proc_info = get_process_info(pid)) {
                        Finding f;
                        f.id = "proc.exec.detected";
                        f.severity = Severity::Info;
                        f.title = "Process execution detected: " + proc_info->comm +
                                " (PID: " + std::to_string(pid) + ")";
                        f.description = "New process execution detected via /proc monitoring";
                        f.metadata["pid"] = std::to_string(pid);
                        f.metadata["comm"] = proc_info->comm;
                        f.metadata["ppid"] = std::to_string(proc_info->ppid);
                        f.metadata["source"] = "proc_fallback";
                        f.metadata["detection_method"] = "proc_polling";
                        context.report.add_finding(name(), std::move(f));

                        known_pids.insert(pid);
                    }
                }
            }

            // Clean up finished processes from known_pids
            for (auto it = known_pids.begin(); it != known_pids.end(); ) {
                if (current_pids->find(*it) == current_pids->end()) {
                    it = known_pids.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Create summary finding
        Finding summary;
        summary.id = "proc.monitoring.complete";
        summary.severity = Severity::Info;
        summary.title = "Process monitoring completed via /proc filesystem";
        summary.description = "Alternative process monitoring completed using /proc polling method";
        summary.metadata["duration_seconds"] = std::to_string(duration);
        summary.metadata["source"] = "proc_fallback";
        summary.metadata["method"] = "filesystem_polling";
        context.report.add_finding(name(), std::move(summary));
    }

    std::optional<std::set<pid_t>> EbpfScanner::get_running_pids()
    {
        std::set<pid_t> pids;
        try {
            for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
                if (entry.is_directory()) {
                    std::string filename = entry.path().filename().string();
                    // Check if it's a PID directory (numeric)
                    bool is_pid = true;
                    for (char c : filename) {
                        if (!std::isdigit(c)) {
                            is_pid = false;
                            break;
                        }
                    }
                    if (is_pid) {
                        try {
                            pid_t pid = std::stoi(filename);
                            pids.insert(pid);
                        } catch (const std::exception&) {
                            // Skip invalid PID directories
                        }
                    }
                }
            }
        } catch (const std::filesystem::filesystem_error&) {
            Logger::instance().error("Failed to read /proc directory");
            return std::nullopt;
        }
        return pids;
    }

    std::optional<EbpfScanner::ProcessInfo> EbpfScanner::get_process_info(pid_t pid)
    {
        ProcessInfo info{};
        info.pid = pid;

        try {
            // Read /proc/<pid>/stat for process information
            std::ifstream stat_file("/proc/" + std::to_string(pid) + "/stat");
            if (!stat_file.is_open()) {
                return std::nullopt;
            }

            std::string line;
            if (std::getline(stat_file, line)) {
                std::istringstream iss(line);
                std::string token;
                int field = 0;

                while (iss >> token && field < 4) {
                    switch (field) {
                        case 0: info.pid = std::stoi(token); break;
                        case 1: // Process name in parentheses
                            if (token.size() > 2) {
                                info.comm = token.substr(1, token.size() - 2); // Remove parentheses
                            }
                            break;
                        case 3: info.ppid = std::stoi(token); break;
                    }
                    field++;
                }
            }

            // Read command line if available
            std::ifstream cmdline_file("/proc/" + std::to_string(pid) + "/cmdline");
            if (cmdline_file.is_open()) {
                std::string cmdline;
                if (std::getline(cmdline_file, cmdline, '\0')) {
                    info.cmdline = cmdline;
                }
            }

        } catch (const std::exception&) {
            return std::nullopt;
        }

        return info;
    }

    // Runtime eBPF feature detection
    bool EbpfScanner::is_ebpf_available() const
    {
#ifndef SYS_SCAN_HAVE_EBPF
        // eBPF not compiled in at all
        return false;
#else
        // Check if bpftool is available
        if (system("which bpftool > /dev/null 2>&1") != 0) {
            Logger::instance().debug("bpftool not found in PATH");
            return false;
        }

        // Check kernel version for eBPF support (minimum 4.4)
        std::ifstream version_file("/proc/version");
        if (version_file.is_open()) {
            std::string version_line;
            if (std::getline(version_file, version_line)) {
                // Look for kernel version pattern like "Linux version 5.4.0"
                size_t pos = version_line.find("Linux version ");
                if (pos != std::string::npos) {
                    std::string version_str = version_line.substr(pos + 14);
                    // Extract major.minor version
                    size_t dot_pos = version_str.find('.');
                    if (dot_pos != std::string::npos) {
                        size_t second_dot = version_str.find('.', dot_pos + 1);
                        std::string major_minor = version_str.substr(0, second_dot);
                        try {
                            float kernel_version = std::stof(major_minor);
                            if (kernel_version < 4.4f) {
                                Logger::instance().debug("Kernel version " + major_minor + " too old for eBPF");
                                return false;
                            }
                        } catch (const std::exception&) {
                            Logger::instance().debug("Could not parse kernel version: " + major_minor);
                        }
                    }
                }
            }
        }

        // Check for BTF support
        if (!std::filesystem::exists("/sys/kernel/btf/vmlinux")) {
            Logger::instance().debug("Kernel BTF not available - CO-RE may not work");
            // Don't return false here as some eBPF programs work without BTF
        }

        // Try to load a simple eBPF program to test functionality
        SkelPtr test_skel{process_exec_bpf__open()};
        if (!test_skel) {
            Logger::instance().debug("Failed to open eBPF skeleton - eBPF may not be available");
            return false;
        }

        // Try to load the program
        if (process_exec_bpf__load(test_skel.get()) != 0) {
            Logger::instance().debug("Failed to load eBPF program - eBPF may not be available");
            return false;
        }

        Logger::instance().debug("eBPF runtime check passed");
        return true;
#endif
    }
    void EbpfScanner::scan(ScanContext& context)
    {
        const auto& cfg = context.config;
        int duration = cfg.ioc_exec_trace_seconds > 0 ? cfg.ioc_exec_trace_seconds : 3;

        // Check if eBPF is available at runtime
        bool ebpf_available = is_ebpf_available();

        if (!ebpf_available) {
            // eBPF not available - perform alternative detection methods
            Logger::instance().info("eBPF not available at runtime, performing alternative exec tracing");

            // Create finding about eBPF unavailability
            Finding f_ebpf;
            f_ebpf.id = "ebpf:disabled";
            f_ebpf.title = "eBPF support not available at runtime";
            f_ebpf.severity = Severity::Info;
            f_ebpf.description = "eBPF tools not installed, incompatible kernel, or missing capabilities. Using alternative detection methods.";
            f_ebpf.metadata["alternative_detection"] = "true";
            f_ebpf.metadata["source"] = "ebpf_fallback";
            f_ebpf.metadata["detection_method"] = "runtime_check";
            context.report.add_finding(name(), std::move(f_ebpf));

            // Perform alternative exec detection using /proc filesystem
            scan_proc_filesystem(context, duration);
            return;
        }

#ifdef SYS_SCAN_HAVE_EBPF
        // Original eBPF implementation
        Logger::instance().info("ebpf trace: capturing exec events for " + std::to_string(duration) + "s");

        // Setup eBPF infrastructure
        SkelPtr skel{process_exec_bpf__open()};
        if (!skel)
        {
            Logger::instance().error("eBPF skeleton open returned null");
            Finding fe;
            fe.id = "ebpf:error:open";
            fe.title = "eBPF skeleton open failed";
            fe.severity = Severity::High;
            fe.description = "Failed to open eBPF skeleton";
            context.report.add_finding(name(), std::move(fe));
            return;
        }

        if (int rc = process_exec_bpf__load(skel.get()))
        {
            log_bpf_error("load", rc);
            Finding fe;
            fe.id = "ebpf:error:load";
            fe.title = "eBPF program load failed";
            fe.severity = Severity::High;
            fe.description = "Failed to load eBPF program";
            context.report.add_finding(name(), std::move(fe));
            return;
        }

        if (int rc = process_exec_bpf__attach(skel.get()))
        {
            log_bpf_error("attach", rc);
            Finding fe;
            fe.id = "ebpf:error:attach";
            fe.title = "eBPF attach failed";
            fe.severity = Severity::High;
            fe.description = "Failed to attach eBPF program";
            context.report.add_finding(name(), std::move(fe));
            return;
        }

        int ring_fd = bpf_map__fd(skel->maps.events);
        if (ring_fd < 0)
        {
            log_bpf_error("bpf_map__fd", ring_fd);
            Finding fe;
            fe.id = "ebpf:error:ringfd";
            fe.title = "eBPF ring buffer fd failed";
            fe.severity = Severity::High;
            fe.description = "Failed to acquire ring buffer file descriptor";
            context.report.add_finding(name(), std::move(fe));
            return;
        }

        // Setup event collection with pre-allocated capacity
        Aggregated agg;

        RingPtr rb{ring_buffer__new(ring_fd, handle_event, &agg, nullptr)};
        if (!rb)
        {
            Logger::instance().error("ring_buffer__new failed");
            Finding fe;
            fe.id = "ebpf:error:ringbuf";
            fe.title = "eBPF ring buffer create failed";
            fe.severity = Severity::High;
            fe.description = "Failed to create eBPF ring buffer";
            context.report.add_finding(name(), std::move(fe));
            return;
        }

        // Collect events
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(duration))
        {
            int pret = ring_buffer__poll(rb.get(), 200);
            if (pret < 0)
            {
                log_bpf_error("ring_buffer__poll", pret);
            }
        }

        // Process collected events efficiently
        // Reserve space in report for expected findings to avoid reallocations
        size_t expected_findings = agg.execs.size() + agg.conns.size();
        context.report.reserve_additional_findings(name(), expected_findings);

        // Process exec events
        for (const auto& e : agg.execs)
        {
            context.report.add_finding(name(), create_exec_finding(e));
        }

        // Process connection events
        for (const auto& c : agg.conns)
        {
            context.report.add_finding(name(), create_conn_finding(c));
        }
#endif
    }

    std::unique_ptr<Scanner> make_ebpf_scanner()
    {
        return std::make_unique<EbpfScanner>();
    }
} // namespace sys_scan
