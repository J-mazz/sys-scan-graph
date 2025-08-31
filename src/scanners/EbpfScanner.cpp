// Implementation file for EbpfScanner: provide method definitions only to avoid ODR violations.
#include "EbpfScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#ifdef SYS_SCAN_HAVE_EBPF
#include "process_exec.skel.h"
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>

namespace sys_scan {

std::string EbpfScanner::name() const { return "ebpf_exec_trace"; }
std::string EbpfScanner::description() const { return "Short-lived execve trace via eBPF"; }

void EbpfScanner::scan(Report& report) {
#ifndef SYS_SCAN_HAVE_EBPF
    report.add_warning(name(), "eBPF not built; scanner inactive", ErrorCode::Unknown);
    return;
#else
    auto& cfg = config();
    int duration = cfg.ioc_exec_trace_seconds > 0 ? cfg.ioc_exec_trace_seconds : 3;
    Logger::instance().info("ebpf trace: capturing exec events for " + std::to_string(duration) + "s");
    // RAII wrappers for skeleton & ring buffer
    struct SkelDeleter { void operator()(process_exec_bpf* p) const noexcept { if(p) process_exec_bpf__destroy(p); } }; 
    using SkelPtr = std::unique_ptr<process_exec_bpf, SkelDeleter>;
    struct RingDeleter { void operator()(ring_buffer* rb) const noexcept { if(rb) ring_buffer__free(rb); } };
    using RingPtr = std::unique_ptr<ring_buffer, RingDeleter>;

    auto log_bpf_err = [&](const std::string& stage, int err_code){
        // libbpf APIs sometimes encode negative errors; try libbpf_get_error if pointer returns are used elsewhere
        std::string sys_err;
        if(err_code < 0) {
            sys_err = std::string(strerror(-err_code));
        } else if(err_code > 0) {
            sys_err = std::string(strerror(err_code));
        }
        Logger::instance().error("eBPF " + stage + " failed: code=" + std::to_string(err_code) + (sys_err.empty()?"":" ("+sys_err+")"));
    };

    SkelPtr skel{process_exec_bpf__open()};
    if(!skel){
        Logger::instance().error("eBPF skeleton open returned null");
        report.add_error(name(), "open failed");
        return;
    }
    if(int rc = process_exec_bpf__load(skel.get())) { 
        log_bpf_err("load", rc); 
        report.add_error(name(), "load failed"); 
        return; 
    }
    if(int rc = process_exec_bpf__attach(skel.get())) { 
        log_bpf_err("attach", rc); 
        report.add_error(name(), "attach failed"); 
        return; 
    }
    // Get ring buffer file descriptor from the events map
    int ring_fd = bpf_map__fd(skel->maps.events);
    if(ring_fd < 0){ 
        log_bpf_err("bpf_map__fd", ring_fd); 
        report.add_error(name(), "failed to get ring buffer fd"); 
        return; 
    }

    struct ExecEvent { unsigned int type; unsigned int pid; char comm[16]; };
    struct ConnEvent { 
        unsigned int type; 
        unsigned int pid; 
        unsigned int daddr; 
        unsigned short dport; 
        char comm[16]; 
        unsigned char is_ipv6;
        unsigned int daddr6[4];
    };
    struct AnyEvent { unsigned int type; };
    struct Aggregated { std::vector<ExecEvent> execs; std::vector<ConnEvent> conns; } agg;
    agg.execs.reserve(512); agg.conns.reserve(512);
    auto handle_event = [](void *ctx, void *data, size_t len) -> int {
        auto agg = static_cast<Aggregated*>(ctx);
        if(len == sizeof(ExecEvent)){
            auto* ee = (ExecEvent*)data; if(ee->type==1) { agg->execs.push_back(*ee); return 0; }
        }
        if(len == sizeof(ConnEvent)){
            auto* ce = (ConnEvent*)data; if(ce->type==2) { agg->conns.push_back(*ce); return 0; }
        }
        return 0; };
    RingPtr rb{ ring_buffer__new(ring_fd, handle_event, &agg, nullptr) };
    if(!rb){ 
        Logger::instance().error("ring_buffer__new failed" );
        report.add_error(name(), "ring buffer create failed"); 
        return; 
    }
    auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now() - start < std::chrono::seconds(duration)){
        int pret = ring_buffer__poll(rb.get(), 200 /* ms */);
        if(pret < 0){
            log_bpf_err("ring_buffer__poll", pret);
            // Continue polling until timeout; transient errors may occur (e.g., EINTR)
        }
    }
    // Convert to findings
    for(const auto& e : agg.execs){
        Finding f; f.id = "exec.trace"; f.severity = Severity::Info; f.title = std::string("exec: ") + e.comm + " pid=" + std::to_string(e.pid); f.description = "Observed exec event"; f.metadata["pid"] = std::to_string(e.pid); f.metadata["comm"] = e.comm; f.metadata["source"] = "ebpf"; f.metadata["collector"] = "exec"; report.add_finding(name(), std::move(f)); }
    for(const auto& c : agg.conns){
        // Convert network order to dotted quad using standard library
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &c.daddr, ipbuf, sizeof(ipbuf));
        unsigned short port_n = ntohs(c.dport);
        Finding f; f.id = "net.connect"; f.severity = Severity::Info; f.title = std::string("connect: ") + c.comm + " pid=" + std::to_string(c.pid) + " dst=" + ipbuf + ":" + std::to_string(port_n); f.description = "Observed outbound connection attempt"; f.metadata["pid"] = std::to_string(c.pid); f.metadata["comm"] = c.comm; f.metadata["dst_ip"] = ipbuf; f.metadata["dst_port"] = std::to_string(port_n); f.metadata["source"] = "ebpf"; f.metadata["collector"] = "tcp_v4_connect"; report.add_finding(name(), std::move(f)); }
#endif
}

// Factory registration helper (not using static init to keep deterministic control)
std::unique_ptr<Scanner> make_ebpf_scanner(){ return std::make_unique<EbpfScanner>(); }

} // namespace sys_scan
