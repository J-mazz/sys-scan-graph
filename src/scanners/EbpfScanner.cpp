#include "../core/Scanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#ifdef SYS_SCAN_HAVE_EBPF
#include "process_exec.skel.h"
#include <bpf/libbpf.h>
#endif
#include <chrono>
#include <thread>
#include <atomic>

namespace sys_scan {

class EbpfScanner : public Scanner {
public:
    std::string name() const override { return "ebpf_exec_trace"; }
    std::string description() const override { return "Short-lived execve trace via eBPF"; }
    void scan(Report& report) override {
#ifndef SYS_SCAN_HAVE_EBPF
        report.add_warning(name(), "eBPF not built; scanner inactive", ErrorCode::Unknown);
        return;
#else
        auto& cfg = config();
        int duration = cfg.ioc_exec_trace_seconds > 0 ? cfg.ioc_exec_trace_seconds : 3;
        Logger::instance().info("ebpf trace: capturing exec events for " + std::to_string(duration) + "s");
        struct process_exec_bpf* skel = process_exec_bpf__open();
        if(!skel){ report.add_error(name(), "open failed", ErrorCode::Unknown); return; }
        if(process_exec_bpf__load(skel)) { report.add_error(name(), "load failed", ErrorCode::Unknown); process_exec_bpf__destroy(skel); return; }
        if(process_exec_bpf__attach(skel)) { report.add_error(name(), "attach failed", ErrorCode::Unknown); process_exec_bpf__destroy(skel); return; }
    // Skeleton may be stub (non-strict mode) - detect by absence of expected map via CO-RE accessor macro
#ifdef process_exec_bpf__destroy
    // Attempt to locate 'events' map symbolically; fallback ring_fd=-1 if not present
    int ring_fd = -1;
    // libbpf skeleton normally exposes skel->maps.events; use offsetof trick guarded by macro
#ifdef PROCESS_EXEC_BPF_SKEL_H /* stub header defines empty struct; maps field absent */
    // stub mode: no runtime events
    ring_fd = -1;
#else
    // best-effort attempt (may fail in stub header scenario)
    try {
        ring_fd = bpf_map__fd(skel->maps.events);
    } catch(...) { ring_fd = -1; }
#endif
    if(ring_fd < 0){ report.add_warning(name(), "stub skeleton (no events captured)", ErrorCode::Unknown); process_exec_bpf__destroy(skel); return; }
#else
    int ring_fd = -1; // unreachable but keeps compiler happy if macros differ
#endif

        struct ExecEvent { unsigned int type; unsigned int pid; char comm[16]; };
        struct ConnEvent { unsigned int type; unsigned int pid; unsigned int daddr; unsigned short dport; char comm[16]; };
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
        struct ring_buffer* rb = ring_buffer__new(ring_fd, handle_event, &agg, nullptr);
        if(!rb){ report.add_error(name(), "ring buffer create failed", ErrorCode::Unknown); process_exec_bpf__destroy(skel); return; }
        auto start = std::chrono::steady_clock::now();
        while(std::chrono::steady_clock::now() - start < std::chrono::seconds(duration)){
            ring_buffer__poll(rb, 200 /* ms */);
        }
        ring_buffer__free(rb);
        // Convert to findings
        for(const auto& e : agg.execs){
            Finding f; f.id = "exec.trace"; f.severity = Severity::Info; f.title = std::string("exec: ") + e.comm + " pid=" + std::to_string(e.pid); f.description = "Observed exec event"; f.metadata["pid"] = std::to_string(e.pid); f.metadata["comm"] = e.comm; f.metadata["source"] = "ebpf"; f.metadata["collector"] = "exec"; buffered_add(report, name(), std::move(f)); }
        for(const auto& c : agg.conns){
            // Convert network order to dotted quad quickly (user space). We'll reconstruct IPv4.
            unsigned int ip = c.daddr; unsigned char b1= ip & 0xFF, b2=(ip>>8)&0xFF, b3=(ip>>16)&0xFF, b4=(ip>>24)&0xFF; char ipbuf[32]; snprintf(ipbuf,sizeof(ipbuf), "%u.%u.%u.%u", b1,b2,b3,b4);
            unsigned short port_n = (c.dport>>8) | (c.dport<<8); // ntohs
            Finding f; f.id = "net.connect"; f.severity = Severity::Info; f.title = std::string("connect: ") + c.comm + " pid=" + std::to_string(c.pid) + " dst=" + ipbuf + ":" + std::to_string(port_n); f.description = "Observed outbound connection attempt"; f.metadata["pid"] = std::to_string(c.pid); f.metadata["comm"] = c.comm; f.metadata["dst_ip"] = ipbuf; f.metadata["dst_port"] = std::to_string(port_n); f.metadata["source"] = "ebpf"; f.metadata["collector"] = "tcp_v4_connect"; buffered_add(report, name(), std::move(f)); }
        process_exec_bpf__destroy(skel);
#endif
    }
};

// Factory registration helper (not using static init to keep deterministic control)
std::unique_ptr<Scanner> make_ebpf_scanner(){ return std::make_unique<EbpfScanner>(); }

}
