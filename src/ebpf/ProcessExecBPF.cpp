#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>

#ifdef SYS_SCAN_HAVE_EBPF
#include "process_exec.skel.h"
#include <bpf/libbpf.h>
#endif

namespace sys_scan {

class ProcessExecBPFRunner {
public:
    ProcessExecBPFRunner() = default;
    ~ProcessExecBPFRunner(){ stop(); }
    bool start(){
#ifdef SYS_SCAN_HAVE_EBPF
        if(running_) return true;
        skel_ = process_exec_bpf__open();
        if(!skel_) { std::cerr << "Failed to open BPF skeleton" << std::endl; return false; }
        if(process_exec_bpf__load(skel_)) { std::cerr << "Failed to load BPF skeleton" << std::endl; process_exec_bpf__destroy(skel_); skel_=nullptr; return false; }
        if(process_exec_bpf__attach(skel_)) { std::cerr << "Failed to attach BPF skeleton" << std::endl; process_exec_bpf__destroy(skel_); skel_=nullptr; return false; }
        running_=true;
        stop_flag_=false;
        thread_ = std::thread([this]{ this->loop(); });
        return true;
#else
        return false;
#endif
    }
    void stop(){
#ifdef SYS_SCAN_HAVE_EBPF
        if(!running_) return;
        stop_flag_=true;
        if(thread_.joinable()) thread_.join();
        process_exec_bpf__destroy(skel_); skel_=nullptr; running_=false;
#endif
    }
private:
    void loop(){
#ifdef SYS_SCAN_HAVE_EBPF
        // Consume ring buffer events
        auto handle_event = [](void *ctx, void *data, size_t len) -> int {
            struct exec_event { unsigned int pid; char comm[16]; }; // mirror definition
            auto *e = (exec_event*)data;
            std::cerr << "[ebpf] exec pid=" << e->pid << " comm=" << e->comm << std::endl;
            return 0;
        };
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel_->maps.events), handle_event, nullptr, nullptr);
        if(!rb) { std::cerr << "Failed to create ring buffer" << std::endl; return; }
        while(!stop_flag_) {
            ring_buffer__poll(rb, 250 /* ms */);
        }
        ring_buffer__free(rb);
#endif
    }
#ifdef SYS_SCAN_HAVE_EBPF
    struct process_exec_bpf *skel_ = nullptr;
    std::thread thread_{};
    std::atomic<bool> stop_flag_{false};
    bool running_ = false;
#endif
};

// For future integration: expose a singleton accessor (not yet wired into scanners)
ProcessExecBPFRunner& process_exec_bpf_runner(){ static ProcessExecBPFRunner r; return r; }

}
