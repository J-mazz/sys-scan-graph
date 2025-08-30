// Minimal eBPF program to trace process exec & outbound TCP connect events.
// We prefer including generated vmlinux.h for CO-RE; in non-strict builds or
// environments lacking BTF some fundamental typedefs may be missing. Provide
// guarded fallbacks so the object can still compile (a stub skeleton may be
// generated later in the pipeline if relocation isn't possible).
#include "vmlinux.h"

// Fallback basic kernel-style integer typedefs (only if absent).
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif
#ifndef __s32
typedef int __s32;
#endif
#ifndef __s64
typedef long long __s64;
#endif
#ifndef __be16
typedef __u16 __be16;
#endif
#ifndef __be32
typedef __u32 __be32;
#endif
#ifndef __wsum
typedef __u32 __wsum; /* checksum pseudo type */
#endif

// Short aliases used in many eBPF examples; only define if not present.
#ifndef u32
#define u32 __u32
#endif
#ifndef u16
#define u16 __u16
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

enum event_type { EVENT_EXEC=1, EVENT_CONN=2 };

struct exec_event { u32 type; u32 pid; char comm[16]; };
struct conn_event { u32 type; u32 pid; u32 daddr; u16 dport; char comm[16]; u8 is_ipv6; u32 daddr6[4]; };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e) return 0;
    e->type = EVENT_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Minimal IPv4 sockaddr definition (avoid heavy kernel headers)
struct minimal_sockaddr { __u16 sa_family; char sa_data[14]; };
struct minimal_sockaddr_in { __u16 sin_family; __u16 sin_port; __u32 sin_addr; char pad[8]; };
struct minimal_sockaddr_in6 { __u16 sin6_family; __u16 sin6_port; __u32 sin6_flowinfo; __u32 sin6_addr[4]; __u32 sin6_scope_id; };

// Minimal tracepoint context for sys_enter_connect (mirrors trace_event_raw_sys_enter)
struct minimal_sys_enter {
    unsigned short type; // trace_entry
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
    long id;      // syscall id
    long args[6]; // syscall arguments
};

// Trace outbound connect via syscall tracepoint; works without struct sock definitions.
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct minimal_sys_enter *ctx){
    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e) return 0;
    e->type = EVENT_CONN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->is_ipv6 = 0; // default to IPv4

    void *uservaddr = (void*)ctx->args[1];
    int addrlen = (int)ctx->args[2];
    
    // Try IPv4 first
    if(addrlen >= (int)sizeof(struct minimal_sockaddr_in)){
        struct minimal_sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uservaddr);
        if(sin.sin_family == 2 /* AF_INET */){
            e->daddr = sin.sin_addr; // already network order
            e->dport = sin.sin_port; // network order
            goto submit;
        }
    }
    
    // Try IPv6
    if(addrlen >= (int)sizeof(struct minimal_sockaddr_in6)){
        struct minimal_sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr);
        if(sin6.sin6_family == 10 /* AF_INET6 */){
            e->is_ipv6 = 1;
            e->daddr = 0; // IPv4 field not used for IPv6
            e->dport = sin6.sin6_port; // network order
            // Copy IPv6 address (already in network order)
            e->daddr6[0] = sin6.sin6_addr[0];
            e->daddr6[1] = sin6.sin6_addr[1];
            e->daddr6[2] = sin6.sin6_addr[2];
            e->daddr6[3] = sin6.sin6_addr[3];
            goto submit;
        }
    }
    
    // Unsupported address family or too short
    e->daddr = 0; 
    e->dport = 0;
    
submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Older kernels without the tracepoint could optionally attach to kprobes (omitted for brevity)

