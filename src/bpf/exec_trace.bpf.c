// exec_trace.bpf.c - detailed exec tracepoint program
// Attaches to sched_process_exec and emits enriched event with pid/ppid/comm/filename and retval placeholder.
// CO-RE compatible minimal example.

#include "vmlinux.h"
#ifndef __u32
#define __u32 unsigned int
#endif
#ifndef __u64
#define __u64 unsigned long long
#endif
#ifndef __s32
#define __s32 int
#endif
#ifndef __s64
#define __s64 long long
#endif
#ifndef __s32
#define __s32 int
#endif
#ifndef __u16
#define __u16 unsigned short
#endif
#ifndef __be16
#define __be16 unsigned short
#endif
#ifndef __be32
#define __be32 unsigned int
#endif
#ifndef __wsum
#define __wsum unsigned int
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

// Fallback stub for struct task_struct if BTF unavailable
#ifndef SYS_SCAN_HAVE_TASK_STRUCT
struct task_struct { struct task_struct *real_parent; int tgid; };
#endif

// Fallback for tracepoint context if not present
#ifndef SYS_SCAN_HAVE_SCHED_PROCESS_EXEC_CTX
struct trace_event_raw_sched_process_exec { const char *filename; };
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct exec_event_t {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    char filename[256];
    int retval; // always 0 for sched_process_exec (placeholder for symmetry w/ kprobe variant)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512 KB buffer
} exec_events SEC(".maps");

// Helper: safely read parent pid
static __always_inline __u32 get_ppid(struct task_struct *task){
#ifdef BPF_CORE_READ
    __u32 ppid = 0;
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if(parent) ppid = BPF_CORE_READ(parent, tgid);
    return ppid;
#else
    // Fallback: trust stub linkage
    if(task && task->real_parent) return task->real_parent->tgid;
    return 0;
#endif
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx){
    struct exec_event_t *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if(!e) return 0;
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->ppid = get_ppid(task);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // filename from tracepoint context: filename member points to string user executed
    const char *fn = (const char*)ctx->filename;
    bpf_core_read_str(&e->filename, sizeof(e->filename), fn);
    e->retval = 0; // tracepoint doesn't expose return code
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Alternative kprobe variant (commented for now) could capture retval from do_execveat_common
// SEC("kprobe/do_execveat_common")
// int BPF_KPROBE(handle_execveat, int fd, struct filename *filename, struct user_arg_ptr *argv, struct user_arg_ptr *envp, int flags){
//     return 0;
// }
