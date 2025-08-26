#include "Privilege.h"
#include "Logging.h"
#include <unistd.h>
#ifdef SYS_SCAN_HAVE_LIBCAP
#include <sys/capability.h>
#endif
#ifdef SYS_SCAN_HAVE_SECCOMP
#include <seccomp.h>
#endif

namespace sys_scan {
void drop_capabilities(bool keep_cap_dac){
#ifdef SYS_SCAN_HAVE_LIBCAP
    cap_t caps = cap_get_proc(); if(!caps) return; // best-effort
    cap_clear(caps);
    if(keep_cap_dac){
        cap_value_t v = CAP_DAC_READ_SEARCH;
        cap_set_flag(caps, CAP_PERMITTED, 1, &v, CAP_SET);
        cap_set_flag(caps, CAP_EFFECTIVE, 1, &v, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, 1, &v, CAP_SET);
    }
    if(cap_set_proc(caps)!=0){ Logger::instance().warn("cap_set_proc failed (continuing)"); }
    cap_free(caps);
#else
    (void)keep_cap_dac;
#endif
}

bool apply_seccomp_profile(){
#ifdef SYS_SCAN_HAVE_SECCOMP
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); if(!ctx) return false;
    auto allow=[&](int call){ return seccomp_rule_add(ctx, SCMP_ACT_ALLOW, call, 0)==0; };
    int calls[] = { SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(openat), SCMP_SYS(close), SCMP_SYS(fstat), SCMP_SYS(newfstatat),
                    SCMP_SYS(lseek), SCMP_SYS(mmap), SCMP_SYS(mprotect), SCMP_SYS(munmap), SCMP_SYS(brk), SCMP_SYS(rt_sigaction),
                    SCMP_SYS(rt_sigprocmask), SCMP_SYS(getpid), SCMP_SYS(gettid), SCMP_SYS(clock_gettime), SCMP_SYS(nanosleep),
                    SCMP_SYS(getrandom), SCMP_SYS(ioctl), SCMP_SYS(getdents64), SCMP_SYS(prlimit64), SCMP_SYS(statx), SCMP_SYS(access) };
    for(int c: calls){ if(!allow(c)){ seccomp_release(ctx); return false; } }
    if(seccomp_load(ctx)!=0){ seccomp_release(ctx); return false; }
    seccomp_release(ctx); return true;
#else
    return true;
#endif
}
}
