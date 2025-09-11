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

// Helper function to log current capability state
void log_capabilities(const std::string& context) {
#ifdef SYS_SCAN_HAVE_LIBCAP
    cap_t caps = cap_get_proc();
    if (!caps) {
        Logger::instance().warn("Failed to get current capabilities for " + context);
        return;
    }
    
    char* cap_text = cap_to_text(caps, nullptr);
    if (cap_text) {
        Logger::instance().info("Capabilities " + context + ": " + std::string(cap_text));
        cap_free(cap_text);
    } else {
        Logger::instance().warn("Failed to convert capabilities to text for " + context);
    }
    
    cap_free(caps);
#else
    Logger::instance().info("Capabilities logging not available (libcap not compiled in)");
#endif
}

void drop_capabilities(bool keep_cap_dac){
#ifdef SYS_SCAN_HAVE_LIBCAP
    // Don't log if seccomp has been applied, as logging may use forbidden syscalls
    static bool seccomp_applied = false;
    if (!seccomp_applied) {
        Logger::instance().info("Dropping capabilities (keep_cap_dac=" + std::string(keep_cap_dac ? "true" : "false") + ")");
        log_capabilities("before drop");
    }
    
    cap_t caps = cap_get_proc(); if(!caps) return; // best-effort
    cap_clear(caps);
    if(keep_cap_dac){
        cap_value_t v = CAP_DAC_READ_SEARCH;
        cap_set_flag(caps, CAP_PERMITTED, 1, &v, CAP_SET);
        cap_set_flag(caps, CAP_EFFECTIVE, 1, &v, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, 1, &v, CAP_SET);
    }
    if(cap_set_proc(caps)!=0){ 
        if (!seccomp_applied) {
            Logger::instance().error("cap_set_proc failed");
        }
    } else {
        if (!seccomp_applied) {
            log_capabilities("after drop");
        }
    }
    cap_free(caps);
    
    // Check if seccomp has been applied (this is a heuristic)
    seccomp_applied = seccomp_applied || (apply_seccomp_profile() == false); // If seccomp fails, it might already be applied
#else
    Logger::instance().info("Capability dropping not available (libcap not compiled in)");
#endif
}

bool apply_seccomp_profile(){
#ifdef SYS_SCAN_HAVE_SECCOMP
    static bool seccomp_applied = false;
    if (seccomp_applied) {
        // Seccomp has already been applied to this process
        return true;
    }
    
    Logger::instance().info("Applying seccomp profile");
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); if(!ctx) {
        Logger::instance().error("Failed to initialize seccomp context");
        return false;
    }
    auto allow=[&](int call){ return seccomp_rule_add(ctx, SCMP_ACT_ALLOW, call, 0)==0; };
    int calls[] = { SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(close), SCMP_SYS(fstat), SCMP_SYS(newfstatat),
                    SCMP_SYS(lseek), SCMP_SYS(mmap), SCMP_SYS(mprotect), SCMP_SYS(munmap), SCMP_SYS(brk), SCMP_SYS(rt_sigaction),
                    SCMP_SYS(rt_sigprocmask), SCMP_SYS(getpid), SCMP_SYS(gettid), SCMP_SYS(clock_gettime), SCMP_SYS(nanosleep),
                    SCMP_SYS(getrandom), SCMP_SYS(ioctl), SCMP_SYS(getdents64), SCMP_SYS(prlimit64), SCMP_SYS(statx), SCMP_SYS(access),
                    SCMP_SYS(readlink), SCMP_SYS(readlinkat), SCMP_SYS(getuid), SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid),
                    SCMP_SYS(exit), SCMP_SYS(exit_group) };
    for(int c: calls){ if(!allow(c)){ 
        Logger::instance().error("Failed to allow syscall " + std::to_string(c) + " in seccomp");
        seccomp_release(ctx); 
        return false; 
    } }
    if(seccomp_load(ctx)!=0){ 
        Logger::instance().error("Failed to load seccomp profile");
        seccomp_release(ctx); 
        return false; 
    }
    seccomp_release(ctx); 
    seccomp_applied = true;
    // Don't log success after seccomp is applied - logging might use forbidden syscalls
    return true;
#else
    Logger::instance().info("Seccomp not available (not compiled in)");
    return true;
#endif
}
}
