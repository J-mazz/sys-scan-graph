// Linux privilege & sandbox helpers (best-effort; compile-time gated)
#pragma once
namespace sys_scan {
void drop_capabilities(bool keep_cap_dac);
bool apply_seccomp_profile();
bool is_privilege_available();
bool is_seccomp_available();
int get_seccomp_allowed_syscalls_count();
}
