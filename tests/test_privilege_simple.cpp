#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/Privilege.h"
#include "../src/core/Logging.h"

// Simple test file for privilege functions that can be tested without forking
// This avoids corrupting coverage instrumentation

namespace sys_scan {

TEST(PrivilegeSimpleTest, IsPrivilegeAvailable) {
    bool result = is_privilege_available();
#ifdef SYS_SCAN_HAVE_LIBCAP
    EXPECT_TRUE(result);
#else
    EXPECT_FALSE(result);
#endif
}

TEST(PrivilegeSimpleTest, IsSeccompAvailable) {
    bool result = is_seccomp_available();
#ifdef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(result);
#else
    EXPECT_FALSE(result);
#endif
}

TEST(PrivilegeSimpleTest, GetSeccompAllowedSyscallsCount) {
    int count = get_seccomp_allowed_syscalls_count();
#ifdef SYS_SCAN_HAVE_SECCOMP
    EXPECT_EQ(count, 27); // Should match the number of syscalls in the profile
#else
    EXPECT_EQ(count, 0);
#endif
}

TEST(PrivilegeSimpleTest, PrivilegeFunctionSignatures) {
    // Test that functions have correct signatures and are callable
    auto func_priv = is_privilege_available;
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(func_priv)>));

    auto func_seccomp = is_seccomp_available;
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(func_seccomp)>));

    auto func_count = get_seccomp_allowed_syscalls_count;
    EXPECT_TRUE((std::is_invocable_r_v<int, decltype(func_count)>));
}

} // namespace sys_scan

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}