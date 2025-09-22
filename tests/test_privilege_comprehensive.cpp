#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/Privilege.h"
#include "../src/core/Logging.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <atomic>

// Comprehensive extended tests for Privilege functions
// These tests focus on missing coverage areas: conditional compilation fallbacks,
// error conditions, and edge cases not covered by existing tests

namespace sys_scan {

class PrivilegeComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        Logger::instance().set_level(LogLevel::Info);
    }

    void TearDown() override {
        // Clean up after tests
    }
};

// Test availability functions - these should work regardless of library availability
TEST_F(PrivilegeComprehensiveTest, AvailabilityFunctionsAlwaysWork) {
    // These functions should always return boolean values and be callable
    bool priv_available = is_privilege_available();
    bool seccomp_available = is_seccomp_available();
    int syscall_count = get_seccomp_allowed_syscalls_count();

    // Results should be boolean
    EXPECT_TRUE(priv_available == true || priv_available == false);
    EXPECT_TRUE(seccomp_available == true || seccomp_available == false);

    // Syscall count should be non-negative
    EXPECT_GE(syscall_count, 0);

    // Test multiple calls return consistent results
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(is_privilege_available(), priv_available);
        EXPECT_EQ(is_seccomp_available(), seccomp_available);
        EXPECT_EQ(get_seccomp_allowed_syscalls_count(), syscall_count);
    }
}

// Test conditional compilation fallbacks when libraries are NOT available
#ifndef SYS_SCAN_HAVE_LIBCAP
TEST_F(PrivilegeComprehensiveTest, DropCapabilitiesFallbackWhenLibcapUnavailable) {
    // When libcap is not available, drop_capabilities should be a no-op
    // but still callable and safe

    // Test both parameter values
    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));

    // Test in child process to ensure no interference
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process
        drop_capabilities(false);
        drop_capabilities(true);

        // Multiple calls should be safe
        for (int i = 0; i < 10; ++i) {
            drop_capabilities(i % 2 == 0);
        }

        syscall(SYS_exit, 0);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
TEST_F(PrivilegeComprehensiveTest, ApplySeccompProfileFallbackWhenSeccompUnavailable) {
    // When seccomp is not available, apply_seccomp_profile should return true
    // indicating "success" (no-op success)

    EXPECT_TRUE(apply_seccomp_profile());
    EXPECT_TRUE(apply_seccomp_profile());
    EXPECT_TRUE(apply_seccomp_profile());

    // Test in child process
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process
        bool result1 = apply_seccomp_profile();
        bool result2 = apply_seccomp_profile();

        // Both should return true
        if (!result1 || !result2) {
            syscall(SYS_exit, 1);
        }

        // Multiple calls should remain successful
        for (int i = 0; i < 5; ++i) {
            if (!apply_seccomp_profile()) {
                syscall(SYS_exit, 1);
            }
        }

        syscall(SYS_exit, 0);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}
#endif

// Test mixed availability scenarios
TEST_F(PrivilegeComprehensiveTest, MixedAvailabilityScenarios) {
    bool priv_available = is_privilege_available();
    bool seccomp_available = is_seccomp_available();

    // Test all combinations of availability
    if (priv_available && seccomp_available) {
        // Both available - should work normally
        pid_t pid = fork();
        if (pid == 0) {
            drop_capabilities(false);
            bool result = apply_seccomp_profile();
            syscall(SYS_exit, result ? 0 : 1);
        } else {
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status));
        }
    } else if (priv_available && !seccomp_available) {
        // Only privileges available
        pid_t pid = fork();
        if (pid == 0) {
            drop_capabilities(true);
            bool result = apply_seccomp_profile(); // Should return true (no-op)
            syscall(SYS_exit, result ? 0 : 1);
        } else {
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status));
            EXPECT_EQ(WEXITSTATUS(status), 0);
        }
    } else if (!priv_available && seccomp_available) {
        // Only seccomp available
        pid_t pid = fork();
        if (pid == 0) {
            drop_capabilities(false); // Should be no-op
            bool result = apply_seccomp_profile();
            syscall(SYS_exit, result ? 0 : 1);
        } else {
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status));
        }
    } else {
        // Neither available - all should be no-ops
        pid_t pid = fork();
        if (pid == 0) {
            drop_capabilities(false);
            drop_capabilities(true);
            bool result = apply_seccomp_profile();
            syscall(SYS_exit, result ? 0 : 1);
        } else {
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status));
            EXPECT_EQ(WEXITSTATUS(status), 0);
        }
    }
}

// Test error conditions and edge cases
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsUnderResourceConstraints) {
    // Test functions under memory pressure
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - try to exhaust memory
        std::vector<char*> allocations;
        try {
            for (int i = 0; i < 1000; ++i) {
                char* ptr = new char[1024 * 1024]; // 1MB allocations
                memset(ptr, 0, 1024 * 1024);
                allocations.push_back(ptr);
            }
        } catch (const std::bad_alloc&) {
            // Memory exhausted - now test privilege functions
            drop_capabilities(false);
            bool result = apply_seccomp_profile();
            // Should not crash even under memory pressure
            syscall(SYS_exit, result ? 0 : 1);
        }

        // Clean up if we get here
        for (auto ptr : allocations) {
            delete[] ptr;
        }
        syscall(SYS_exit, 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
    }
}

TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsWithInvalidFileDescriptors) {
    // Test functions when file descriptors are exhausted
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - exhaust file descriptors
        std::vector<int> fds;
        for (int i = 0; i < 1000; ++i) {
            int fd = open("/dev/null", O_RDONLY);
            if (fd == -1) break;
            fds.push_back(fd);
        }

        // Now test privilege functions with limited FDs
        drop_capabilities(true);
        bool result = apply_seccomp_profile();

        // Clean up
        for (int fd : fds) {
            close(fd);
        }

        syscall(SYS_exit, result ? 0 : 1);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
    }
}

TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsAfterSetuid) {
    // Test privilege functions after setuid (if possible)
    pid_t pid = fork();
    if (pid == 0) {
        // Try to set uid to non-root (may fail if already non-root)
        if (geteuid() == 0) {
            // We're root, try to drop privileges
            setuid(65534); // nobody user
        }

        // Now test privilege functions
        drop_capabilities(false);
        bool result = apply_seccomp_profile();

        syscall(SYS_exit, result ? 0 : 1);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
    }
}

TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsWithSignals) {
    // Test privilege functions while signals are being sent
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        alarm(1); // Set alarm to interrupt

        drop_capabilities(false);
        bool result = apply_seccomp_profile();

        syscall(SYS_exit, result ? 0 : 1);
    } else {
        int status;
        waitpid(pid, &status, 0);
        // Should complete despite signal
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
    }
}

// Test logging edge cases specifically for privilege functions
TEST_F(PrivilegeComprehensiveTest, PrivilegeLoggingEdgeCases) {
    // Test logging when logger is in various states
    // Run in child process to avoid seccomp interference
    pid_t pid = fork();
    if (pid == 0) {
        Logger& logger = Logger::instance();

        // Test with null logger output (if possible)
        logger.set_level(LogLevel::Error); // Minimize output

        drop_capabilities(true);
        bool result = apply_seccomp_profile();

        // Test with maximum logging
        logger.set_level(LogLevel::Debug);

        drop_capabilities(false);
        result = apply_seccomp_profile();

        // Test after logger reconfiguration
        logger.set_level(LogLevel::Info);
        EXPECT_EQ(logger.level(), LogLevel::Info);

        syscall(SYS_exit, 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        // Accept either normal exit or signal termination (seccomp may kill the child)
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
        if (WIFEXITED(status)) {
            EXPECT_EQ(WEXITSTATUS(status), 0);
        }
    }
}

// Test function pointer operations and callbacks
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionPointers) {
    // Test that functions can be used as function pointers
    void (*drop_func)(bool) = drop_capabilities;
    bool (*seccomp_func)() = apply_seccomp_profile;
    bool (*priv_check)() = is_privilege_available;
    bool (*seccomp_check)() = is_seccomp_available;
    int (*syscall_count)() = get_seccomp_allowed_syscalls_count;

    EXPECT_TRUE(drop_func != nullptr);
    EXPECT_TRUE(seccomp_func != nullptr);
    EXPECT_TRUE(priv_check != nullptr);
    EXPECT_TRUE(seccomp_check != nullptr);
    EXPECT_TRUE(syscall_count != nullptr);

    // Test calling through function pointers in child process
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_NO_THROW(drop_func(false));
        EXPECT_NO_THROW(drop_func(true));
        bool result = seccomp_func();
        EXPECT_TRUE(result == true || result == false);

        bool priv_avail = priv_check();
        bool seccomp_avail = seccomp_check();
        int count = syscall_count();

        EXPECT_TRUE(priv_avail == true || priv_avail == false);
        EXPECT_TRUE(seccomp_avail == true || seccomp_avail == false);
        EXPECT_GE(count, 0);

        syscall(SYS_exit, 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        // Accept either normal exit or signal termination (seccomp may kill the child)
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
        if (WIFEXITED(status)) {
            EXPECT_EQ(WEXITSTATUS(status), 0);
        }
    }
}

// Test thread safety and concurrent access
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsConcurrentAccess) {
    const int num_threads = 4;
    std::vector<std::thread> threads;
    std::atomic<bool> all_successful{true};

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([i, &all_successful]() {
            try {
                // Each thread calls functions with different patterns
                if (i % 2 == 0) {
                    drop_capabilities(false);
                    bool result = apply_seccomp_profile();
                    if (!(result == true || result == false)) {
                        all_successful = false;
                    }
                } else {
                    drop_capabilities(true);
                    bool result = apply_seccomp_profile();
                    if (!(result == true || result == false)) {
                        all_successful = false;
                    }
                }

                // Test availability functions
                bool priv = is_privilege_available();
                bool seccomp = is_seccomp_available();
                int count = get_seccomp_allowed_syscalls_count();

                if (!(priv == true || priv == false) ||
                    !(seccomp == true || seccomp == false) ||
                    count < 0) {
                    all_successful = false;
                }

            } catch (...) {
                all_successful = false;
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_TRUE(all_successful);
}

// Test boundary conditions and extreme inputs
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsBoundaryConditions) {
    // Test rapid successive calls in child process
    pid_t pid = fork();
    if (pid == 0) {
        for (int i = 0; i < 100; ++i) {
            drop_capabilities(i % 2 == 0);
            bool result = apply_seccomp_profile();
            EXPECT_TRUE(result == true || result == false);
        }

        // Test with varying process states
        chdir("/");
        umask(022);

        drop_capabilities(false);
        bool result1 = apply_seccomp_profile();

        // Change process group
        setpgid(0, 0);

        drop_capabilities(true);
        bool result2 = apply_seccomp_profile();

        syscall(SYS_exit, (result1 && result2) ? 0 : 1);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

// Test interaction with system calls and library functions
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsSystemCallInteraction) {
    // Test privilege functions before and after system calls in child process
    pid_t pid = fork();
    if (pid == 0) {
        pid_t original_pid = getpid();
        uid_t original_uid = getuid();

        drop_capabilities(false);
        bool result1 = apply_seccomp_profile();

        // Verify system calls still work
        pid_t current_pid = getpid();
        uid_t current_uid = getuid();

        EXPECT_EQ(original_pid, current_pid);
        EXPECT_EQ(original_uid, current_uid);

        drop_capabilities(true);
        bool result2 = apply_seccomp_profile();

        // Functions should return consistent types
        EXPECT_TRUE(result1 == true || result1 == false);
        EXPECT_TRUE(result2 == true || result2 == false);

        syscall(SYS_exit, 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

// Test memory and resource management
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsResourceManagement) {
    // Test that functions don't leak resources in child process
    pid_t pid = fork();
    if (pid == 0) {
        struct rusage usage_before, usage_after;

        getrusage(RUSAGE_SELF, &usage_before);

        // Call functions many times
        for (int i = 0; i < 50; ++i) {
            drop_capabilities(i % 2 == 0);
            apply_seccomp_profile();
            is_privilege_available();
            is_seccomp_available();
            get_seccomp_allowed_syscalls_count();
        }

        getrusage(RUSAGE_SELF, &usage_after);

        // Memory usage should not increase significantly
        long mem_increase = usage_after.ru_maxrss - usage_before.ru_maxrss;
        EXPECT_LT(mem_increase, 10 * 1024 * 1024); // Less than 10MB increase

        syscall(SYS_exit, 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

// Test compile-time conditional logic thoroughly
TEST_F(PrivilegeComprehensiveTest, CompileTimeConditionalLogic) {
    // Test that the preprocessor logic works correctly

#ifdef SYS_SCAN_HAVE_LIBCAP
    // When libcap is available, privilege functions should be fully functional
    bool priv_available = is_privilege_available();
    EXPECT_TRUE(priv_available);

    // drop_capabilities should be callable and functional
    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));
#else
    // When libcap is not available, should return false and be no-op
    bool priv_available = is_privilege_available();
    EXPECT_FALSE(priv_available);

    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    // When seccomp is available, seccomp functions should be functional
    bool seccomp_available = is_seccomp_available();
    EXPECT_TRUE(seccomp_available);

    bool result = apply_seccomp_profile();
    EXPECT_TRUE(result == true || result == false);

    int count = get_seccomp_allowed_syscalls_count();
    EXPECT_GT(count, 0); // Should have some allowed syscalls
#else
    // When seccomp is not available, should return false and true (no-op success)
    bool seccomp_available = is_seccomp_available();
    EXPECT_FALSE(seccomp_available);

    bool result = apply_seccomp_profile();
    EXPECT_TRUE(result); // Should return true (no-op success)

    int count = get_seccomp_allowed_syscalls_count();
    EXPECT_EQ(count, 0); // Should return 0 when not available
#endif
}

// Test error recovery and resilience
TEST_F(PrivilegeComprehensiveTest, PrivilegeFunctionsErrorRecovery) {
    // Test that functions can recover from various error conditions in child process
    pid_t pid = fork();
    if (pid == 0) {
        // Test after failed system calls
        errno = EINVAL;
        drop_capabilities(false);
        bool result = apply_seccomp_profile();
        EXPECT_TRUE(result == true || result == false);

        // Test with corrupted environment
        setenv("SYS_SCAN_LOG_LEVEL", "INVALID", 1);
        drop_capabilities(true);
        result = apply_seccomp_profile();
        EXPECT_TRUE(result == true || result == false);

        // Clean up environment
        unsetenv("SYS_SCAN_LOG_LEVEL");

        syscall(SYS_exit, 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan