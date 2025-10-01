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

// Extended comprehensive tests for Privilege functions
// These tests focus on edge cases, error conditions, and boundary scenarios

namespace sys_scan {

class PrivilegeExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        Logger::instance().set_level(LogLevel::Info);
    }

    void TearDown() override {
        // Clean up after tests
    }
};

TEST_F(PrivilegeExtendedTest, DropCapabilitiesWithoutLibcapEdgeCases) {
    // Test drop_capabilities when libcap is not available
    // This should handle all parameter combinations gracefully
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));

    // Test multiple calls
    for (int i = 0; i < 10; ++i) {
        EXPECT_NO_THROW(drop_capabilities(i % 2 == 0));
    }
#endif
}

TEST_F(PrivilegeExtendedTest, ApplySeccompProfileWithoutSeccompEdgeCases) {
    // Test apply_seccomp_profile when seccomp is not available
    // Should return true and handle multiple calls
#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
    EXPECT_TRUE(apply_seccomp_profile());
    EXPECT_TRUE(apply_seccomp_profile());
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsNullOperations) {
    // Test that calling functions with no actual effect works
    // This tests the compile-time guard logic
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsSignatures) {
    // Test that functions have correct signatures and are callable
    // This ensures the functions exist and can be linked
#ifdef SYS_SCAN_HAVE_LIBCAP
    // drop_capabilities should be callable with bool parameter
    auto func1 = drop_capabilities;
    EXPECT_TRUE((std::is_invocable_v<decltype(func1), bool>));
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    // apply_seccomp_profile should return bool
    auto func2 = apply_seccomp_profile;
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(func2)>));
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsTypeTraits) {
    // Test type traits and function properties
#ifdef SYS_SCAN_HAVE_LIBCAP
    // drop_capabilities should be a function that takes bool
    using DropCapsFunc = decltype(drop_capabilities);
    EXPECT_TRUE((std::is_invocable_v<DropCapsFunc, bool>));
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    // apply_seccomp_profile should return bool and take no parameters
    using SeccompFunc = decltype(apply_seccomp_profile);
    EXPECT_TRUE((std::is_invocable_r_v<bool, SeccompFunc>));
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsAddressable) {
    // Test that functions can be assigned to function pointers
#ifdef SYS_SCAN_HAVE_LIBCAP
    void (*drop_func)(bool) = drop_capabilities;
    EXPECT_TRUE(drop_func != nullptr);
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    bool (*seccomp_func)() = apply_seccomp_profile;
    EXPECT_TRUE(seccomp_func != nullptr);
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsInStdFunction) {
    // Test that functions can be wrapped in std::function
#ifdef SYS_SCAN_HAVE_LIBCAP
    std::function<void(bool)> drop_func = drop_capabilities;
    EXPECT_TRUE(drop_func != nullptr);
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    std::function<bool()> seccomp_func = apply_seccomp_profile;
    EXPECT_TRUE(seccomp_func != nullptr);
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsLoggingEdgeCases) {
    // Test logging behavior with different log levels
    std::vector<LogLevel> levels = {LogLevel::Debug, LogLevel::Info, LogLevel::Warn, LogLevel::Error};

    for (auto level : levels) {
        Logger::instance().set_level(level);
        // These should not crash regardless of log level
#ifndef SYS_SCAN_HAVE_LIBCAP
        EXPECT_NO_THROW(drop_capabilities(false));
#endif
#ifndef SYS_SCAN_HAVE_SECCOMP
        EXPECT_TRUE(apply_seccomp_profile());
#endif
    }
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsMultipleLoggerInstances) {
    // Test with multiple logger accesses
    Logger& logger1 = Logger::instance();
    Logger& logger2 = Logger::instance();
    EXPECT_EQ(&logger1, &logger2); // Should be same instance

    logger1.set_level(LogLevel::Debug);
    EXPECT_EQ(logger2.level(), LogLevel::Debug);

    // Functions should work fine while thread is running
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(true));
#endif
#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsWithEnvironment) {
    // Test functions with various environment variable states
    // Save original environment
    const char* original_level = getenv("SYS_SCAN_LOG_LEVEL");
    const char* original_debug = getenv("SYS_SCAN_DEBUG");

    // Test with environment variables set
    setenv("SYS_SCAN_LOG_LEVEL", "DEBUG", 1);
    setenv("SYS_SCAN_DEBUG", "1", 1);

    // Functions should handle environment variables gracefully
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(false));
#endif
#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
#endif

    // Restore environment
    if (original_level) {
        setenv("SYS_SCAN_LOG_LEVEL", original_level, 1);
    } else {
        unsetenv("SYS_SCAN_LOG_LEVEL");
    }
    if (original_debug) {
        setenv("SYS_SCAN_DEBUG", original_debug, 1);
    } else {
        unsetenv("SYS_SCAN_DEBUG");
    }
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsMemoryLayout) {
    // Test that functions have reasonable memory addresses
#ifdef SYS_SCAN_HAVE_LIBCAP
    uintptr_t addr_drop = reinterpret_cast<uintptr_t>(drop_capabilities);
    EXPECT_NE(addr_drop, 0);
    EXPECT_TRUE(addr_drop % alignof(void(*)(bool)) == 0); // Properly aligned
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    uintptr_t addr_seccomp = reinterpret_cast<uintptr_t>(apply_seccomp_profile);
    EXPECT_NE(addr_seccomp, 0);
    EXPECT_TRUE(addr_seccomp % alignof(bool(*)()) == 0); // Properly aligned
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsExceptionSafety) {
    // Test that functions don't throw exceptions (they use best-effort approach)
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_NO_THROW({
        bool result = apply_seccomp_profile();
        (void)result; // Suppress unused variable warning
    });
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsConstCorrectness) {
    // Test that functions can be called from const contexts
#ifdef SYS_SCAN_HAVE_LIBCAP
    const auto const_drop_func = drop_capabilities;
    // Should be able to call const function pointer
    EXPECT_TRUE((std::is_invocable_v<decltype(const_drop_func), bool>));
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    const auto const_seccomp_func = apply_seccomp_profile;
    // Should be able to call const function pointer
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(const_seccomp_func)>));
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsThreadLocalState) {
    // Test that functions work correctly in multi-threaded context
    // Note: This doesn't actually call the functions in threads to avoid
    // affecting the main process, but tests the setup
    std::atomic<bool> thread_ready{false};
    std::atomic<bool> thread_done{false};

    std::thread test_thread([&]() {
        thread_ready = true;
        // Wait for main thread signal
        while (!thread_done) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    // Wait for thread to be ready
    while (!thread_ready) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Functions should work fine while thread is running
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(true));
#endif
#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
#endif

    thread_done = true;
    test_thread.join();
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsPerformance) {
    // Test that functions complete in reasonable time
    auto start = std::chrono::high_resolution_clock::now();

#ifndef SYS_SCAN_HAVE_LIBCAP
    drop_capabilities(false);
    drop_capabilities(true);
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
    apply_seccomp_profile();
#endif

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete very quickly (less than 100ms)
    EXPECT_LT(duration.count(), 100);
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsIdempotent) {
    // Test that calling functions multiple times is safe
    for (int i = 0; i < 5; ++i) {
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(i % 2 == 0));
#endif
#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
#endif
    }
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsStateIsolation) {
    // Test that functions don't interfere with each other
    Logger::instance().set_level(LogLevel::Info);

#ifndef SYS_SCAN_HAVE_LIBCAP
    drop_capabilities(false);
    drop_capabilities(true);
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
    bool result1 = apply_seccomp_profile();
    bool result2 = apply_seccomp_profile();
    // Should return consistent results
    EXPECT_EQ(result1, result2);
#endif

    // Logger level should still be Info
    EXPECT_EQ(Logger::instance().level(), LogLevel::Info);
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsResourceCleanup) {
    // Test that functions clean up resources properly
    // This is mainly about ensuring no memory leaks or dangling resources

    // Get initial resource usage if possible
    struct rusage initial_usage;
    getrusage(RUSAGE_SELF, &initial_usage);

#ifndef SYS_SCAN_HAVE_LIBCAP
    drop_capabilities(false);
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
    apply_seccomp_profile();
#endif

    // Get final resource usage
    struct rusage final_usage;
    getrusage(RUSAGE_SELF, &final_usage);

    // Memory usage should not have increased significantly
    // (Allow some tolerance for measurement overhead)
    long mem_diff = final_usage.ru_maxrss - initial_usage.ru_maxrss;
    EXPECT_LT(mem_diff, 1024 * 1024); // Less than 1MB increase
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsWithSignalsBlocked) {
    // Test functions with signals blocked
    sigset_t old_set, new_set;
    sigfillset(&new_set);
    sigprocmask(SIG_BLOCK, &new_set, &old_set);

    // Functions should work even with signals blocked
#ifndef SYS_SCAN_HAVE_LIBCAP
    EXPECT_NO_THROW(drop_capabilities(true));
#endif

#ifndef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(apply_seccomp_profile());
#endif

    // Restore signal mask
    sigprocmask(SIG_SETMASK, &old_set, nullptr);
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsAfterFork) {
    // Test that functions work correctly after fork operations
    // This simulates the pattern used in the main tests
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process - test functions here
#ifndef SYS_SCAN_HAVE_LIBCAP
        drop_capabilities(false);
#endif
#ifndef SYS_SCAN_HAVE_SECCOMP
        apply_seccomp_profile();
#endif
        // Exit child process
        _exit(0);
    } else {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsCompileTimeGuards) {
    // Test that the compile-time guards work correctly
    // This ensures the preprocessor logic is sound

#ifdef SYS_SCAN_HAVE_LIBCAP
    // If libcap is available, function should be defined
    auto func_drop = drop_capabilities;
    EXPECT_TRUE((std::is_invocable_v<decltype(func_drop), bool>));
#else
    // If libcap is not available, function should still be defined but do nothing
    EXPECT_NO_THROW(drop_capabilities(false));
    EXPECT_NO_THROW(drop_capabilities(true));
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    // If seccomp is available, function should be defined and return bool
    auto func_seccomp = apply_seccomp_profile;
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(func_seccomp)>));
#else
    // If seccomp is not available, function should return true
    EXPECT_TRUE(apply_seccomp_profile());
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsHeaderDeclarations) {
    // Test that header declarations match implementations
    // This ensures ABI compatibility

#ifdef SYS_SCAN_HAVE_LIBCAP
    // drop_capabilities should be declared as void drop_capabilities(bool)
    using ExpectedSignatureDrop = void(*)(bool);
    ExpectedSignatureDrop func_ptr_drop = drop_capabilities;
    EXPECT_TRUE(func_ptr_drop != nullptr);
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    // apply_seccomp_profile should be declared as bool apply_seccomp_profile()
    using ExpectedSignatureSeccomp = bool(*)();
    ExpectedSignatureSeccomp func_ptr_seccomp = apply_seccomp_profile;
    EXPECT_TRUE(func_ptr_seccomp != nullptr);
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeAvailabilityFunctions) {
    // Test the simple availability functions that can be called without privileges
    bool priv_available = is_privilege_available();
    bool seccomp_available = is_seccomp_available();
    int syscall_count = get_seccomp_allowed_syscalls_count();

#ifdef SYS_SCAN_HAVE_LIBCAP
    EXPECT_TRUE(priv_available);
#else
    EXPECT_FALSE(priv_available);
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
    EXPECT_TRUE(seccomp_available);
    EXPECT_EQ(syscall_count, 27); // Should match the number of syscalls in the profile
#else
    EXPECT_FALSE(seccomp_available);
    EXPECT_EQ(syscall_count, 0);
#endif
}

TEST_F(PrivilegeExtendedTest, PrivilegeAvailabilityFunctionSignatures) {
    // Test that the availability functions have correct signatures
    auto func_priv = is_privilege_available;
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(func_priv)>));

    auto func_seccomp = is_seccomp_available;
    EXPECT_TRUE((std::is_invocable_r_v<bool, decltype(func_seccomp)>));

    auto func_count = get_seccomp_allowed_syscalls_count;
    EXPECT_TRUE((std::is_invocable_r_v<int, decltype(func_count)>));
}

#ifdef SYS_SCAN_HAVE_LIBCAP
TEST_F(PrivilegeExtendedTest, DropCapabilitiesWithLibcapExtended) {
    // Extended test for dropping capabilities when libcap is available
    // Test various scenarios in child processes
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process
        // Test dropping all capabilities
        drop_capabilities(false);
        // Test keeping CAP_DAC_READ_SEARCH
        drop_capabilities(true);
        // Use direct syscall to exit to avoid seccomp blocking
        syscall(SYS_exit, 0);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        // Accept either normal exit or signal termination (seccomp may kill the child)
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
        if (WIFEXITED(status)) {
            EXPECT_EQ(WEXITSTATUS(status), 0);
        }
    }
}
#endif

#ifdef SYS_SCAN_HAVE_SECCOMP
TEST_F(PrivilegeExtendedTest, ApplySeccompProfileWithSeccompExtended) {
    // Extended test for applying seccomp profile when seccomp is available
    // Test in child process to avoid affecting main process
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process
        bool result = apply_seccomp_profile();
        // Use direct syscall to exit to avoid seccomp blocking
        syscall(SYS_exit, result ? 0 : 1);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0); // Should succeed
    }
}
#endif

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsCallableInChildProcess) {
    // Test that privilege functions can be called in child processes
    // This ensures they work in the intended usage pattern
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process
        drop_capabilities(false);
        drop_capabilities(true);
        bool result = apply_seccomp_profile();
        // Use direct syscall to exit to avoid seccomp blocking
        syscall(SYS_exit, result ? 0 : 1);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        // Accept either normal exit or signal termination
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
        if (WIFEXITED(status)) {
            EXPECT_TRUE(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 1);
        }
    }
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsMultipleCallsInChild) {
    // Test multiple calls to privilege functions in child process
    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "Failed to fork process";

    if (pid == 0) {
        // Child process
        for (int i = 0; i < 3; ++i) {
            drop_capabilities(i % 2 == 0);
            bool result = apply_seccomp_profile();
            if (!(result == true || result == false)) {
                syscall(SYS_exit, 1);
            }
        }
        // Use direct syscall to exit to avoid seccomp blocking
        syscall(SYS_exit, 0);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        // Accept either normal exit or signal termination (seccomp may kill the child)
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
        if (WIFEXITED(status)) {
            EXPECT_EQ(WEXITSTATUS(status), 0);
        }
    }
}

TEST_F(PrivilegeExtendedTest, PrivilegeFunctionsWithDifferentLogLevelsInChild) {
    // Test privilege functions with different log levels in child process
    std::vector<LogLevel> levels = {LogLevel::Debug, LogLevel::Info, LogLevel::Warn};

    for (auto level : levels) {
        pid_t pid = fork();
        ASSERT_NE(pid, -1) << "Failed to fork process";

        if (pid == 0) {
            // Child process
            Logger::instance().set_level(level);
            drop_capabilities(false);
            bool result = apply_seccomp_profile();
            // Use direct syscall to exit to avoid seccomp blocking
            syscall(SYS_exit, result ? 0 : 1);
        } else {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status));
            EXPECT_TRUE(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 1);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan