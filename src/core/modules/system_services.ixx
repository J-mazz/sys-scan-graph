module;
#include <fstream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <system_error>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <array>
#include <cstdlib>
#include <type_traits>
#include <variant>

#if __has_include(<expected>)
#include <expected>
#endif
#if __has_include(<experimental/expected>)
#include <experimental/expected>
#endif

#ifndef SYS_SCAN_HAS_EXPECTED
#if defined(__cpp_lib_expected)
#define SYS_SCAN_HAS_EXPECTED 1
#elif defined(__cpp_lib_experimental_expected)
namespace std {
    using std::experimental::expected;
    using std::experimental::unexpected;
    using std::experimental::unexpect;
}
#define SYS_SCAN_HAS_EXPECTED 1
#else
namespace std {
    template <class E>
    class unexpected {
    public:
        constexpr explicit unexpected(E e) : value_(std::move(e)) {}
        constexpr const E& error() const & { return value_; }
    private:
        E value_;
    };

    struct unexpect_t {
        constexpr explicit unexpect_t() = default;
    };
    inline constexpr unexpect_t unexpect{};

    template <class T, class E>
    class expected {
    public:
        constexpr expected(const T& v) : storage_(v) {}
        constexpr expected(T&& v) : storage_(std::move(v)) {}
        constexpr expected(unexpected<E> e) : storage_(std::move(e)) {}

        constexpr bool has_value() const { return std::holds_alternative<T>(storage_); }
        constexpr explicit operator bool() const { return has_value(); }

        constexpr T& value() & { return std::get<T>(storage_); }
        constexpr const T& value() const & { return std::get<T>(storage_); }
        constexpr E& error() & { return std::get<unexpected<E>>(storage_).error(); }
        constexpr const E& error() const & { return std::get<unexpected<E>>(storage_).error(); }

        template <class U>
        constexpr T value_or(U&& default_value) const {
            if (has_value()) return std::get<T>(storage_);
            return static_cast<T>(std::forward<U>(default_value));
        }

    private:
        std::variant<T, unexpected<E>> storage_;
    };
}
#define SYS_SCAN_HAS_EXPECTED 1
#endif
#endif

export module sys_scan.system_services;
import sys_scan.interfaces;

namespace fs = std::filesystem;

export namespace sys_scan {

class RealFileSystem : public IFileSystem {
public:
    bool exists(const std::string& path) const override {
        std::error_code ec;
        return fs::exists(path, ec);
    }

    bool is_directory(const std::string& path) const override {
        std::error_code ec;
        return fs::is_directory(path, ec);
    }

    std::string read_file(const std::string& path) const override {
        std::ifstream f(path, std::ios::binary);
        if (!f) return "";
        std::stringstream buffer;
        buffer << f.rdbuf();
        return buffer.str();
    }

    std::vector<FileEntry> list_directory(const std::string& path) const override {
        std::vector<FileEntry> result;
        std::error_code ec;
        if (!fs::exists(path, ec) || !fs::is_directory(path, ec)) return result;

        for (const auto& entry : fs::directory_iterator(path, ec)) {
             FileEntry fe;
             fe.path = entry.path().string();
             fe.name = entry.path().filename().string();
             fe.is_directory = entry.is_directory(ec);
             fe.is_symlink = entry.is_symlink(ec);
             fe.is_regular = entry.is_regular_file(ec);
             result.push_back(fe);
        }
        return result;
    }

    std::string read_symlink(const std::string& path) const override {
        std::error_code ec;
        if (fs::is_symlink(path, ec)) {
            return fs::read_symlink(path, ec).string();
        }
        return "";
    }

    std::filesystem::perms permissions(const std::string& path) const override {
        std::error_code ec;
        auto status = fs::status(path, ec);
        if (ec) return std::filesystem::perms::unknown;
        return status.permissions();
    }
};

class RealProcessRunner : public IProcessRunner {
public:
    std::expected<std::string, int> exec(const std::string& command, const std::vector<std::string>& args) const override {
        int pipefd[2];
        if (pipe(pipefd) == -1) return std::unexpected(-1);

        pid_t pid = fork();
        if (pid == -1) {
            close(pipefd[0]); close(pipefd[1]);
            return std::unexpected(-1);
        }

        if (pid == 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);

            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(command.c_str()));
            for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
            argv.push_back(nullptr);

            // Sanitize environment
            unsetenv("LD_PRELOAD");
            unsetenv("LD_LIBRARY_PATH");
            setenv("PATH", "/usr/bin:/bin", 1);

            execvp(argv[0], argv.data());
            _exit(127);
        } else {
            close(pipefd[1]);
            std::string output;
            std::array<char, 1024> buffer;
            ssize_t bytes;
            while ((bytes = read(pipefd[0], buffer.data(), buffer.size())) > 0) {
                output.append(buffer.data(), bytes);
            }
            close(pipefd[0]);
            int status = 0;
            waitpid(pid, &status, 0);
            int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            if (exit_code == 0) return output;
            return std::unexpected(exit_code);
        }
    }
};

class RealSystemInfo : public ISystemInfo {
public:
    std::string kernel_release() const override {
        struct utsname un;
        if (uname(&un) != 0) return "";
        return std::string{un.release};
    }
};

class RealSleeper : public ISleeper {
public:
    void sleep_for(std::chrono::milliseconds duration) const override {
        std::this_thread::sleep_for(duration);
    }
};

}
