module;
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <utility>
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

export module sys_scan.interfaces;

export namespace sys_scan {

struct FileEntry {
    // Full path to this entry (best-effort; may be empty for synthetic/mock file systems).
    std::string path;
    std::string name;
    bool is_directory;
    bool is_symlink;
    bool is_regular;
};

// System information and time primitives for testability.
struct ISystemInfo {
    virtual ~ISystemInfo() = default;
    virtual std::string kernel_release() const = 0;
};

struct ISleeper {
    virtual ~ISleeper() = default;
    virtual void sleep_for(std::chrono::milliseconds duration) const = 0;
};

struct IFileSystem {
    virtual ~IFileSystem() = default;
    
    // Core operations
    virtual bool exists(const std::string& path) const = 0;
    virtual bool is_directory(const std::string& path) const = 0;
    virtual std::string read_file(const std::string& path) const = 0;
    virtual std::vector<FileEntry> list_directory(const std::string& path) const = 0;
    virtual std::string read_symlink(const std::string& path) const = 0;
    virtual std::filesystem::perms permissions(const std::string& path) const = 0;
};

struct IProcessRunner {
    virtual ~IProcessRunner() = default;
    // C++23: Use std::expected for explicit error handling
    // Success = stdout content, Error = exit code
    virtual std::expected<std::string, int> exec(const std::string& command, const std::vector<std::string>& args) const = 0;
};

}
