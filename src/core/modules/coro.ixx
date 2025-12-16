module;
#include <coroutine>
#include <exception>
#include <utility>
#include <iterator>

export module sys_scan.coro;

export using std::coroutine_handle;
export using std::coroutine_traits;
export using std::suspend_always;
export using std::default_sentinel_t;

export namespace sys_scan {

template<typename T>
struct Generator {
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    struct promise_type {
        T const* current_value = nullptr;
        std::exception_ptr exception = nullptr;

        Generator get_return_object() {
            return Generator(handle_type::from_promise(*this));
        }

        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }

        std::suspend_always yield_value(T const& value) {
            current_value = &value;
            return {};
        }

        void return_void() {}

        void unhandled_exception() {
            exception = std::current_exception();
        }
    };

    handle_type coro;

    explicit Generator(handle_type h) : coro(h) {}
    ~Generator() {
        if (coro) coro.destroy();
    }

    Generator(const Generator&) = delete;
    Generator& operator=(const Generator&) = delete;
    Generator(Generator&& other) noexcept : coro(other.coro) {
        other.coro = nullptr;
    }
    Generator& operator=(Generator&& other) noexcept {
        if (this != &other) {
            if (coro) coro.destroy();
            coro = other.coro;
            other.coro = nullptr;
        }
        return *this;
    }

    struct Iterator {
        handle_type coro;
        bool done;

        void rethrow_if_exception() const {
            if (coro && coro.promise().exception) {
                std::rethrow_exception(coro.promise().exception);
            }
        }

        Iterator& operator++() {
            coro.resume();
            rethrow_if_exception();
            done = coro.done();
            return *this;
        }

        bool operator!=(std::default_sentinel_t) const { return !done; }

        const T& operator*() const {
            return *coro.promise().current_value;
        }
    };

    Iterator begin() {
        if (coro) {
            coro.resume();
            if (coro.promise().exception) {
                std::rethrow_exception(coro.promise().exception);
            }
            if (coro.done()) return {coro, true};
        }
        return {coro, false};
    }

    std::default_sentinel_t end() { return {}; }
};

}
