#pragma once

#include <coroutine>
#include <exception>
#include <QString>

namespace sys_scan::ui {

    template<typename T>
    struct Generator {
        struct promise_type;
        using handle_type = std::coroutine_handle<promise_type>;

        struct promise_type {
            T current_value;
            std::exception_ptr exception = nullptr;

            Generator get_return_object() { return Generator(handle_type::from_promise(*this)); }
            std::suspend_always initial_suspend() { return {}; }
            std::suspend_always final_suspend() noexcept { return {}; }

            std::suspend_always yield_value(T value) {
                current_value = std::move(value);
                return {};
            }
            void return_void() {}
            void unhandled_exception() { exception = std::current_exception(); }
        };

        handle_type coro;

        explicit Generator(handle_type h) : coro(h) {}
        ~Generator() { if (coro) coro.destroy(); }

        // Move-only
        Generator(const Generator&) = delete;
        Generator(Generator&& other) noexcept : coro(other.coro) { other.coro = nullptr; }

        struct Iterator {
            handle_type coro;
            bool done;

            void operator++() {
                coro.resume();
                done = coro.done();
            }
            bool operator!=(std::default_sentinel_t) const { return !done; }
            T operator*() const { return coro.promise().current_value; }
        };

        Iterator begin() {
            if (coro) {
                coro.resume();
                if (coro.done()) return {coro, true};
            }
            return {coro, false};
        }
        std::default_sentinel_t end() { return {}; }
    };

} // namespace sys_scan::ui
