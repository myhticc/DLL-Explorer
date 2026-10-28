#pragma once
#include <utility>
#include <windows.h>

namespace platform {
// Owns a kernel handle. Both null and INVALID_HANDLE_VALUE are empty states.
class Handle {
  public:
    explicit Handle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~Handle() {
        reset();
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other)
            reset(std::exchange(other.handle_, nullptr));
        return *this;
    }
    HANDLE get() const noexcept {
        return handle_;
    }
    explicit operator bool() const noexcept {
        return handle_ && handle_ != INVALID_HANDLE_VALUE;
    }
    void reset(HANDLE replacement = nullptr) noexcept {
        if (*this)
            CloseHandle(handle_);
        handle_ = replacement;
    }

  private:
    HANDLE handle_;
};
} // namespace platform
