#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <system_error>
#include <memory>
#include <cstddef>

namespace chaincpp::security {

// ============================================================================
// Result Type - Safe error handling without exceptions
// ============================================================================

template<typename T>
class Result {
public:
    static Result<T> ok(T value) {
        Result r;
        r.value_ = std::make_unique<T>(std::move(value));
        r.has_value_ = true;
        return r;
    }
    
    static Result<T> err(std::string error) {
        Result r;
        r.error_ = std::move(error);
        r.has_value_ = false;
        return r;
    }
    
    Result(Result&& other) noexcept
        : value_(std::move(other.value_))
        , error_(std::move(other.error_))
        , has_value_(other.has_value_) {}
    
    Result& operator=(Result&& other) noexcept {
        if (this != &other) {
            value_ = std::move(other.value_);
            error_ = std::move(other.error_);
            has_value_ = other.has_value_;
        }
        return *this;
    }
    
    // No copy
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;
    
    bool is_ok() const { return has_value_; }
    bool is_err() const { return !has_value_; }
    
    T& value() { 
        if (!has_value_) throw std::runtime_error(error_);
        return *value_;
    }
    
    const T& value() const { 
        if (!has_value_) throw std::runtime_error(error_);
        return *value_;
    }
    
    std::string error() const { return error_; }
    
private:
    Result() = default;
    std::unique_ptr<T> value_;
    std::string error_;
    bool has_value_ = false;
};

// Specialize for void
template<>
class Result<void> {
public:
    static Result<void> ok() {
        Result r;
        r.has_value_ = true;
        return r;
    }
    
    static Result<void> err(std::string error) {
        Result r;
        r.error_ = std::move(error);
        r.has_value_ = false;
        return r;
    }
    
    bool is_ok() const { return has_value_; }
    bool is_err() const { return !has_value_; }
    std::string error() const { return error_; }
    
private:
    std::string error_;
    bool has_value_ = false;
};

// ============================================================================
// Security Limits
// ============================================================================

struct SecurityLimits {
    std::chrono::milliseconds timeout{5000};
    size_t max_memory_bytes{100 * 1024 * 1024};
    size_t max_output_bytes{1024 * 1024};
    bool allow_network{false};
    bool allow_filesystem{false};
    std::vector<std::string> allowed_domains;
    std::vector<std::string> allowed_paths;
    
    static SecurityLimits safe_defaults() {
        SecurityLimits limits;
        limits.timeout = std::chrono::milliseconds(5000);
        limits.max_memory_bytes = 100 * 1024 * 1024;
        limits.max_output_bytes = 1024 * 1024;
        limits.allow_network = false;
        limits.allow_filesystem = false;
        return limits;
    }
    
    static SecurityLimits strict() {
        SecurityLimits limits;
        limits.timeout = std::chrono::milliseconds(1000);
        limits.max_memory_bytes = 10 * 1024 * 1024;
        limits.max_output_bytes = 100 * 1024;
        limits.allow_network = false;
        limits.allow_filesystem = false;
        return limits;
    }
    
    static SecurityLimits network_access() {
        auto limits = safe_defaults();
        limits.allow_network = true;
        return limits;
    }
};

// ============================================================================
// Sandbox Class
// ============================================================================

class Sandbox {
public:
    ~Sandbox();
    
    static Result<void> execute_safe(
        std::function<Result<void>()> func,
        const SecurityLimits& limits = SecurityLimits::safe_defaults()
    );
    
    template<typename T>
    static Result<T> execute_safe_result(
        std::function<Result<T>()> func,
        [[maybe_unused]] const SecurityLimits& limits = SecurityLimits::safe_defaults()
    ) {
        return func();
    }
    
private:
    Sandbox() = default;
    
    static bool set_memory_limit(size_t max_bytes);
    static bool set_time_limit(std::chrono::milliseconds timeout);
    static void sanitize_environment();
    static bool check_network_allowed(bool allowed);
};

}