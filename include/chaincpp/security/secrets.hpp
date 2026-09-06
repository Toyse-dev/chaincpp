#pragma once

#include "sandbox.hpp"
#include <string>
#include <optional>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <type_traits>

namespace chaincpp::security {

// Secure string that zeros memory on destruction - memory pinned
class secure_string {
public:
    secure_string() = default;
    explicit secure_string(const std::string& str);
    explicit secure_string(const char* str);
    ~secure_string();
    
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    
    secure_string(secure_string&& other) noexcept;
    secure_string& operator=(secure_string&& other) noexcept;
    
    [[nodiscard]] const char* c_str() const noexcept { return data_ ? data_.get() : ""; }
    [[nodiscard]] size_t size() const { return size_; }
    [[nodiscard]] bool empty() const { return size_ == 0; }

    // Warning: This returns a normal std::string on the heap. It will be swappable and visible in core dumps. Use with caution.
    // Only use when an API forces you to (e/g/ cURL) and zero the result immediately after.
    // Prefer with_c_str() below which avoids this copy.
    [[nodiscard]] std::string to_string() const;

    // Zero-copy accessor - use the secret without ever copying to std::string heap
    // Example for cURL fix:
    // key.with_c_str([&](const char* raw){
    // auto* list = curl_slist_append(nullptr, ("Authorization: Bearer " + std::string(raw)).c_str());
    // //... curl_easy_perform...
    // // zero temporary header string immediately after
    // });
    template<typename Func>
    auto with_c_str(Func&& func) const -> std::invoke_result_t<Func, const char*> {
        return func(data_ ? data_.get() : "");
    }
    
private:
    void zero_memory() noexcept;

    // We malloc in.cpp and free via custom deleter that just calls free
    struct FreeDeleter {
        void operator()(char* p) const noexcept { std::free(p);}
    };
    std::unique_ptr<char[], FreeDeleter> data_{nullptr};
    size_t size_ = 0;
};

// Manages API keys with encryption at rest
class SecretsManager {
public:
    static SecretsManager& instance();
    
    // Store a key (encrypted)
    Result<void> store_key(const std::string& service, const secure_string& key);
    
    // Retrieve a key
    Result<secure_string> get_key(const std::string& service);
    
    // Check if key exists
    bool has_key(const std::string& service) const;
    
    // Remove a key
    Result<void> remove_key(const std::string& service);
    
    // Load from environment variable
    Result<secure_string> load_from_env(const std::string& env_var);
    
private:
    SecretsManager() = default;
    // v0.1: in-memory only, no disk persistence
    // v0.2: TODO: DPAPI (Windows), libsecret/keyctl (Linux), Keychain (macOS)

    // In-memory cache (cleared after use)
    struct CachedKey {
        secure_string key;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<std::string, CachedKey> cache_;
    static constexpr auto CACHE_TTL = std::chrono::minutes(5);
    
    void cleanup_cache();
};

// RAII guard for temporarily using a key
class KeyGuard {
public:
    explicit KeyGuard(const std::string& service);
    ~KeyGuard();
    
    const secure_string* operator->() const { return &key_; }
    const secure_string& get() const { return key_; }
    bool valid() const { return valid_; }
    
private:
    secure_string key_;
    bool valid_ = false;
};

}