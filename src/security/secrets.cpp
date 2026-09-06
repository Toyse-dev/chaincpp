#include "chaincpp/security/secrets.hpp"
#include <sodium.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <mutex>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <strings.h>
#endif

#ifndef explicit_bzero
#define explicit_bzero sodium_memzero
#endif

namespace chaincpp::security {

// secure_string - Memory Pinned zero-on-destruction

secure_string::secure_string(const std::string& str) {
    size_ = str.size();
    char* raw = static_cast<char*>(std::malloc(size_ + 1));
    if (raw) {
        std::memcpy(raw, str.c_str(), size_);
        raw[size_] = '\0';
#if defined(_WIN32)
        VirtualLock(raw, size_ + 1);
#else
        ::mlock(raw, size_ + 1);
#endif
        data_.reset(raw); //Will be freed manually in dtor, not via delete
    }
}

secure_string::secure_string(const char* str) {
    if (str) {
        size_ = std::strlen(str);
        char* raw = static_cast<char*>(std::malloc(size_ + 1));
        if (raw) {
            std::memcpy(raw, str, size_);
            raw[size_] = '\0';
#if defined(_WIN32)
            VirtualLock(raw, size_ + 1);
#else
            ::mlock(raw, size_ + 1);
#endif
            data_.reset(raw);
        }
    } else {
        size_ = 0;
        data_.reset(nullptr);
    }
}

secure_string::~secure_string() {
    if (data_) {
        #if defined(_WIN32)
            SecureZeroMemory(data_.get(), size_ + 1);
        #else
        // sodium_memzero is guaranteed not to be optimized away
        sodium_memzero(data_.get(), size_);
        // clear the null terminator as well
        sodium_memzero(data_.get() + size_, 1);
        #endif
        // Unlock
        #if defined(_WIN32)
            VirtualUnlock(data_.get(), size_ + 1);
        #else
            ::munlock(data_.get(), size_ + 1);
        #endif
        // Free the malloc buffer - bypass unique_ptr's delete
        std::free(data_.release());
    }
    size_ = 0;
}

secure_string::secure_string(secure_string&& other) noexcept
    : data_(std::move(other.data_)), size_(other.size_) {
    other.size_ = 0;
}

secure_string& secure_string::operator=(secure_string&& other) noexcept {
    if (this != &other) {
        // zero and free current
        if (data_) {
#if defined(_WIN32)
            SecureZeroMemory(data_.get(), size_);
            VirtualUnlock(data_.get(), size_ + 1);
#else
            sodium_memzero(data_.get(), size_ + 1);
            ::munlock(data_.get(), size_ + 1);
#endif
            std::free(data_.release());
        }
        data_ = std::move(other.data_);
        size_ = other.size_;
        other.size_ = 0;
    }
    return *this;
}

void secure_string::zero_memory() noexcept {
    if (data_ && size_ > 0) {
        #if defined(_WIN32)
            SecureZeroMemory(data_.get(), size_);
        #else
            sodium_memzero(data_.get(), size_);
        #endif
    }
    // keep size_ = 0 logic to caller - dtor sets it, but zero_memory alone should NOT reset size_
    // to allow correct unlock size. Size reset is done in dtor/move.
}

std::string secure_string::to_string() const {
     // SECURITY NOTE: This returns a regular std::string on the normal heap.
    // It WILL be swappable and visible in core dumps. This is unavoidable for
    // APIs like libcurl that require const char*.
    // CALLER MUST CLEAR IMMEDIATELY AFTER USE:
    return data_? std::string(data_.get(), size_) : std::string();
}

// SecretsManager: Memory pinned cache arechitecture
SecretsManager& SecretsManager::instance() {
    static SecretsManager manager;
    return manager;
};

Result<void> SecretsManager::store_key(const std::string& service, const secure_string& key) {
    // Thread-safe, single-pass lambda initialization gate for Libsodium framework targets
    static std::once_flag flag;
    static bool sodium_ok = false;
    std::call_once(flag, [](){ sodium_ok = sodium_init() >= 0; });

    if (!sodium_ok) return Result<void>::err("Cryptographic Initialization Failure: libsodium startup sequence failed.");

    cleanup_cache();

    if (service.empty() || key.empty()) {
        return Result<void>::err("Validation Fault: Service identifier or key payloads cannot be empty.");
    }

    // Explicit assignment bypasses brace-init conversion restrictions
    CachedKey cache_entry;
    cache_entry.key = secure_string(key.to_string().c_str());
    cache_entry.timestamp = std::chrono::steady_clock::now();
    cache_[service] = std::move(cache_entry);

    return Result<void>::ok();
}

Result<secure_string> SecretsManager::get_key(const std::string& service) {
    cleanup_cache();

    auto it = cache_.find(service);
    if (it != cache_.end()) {
        auto now = std::chrono::steady_clock::now();
        if (now - it->second.timestamp < CACHE_TTL) {
            //  Re-instantiate secure_string cleanly
            return Result<secure_string>::ok(secure_string(it->second.key.to_string()));
        }
    }
    return Result<secure_string>::err("Persistent storage not implemented in v0.1" + service);
}

bool SecretsManager::has_key(const std::string& service) const {
    auto it = cache_.find(service);
    if (it != cache_.end()) {
        auto now = std::chrono::steady_clock::now();
        if (now - it->second.timestamp < CACHE_TTL) {
            return true;
        }
    }
    return false;
}

Result<void> SecretsManager::remove_key(const std::string& service) {
    cache_.erase(service);
    return Result<void>::ok();
}

Result<secure_string> SecretsManager::load_from_env(const std::string& env_var) {
    const char* value = std::getenv(env_var.c_str());
    if (!value || std::strlen(value) == 0) {
        return Result<secure_string>::err("Environment variable not found: " + env_var);
    }

    secure_string secret(value);
    // Clear env copy from memory as soon as possible - getenv buffer is owned by OS
    auto store_res = store_key(env_var, secret);
    if (store_res.is_err()) return Result<secure_string>::err(store_res.error());
    return Result<secure_string>::ok(std::move(secret));
}

// Dead, insecure XOR obfuscation methods completely purged to pass core audit checks
void SecretsManager::cleanup_cache() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (now - it->second.timestamp > CACHE_TTL) {
            it = cache_.erase(it); // secure_string dtor zeroes
        } else {
            ++it;
        }
    }
}

// KeyGuard Implementation
KeyGuard::KeyGuard(const std::string& service) {
    auto result = SecretsManager::instance().get_key(service);
    if (result.is_ok()) {
        key_ = std::move(result.value());
        valid_ = true;
    }
}

KeyGuard::~KeyGuard() = default;

}