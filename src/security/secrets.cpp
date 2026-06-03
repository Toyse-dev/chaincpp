#include "chaincpp/security/secrets.hpp"
#include <fstream>
#include <cstring>
#include <random>
#include <chrono>
#include <unordered_map>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#else
// Linux - use file with permissions
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace chaincpp::security {

// secure_string Implementation

secure_string::secure_string(const std::string& str) {
    size_ = str.size();
    data_.reset(static_cast<char*>(malloc(size_ + 1)));
    if (data_) {
        std::memcpy(data_.get(), str.c_str(), size_);
        data_.get()[size_] = '\0';

        // Lock the memory to prevent swapping to disk
        #ifdef _WIN32
            VirtualLock(data_.get(), size_ + 1);
        #else
            mlock(data_.get(), size_ + 1);
        #endif
    }
}

secure_string::secure_string(const char* str) {
    if (str) {
        size_ = std::strlen(str);
        data_.reset(static_cast<char*>(malloc(size_ + 1)));
        if (data_) {
            std::memcpy(data_.get(), str, size_);
            data_.get()[size_] = '\0';
        }
    }
}

secure_string::~secure_string() {
    zero_memory();
    if (data_) {
        #ifdef _WIN32
            VirtualUnlock(data_.get(), size_ + 1);
        #else
            munlock(data_.get(), size_ + 1);
        #endif
    }
}

// Prevent copying (only move)
secure_string(const secure_string&) = delete;
secure_string& operator=(const secure_string&) = delete;

secure_string::secure_string(secure_string&& other) noexcept
    : data_(std::move(other.data_)), size_(other.size_) {
    other.size_ = 0;
}

secure_string& secure_string::operator=(secure_string&& other) noexcept {
    if (this != &other) {
        zero_memory();
        data_ = std::move(other.data_);
        size_ = other.size_;
        other.size_ = 0;
    }
    return *this;
}

void secure_string::zero_memory() {
    if (data_) {
        volatile char* vp = static_cast<volatile char*>(data_.get());
        for (size_t i = 0; i < size_; ++i) {
            vp[i] = 0;
        }
    }
    size_ = 0;
}

std::string secure_string::to_string() const {
    return data_ ? std::string(data_.get(), size_) : std::string();
}

// SecretsManager EncryptionImpl Implementation
class SecretsManager::EncryptionImpl {
    public:
        static bool init() {
            return sodium_init() >= 0;
        }

        static std::vector<unint8_t> encrypt(const secure_string& plaintext, const std::vector<uint8_t>& key) {
            std::vector<uint8_t> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
            std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
            randombytes_buf(nonce.data(), nonce.size());

            crypto_secretbox_easy(
                ciphertext.data(),
                reinterpret_cast<const char*>(plaintext.data()),
                plaintext.to_string().size(),
                nonce.data(),
                key.data()
            );

            // Prepend nonce to ciphertext for storage
            std::vector<uint8_t> result;
            result.insert(result.end(), nonce.begin(), nonce.end());
            result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            return result;
        }

        static secure_string decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key) {
            if (ciphertext.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
                return secure_string();
            }

            std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + crypto_secretbox_NONCEBYTES);
            std::vector<uint8_t> encrypted(ciphertext.begin() + crypto_secretbox_NONCEBYTES, ciphertext.end());
            std::vector<unint8_t> decrypted(encrypted.size() - crypto_secretbox_MACBYTES);

            if (crypto_secretbox_open_easy(
                decrypted.data(),
                encrypted.data(),
                encrypted.size(),
                nonce.data(),
                key.data()
            ) != 0) {
                return secure_string(); // corrupted or tampered
            }

            return secure_string(std::string(decrypted.begin(), decrypted.end()));
        }
};

SecretsManager& SecretsManager::instance() {
    static SecretsManager manager;
    return manager;
}

Result<void> SecretsManager::store_key(const std::string& service, const secure_string& key) {
    cleanup_cache();
    
    auto encrypted = encrypt(key);
    if (!store_secure(service, encrypted)) {
        return Result<void>::err("Failed to store key for service: " + service);
    }
    
    // Cache the key
    secure_string cache_val(key.to_string());
    cache_[service] = {std::move(cache_val), std::chrono::steady_clock::now()};
    
    return Result<void>::ok();
}

Result<secure_string> SecretsManager::get_key(const std::string& service) {
    cleanup_cache();
    
    // Check cache first
    auto it = cache_.find(service);
    if (it != cache_.end()) {
        auto now = std::chrono::steady_clock::now();
        if (now - it->second.timestamp < CACHE_TTL) {
            // Create a new secure_string from the cached data
            return Result<secure_string>::ok(secure_string(it->second.key.to_string()));
        }
    }
    
    // Retrieve from secure storage
    auto encrypted = retrieve_secure(service);
    if (!encrypted.has_value()) {
        return Result<secure_string>::err("Key not found for service: " + service);
    }
    
    auto key = decrypt(encrypted.value());
    
    // Move into cache, then return a new instance for the user
    std::string key_raw = key.to_string();
    cache_[service] = {std::move(key), std::chrono::steady_clock::now()};
    
    return Result<secure_string>::ok(secure_string(key_raw));
}

bool SecretsManager::has_key(const std::string& service) const {
    return retrieve_secure(service).has_value();
}

Result<void> SecretsManager::remove_key(const std::string& service) {
    cache_.erase(service);
    
#ifdef _WIN32
    // On Windows, we'd delete from DPAPI store
    // For now, just return success
    return Result<void>::ok();
#else
    std::string filename = ".chaincpp_" + service + ".key";
    std::remove(filename.c_str());
    return Result<void>::ok();
#endif
}

Result<secure_string> SecretsManager::load_from_env(const std::string& env_var) {
    const char* value = std::getenv(env_var.c_str());
    if (!value) {
        return Result<secure_string>::err("Environment variable not found: " + env_var);
    }
    
    return Result<secure_string>::ok(secure_string(value));
}

bool SecretsManager::store_secure([[maybe_unused]] const std::string& service, const std::vector<uint8_t>& encrypted) {
#ifdef _WIN32
    // Use DPAPI on Windows
    DATA_BLOB input;
    input.cbData = static_cast<DWORD>(encrypted.size());
    input.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(encrypted.data()));
     
    DATA_BLOB output = {0, nullptr};
    
    if (CryptProtectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
        // Store output.pbData somewhere (simplified - in real impl, use registry)
        LocalFree(output.pbData);
        return true;
    }
    return false;
#else
    // Simple file-based storage with restricted permissions
    std::string filename = ".chaincpp_" + service + ".key";
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;
    
    file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    file.close();
    
    // Set file permissions to owner-only (0600)
    chmod(filename.c_str(), 0600);
    return true;
#endif
}

std::optional<std::vector<uint8_t>> SecretsManager::retrieve_secure([[maybe_unused]] const std::string& service) const {
#ifdef _WIN32
    // On Windows, service is currently unused in this simplified block
    return std::nullopt;
#else
    std::string filename = ".chaincpp_" + service + ".key";
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return std::nullopt;
    
    size_t size = file.tellg();
    file.seekg(0);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return data;
#endif
}

std::vector<uint8_t> SecretsManager::encrypt(const secure_string& plaintext) {
    // Simple XOR with random key (obfuscation, not for high security)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    uint8_t key = static_cast<uint8_t>(dis(gen));
    std::vector<uint8_t> result;
    result.push_back(key);
    
    std::string plain = plaintext.to_string();
    for (char c : plain) {
        result.push_back(static_cast<uint8_t>(c) ^ key);
        key = static_cast<uint8_t>(c);
    }
    
    return result;
}

secure_string SecretsManager::decrypt(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.empty()) return secure_string();
    
    uint8_t key = ciphertext[0];
    std::string plain;
    
    for (size_t i = 1; i < ciphertext.size(); ++i) {
        char c = static_cast<char>(ciphertext[i] ^ key);
        plain += c;
        key = ciphertext[i];
    }
    
    return secure_string(plain);
}

void SecretsManager::cleanup_cache() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (now - it->second.timestamp > CACHE_TTL) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// KeyGuard Implementation
// ============================================================================

KeyGuard::KeyGuard(const std::string& service) {
    auto result = SecretsManager::instance().get_key(service);
    if (result.is_ok()) {
        key_ = std::move(result.value());
        valid_ = true;
    }
}

KeyGuard::~KeyGuard() {
    // key_ automatically zeroed on destruction
}

} // namespace chaincpp::security