#include "chaincpp/rag/embeddings.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <random>
#include <cmath>
#include <thread>
#include <atomic>

using json = nlohmann::json;

namespace chaincpp::rag {
    // Exception-isolated cURL write callback to block use-after-free or lambda exceptions
    static size_t secure_embedding_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t total = size * nmemb;
        auto* response = static_cast<std::string*>(userp);
        if (response) {
            try {
                response->append(static_cast<char*>(contents), total);
            } catch (...) {
                return 0; //Aborts cURL transfer safely on error
            }
        }
        return total;
    }

// OpenAIEmbeddings Implementation
security::Result<std::unique_ptr<OpenAIEmbeddings>> OpenAIEmbeddings::create() {
    return create(Config());
}

security::Result<std::unique_ptr<OpenAIEmbeddings>> OpenAIEmbeddings::create(Config cfg) {
    auto key_result = security::SecretsManager::instance().load_from_env(cfg.api_key_env_var);
    if (key_result.is_err()) {
        return security::Result<std::unique_ptr<OpenAIEmbeddings>>::err(key_result.error());
    }
    
    auto embeddings = std::unique_ptr<OpenAIEmbeddings>(new OpenAIEmbeddings());
    embeddings->api_key_ = std::move(key_result.value());
    embeddings->config_ = std::move(cfg);
    
    return security::Result<std::unique_ptr<OpenAIEmbeddings>>::ok(std::move(embeddings));
}

OpenAIEmbeddings::~OpenAIEmbeddings() = default;

security::Result<std::vector<float>> OpenAIEmbeddings::embed(const std::string& text) {
    auto batch_result = embed_batch({text});
    if (batch_result.is_err()) {
        return security::Result<std::vector<float>>::err(batch_result.error());
    }
    
    auto batch = std::move(batch_result.value());
    if (batch.empty()) {
        return security::Result<std::vector<float>>::err("Empty embedding result");
    }
    
    return security::Result<std::vector<float>>::ok(std::move(batch[0]));
}

security::Result<std::vector<std::vector<float>>> OpenAIEmbeddings::embed_batch(
    const std::vector<std::string>& texts
) {
    if (texts.empty()) {
        return security::Result<std::vector<std::vector<float>>>::ok({});
    }
    
    // Build request
    json request_body = {
        {"model", config_.model},
        {"input", texts}
    };
    
    std::string body = request_body.dump();
    std::string auth_header = "Authorization: Bearer " + api_key_.to_string();
    std::string url = config_.base_url + "/embeddings";
    
    // Use CURL for request
    CURL* curl = curl_easy_init();
    if (!curl) {
        return security::Result<std::vector<std::vector<float>>>::err("Failed to initialize CURL");
    }
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header.c_str());
    
    std::string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, secure_embedding_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 30000);

    #if defined(_WIN32)
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #elif defined(__APPLE__)
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/cert.pem");
    #else
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
    #endif

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return security::Result<std::vector<std::vector<float>>>::err(curl_easy_strerror(res));
    }
    
    if (http_code != 200) {
        return security::Result<std::vector<std::vector<float>>>::err("HTTP " + std::to_string(http_code));
    }
    
    // Parse response
    try {
        json response_json = json::parse(response);
        std::vector<std::vector<float>> embeddings;
        
        for (const auto& item : response_json["data"]) {
            std::vector<float> embedding;
            for (const auto& val : item["embedding"]) {
                embedding.push_back(val.get<float>());
            }
            embeddings.push_back(std::move(embedding));
        }
        
        return security::Result<std::vector<std::vector<float>>>::ok(std::move(embeddings));
    } catch (const std::exception& e) {
        return security::Result<std::vector<std::vector<float>>>::err("Failed to parse response: " + std::string(e.what()));
    }
}

// LOCALEMBEDDINGS Implementation - determinsitic hash embedding (v0.1)
// v0.2 TODO: ONNX Runtime with all-MiniLM-L6-v2
class LocalEmbeddings::Impl {
public:
    Impl(const Config& cfg) : config_(cfg) {
        dimension_ = cfg.dimension > 0 ? cfg.dimension : 384;
    }
    
    security::Result<std::vector<float>> embed(const std::string& text) {
        if (text.empty()) {
            return security::Result<std::vector<float>>::ok(std::vector<float>(dimension_, 0.0f));
        }

        std::vector<float> embedding(dimension_, 0.0f);

        // Lowercase + tokenize by whitespace/punct
        std::string lower = text;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        std::vector<std::string> words;
        std::string cur;
        for (char c : lower) {
            if (std::isalnum((unsigned char)c)) {
                cur += c;
            } else {
                if (!cur.empty()) { words.push_back(cur); cur.clear(); }
            }
        }
        if (!cur.empty()) words.push_back(cur);

        if (words.empty()) {
            words.push_back(lower);
        }
        // Hash-trick: each word contributes to 2 positions + bigram
        std::hash<std::string> hasher;
        for (size_t wi = 0; wi < words.size(); ++wi) {
            const auto& w = words[wi];
            size_t h1 = hasher(w);
            size_t h2 = hasher(w + "_salt");

            embedding[h1 % dimension_] += 1.0f;
            embedding[h2 % dimension_] += 0.5f;

            // bigrams for better similarity
            if (wi + 1 < words.size()) {
                std::string bigram = w + "_" + words[wi+1];
                size_t hb = hasher(bigram);
                embedding[hb % dimension_] += 0.8f;
            }
        }
        
        // Normalize to unit length fo cosine similarity
        float norm = 0.0f;
        for (float v : embedding) norm += v * v;
        norm = std::sqrt(norm);
        if (norm > 1e-6f) {
            for (float& v : embedding) v /= norm;
        }
        
        return security::Result<std::vector<float>>::ok(std::move(embedding));
    }
    
    size_t dimension() const { return dimension_; }
    
private:
    Config config_;
    size_t dimension_ = 384;
};

security::Result<std::unique_ptr<LocalEmbeddings>> LocalEmbeddings::create(Config cfg) {
    auto embeddings = std::unique_ptr<LocalEmbeddings>(new LocalEmbeddings());
    embeddings->impl_ = std::make_unique<Impl>(cfg);
    embeddings->dimension_ = cfg.dimension;
    
    return security::Result<std::unique_ptr<LocalEmbeddings>>::ok(std::move(embeddings));
}

LocalEmbeddings::~LocalEmbeddings() = default;

security::Result<std::vector<float>> LocalEmbeddings::embed(const std::string& text) {
    return impl_->embed(text);
}

security::Result<std::vector<std::vector<float>>> LocalEmbeddings::embed_batch(
    const std::vector<std::string>& texts
) {
    std::vector<std::vector<float>> embeddings;
    for (const auto& text : texts) {
        auto result = embed(text);
        if (result.is_err()) {
            return security::Result<std::vector<std::vector<float>>>::err(result.error());
        }
        embeddings.push_back(std::move(result.value()));
    }
    return security::Result<std::vector<std::vector<float>>>::ok(std::move(embeddings));
}

} // namespace chaincpp::rag