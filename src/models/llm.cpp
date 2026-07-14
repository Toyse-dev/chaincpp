#include "chaincpp/models/llm.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <llama.h>
#include <ggml.h>

#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <regex>
#include <thread>
#include <atomic>

using json = nlohmann::json;

namespace chaincpp::models {

// Core Heuristics and Utilities

// Heuristic fallback token tracking to prevent zero-division rate limits
size_t count_tokens(const std::string& text) {
    if (text.empty()) return 0;
    // v0.1 heuristic fallback: prevent truncation to 0 for single characters
    return std::max(size_t(1), text.length() / 4);  // Rough heuristic: 1 token ~ 4 characters
}

// Message RAII Installation Blocks
Message Message::system(std::string content) { return {Role::SYSTEM, std::move(content), {}}; }
Message Message::user(std::string content) { return {Role::USER, std::move(content), {}}; }
Message Message::assistant(std::string content) { return {Role::ASSISTANT, std::move(content), {}}; }
Message Message::tool(std::string content, std::string name) { return {Role::TOOL, std::move(content), std::move(name)}; }

// Network Layer (Hardened cURL Engine)

struct CurlGlobalInit {
    CurlGlobalInit() { curl_global_init(CURL_GLOBAL_ALL); }
    ~CurlGlobalInit() { curl_global_cleanup(); }
};
static CurlGlobalInit curl_init_guard;

// Safe payload wrapper structure
struct NetworkPayload {
    std::string response_buffer;
    const StreamCallback* stream_callback = nullptr;
};

// Guarded Network write callback with exception isolation
size_t secure_write_callback(void* contents, size_t size, size_t nmemb, void* user_data) {
    size_t total_size = size * nmemb;
    auto* payload = static_cast<NetworkPayload*>(user_data);
    if (!payload) return 0;

    std::string_view chunk(static_cast<const char*>(contents), total_size);

    // Fix bug 2: safe exception boundaries on downstream callback
    if (payload->stream_callback && *(payload->stream_callback)) {
        try {
            (*(payload->stream_callback))(chunk);
        } catch (...) {
            return 0; // Aborts cURL transfer safely with CURLE_WRITE_ERROR
        }
    }

    payload->response_buffer.append(chunk);
    return total_size;
}

// Consolidated Hardened TLS Network Requester
static security::Result<std::string> execute_secure_request(
    const std::string& url,
    const std::string& body,
    const std::string& auth_header,
    std::chrono::seconds timeout,
    const StreamCallback* stream_cb = nullptr
) {
    CURL* curl = curl_easy_init();
    if (!curl) return security::Result<std::string>::err("Failed to initialize CURL");

    NetworkPayload payload;
    payload.stream_callback = stream_cb; // Safely references high-level pointer lifespan

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header.c_str());
    headers = curl_slist_append(headers, "HTTP-Referer: https://github.com");
    headers = curl_slist_append(headers, "X-Title: chaincpp-framework");
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, secure_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(timeout.count()));
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    
    #if defined(_WIN32) 
        // Use windows certificate store
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #elif defined(__APPLE__)
        // Use macOS Keychain
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/cert.pem");
    #else
        // Linux - use system CA bundle
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
    #endif

    // Standard Windows-MinGW safety flags
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return security::Result<std::string>::err(curl_easy_strerror(res));
    if (http_code != 200) return security::Result<std::string>::err("HTTP " + std::to_string(http_code) + ": " + payload.response_buffer);
    
    return security::Result<std::string>::ok(std::move(payload.response_buffer));
}

// OpenAI Implementation

security::Result<std::unique_ptr<OpenAIChat>> OpenAIChat::create() { return create(Config()); }
security::Result<std::unique_ptr<OpenAIChat>> OpenAIChat::create(Config cfg) {
    auto key_res = security::SecretsManager::instance().load_from_env(cfg.api_key_env_var);
    if (key_res.is_err()) return security::Result<std::unique_ptr<OpenAIChat>>::err(key_res.error());

    // Allocate using a custom internal override factory to bypass hidden visibility restrictions
    struct MakeWritableOpenAI : public OpenAIChat { MakeWritableOpenAI() : OpenAIChat() {} };
    auto chat = std::make_unique<MakeWritableOpenAI>();

    chat->api_key_ = std::move(key_res.value());
    chat->config_ = std::move(cfg);
    return security::Result<std::unique_ptr<OpenAIChat>>::ok(std::move(chat));
}

OpenAIChat::~OpenAIChat() = default;

// Overload 1: Satisfies the pure virtual interface contract for BaseLLM
security::Result<std::string> OpenAIChat::generate(const std::vector<Message>& messages, const ModelConfig& config) {
    (void)config; // Unused in this overload
    return generate(messages, nullptr);
}

// Overload 2: Satisfies your localized streaming API execution loop
security::Result<std::string> OpenAIChat::generate(const std::vector<Message>& messages, StreamCallback stream_cb) {
    json body = {
        {"model", "gpt-4o"},
        {"temperature", 0.7}
    };

    json json_messages = json::array();
    for (const auto& msg : messages) {
        std::string role_str;
        switch (msg.role) {
            case Message::Role::SYSTEM: role_str = "system"; break;
            case Message::Role::USER: role_str = "user"; break;
            case Message::Role::ASSISTANT: role_str = "assistant"; break;
            case Message::Role::TOOL: role_str = "tool"; break;
        }
        json_messages.push_back({{"role", role_str}, {"content", msg.content}});
    }
    body["messages"] = json_messages;
    if (stream_cb) body["stream"] = true;

    std::string auth = "Authorization: Bearer " + api_key_.to_string();
    auto res = execute_secure_request("https://openai.com", body.dump(), auth, std::chrono::seconds(30), stream_cb ? &stream_cb : nullptr);
    if (res.is_err()) return res;

    if (stream_cb) return security::Result<std::string>::ok("[Streaming Completed]");

    try {
        auto parsed = json::parse(res.value());
        return security::Result<std::string>::ok(parsed["choices"][0]["message"]["content"].get<std::string>());
    } catch (...) {
        return security::Result<std::string>::err("Failed parsing OpenAI raw JSON packet payload");
    }
}

security::Result<void> OpenAIChat::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    json body = {
        {"model", config.model_name},
        {"temperature", config.temperature},
        {"stream", true}
    };

    json json_messages = json::array();
    for (const auto& msg : messages) {
        std::string role_str;
        switch (msg.role) {
            case Message::Role::SYSTEM: role_str = "system"; break;
            case Message::Role::USER: role_str = "user"; break;
            case Message::Role::ASSISTANT: role_str = "assistant"; break;
            case Message::Role::TOOL: role_str = "tool"; break;
        }
        json_messages.push_back({{"role", role_str}, {"content", msg.content}});
    }
    body["messages"] = json_messages;

    std::string auth = "Authorization: Bearer " + api_key_.to_string();
    auto res = execute_secure_request(config_.base_url + "/chat/completions", body.dump(), auth, config.timeout, &on_chunk);
    
    if (res.is_err()) return security::Result<void>::err(res.error());
    return security::Result<void>::ok();
}


// Anthropic Implementation

security::Result<std::unique_ptr<AnthropicChat>> AnthropicChat::create() { return create(Config()); }
security::Result<std::unique_ptr<AnthropicChat>> AnthropicChat::create(Config cfg) {
    auto key_res = security::SecretsManager::instance().load_from_env(cfg.api_key_env_var);
    if (key_res.is_err()) return security::Result<std::unique_ptr<AnthropicChat>>::err(key_res.error());

    // Fix: Bypasses the abstract class allocation restriction safely
    struct MakeWritableAnthropic : public AnthropicChat { MakeWritableAnthropic() : AnthropicChat() {} };
    auto chat = std::make_unique<MakeWritableAnthropic>();

    chat->api_key_ = std::move(key_res.value());
    chat->config_ = std::move(cfg);
    return security::Result<std::unique_ptr<AnthropicChat>>::ok(std::move(chat));
}

AnthropicChat::~AnthropicChat() = default;

// Overload 1: Satisfies the pure virtual interface contract for BaseLLM (Line 57)
security::Result<std::string> AnthropicChat::generate(const std::vector<Message>& messages, const ModelConfig& config) {
    (void)config;
    return generate(messages, nullptr);
}

// Overload 2: Satisfies your localized streaming API execution loop (Line 124)
security::Result<std::string> AnthropicChat::generate(const std::vector<Message>& messages, StreamCallback stream_cb) {
    json body = {
        {"model", "gpt-4o"},
        {"max_tokens", 4096},
        {"temperature", 0.7}
    };

    // Fix Bug 3: Modern full multi-turn conversation array compilation tracking
    std::string system_prompt = "";
    json json_messages = json::array();

    for (const auto& msg : messages) {
        if (msg.role == Message::Role::SYSTEM) {
            system_prompt = msg.content; // Anthropic passes system context as a top-level flag
        } else {
            std::string role_str = (msg.role == Message::Role::ASSISTANT) ? "assistant" : "user";
            json_messages.push_back({{"role", role_str}, {"content", msg.content}});
        }
    }

    if (!system_prompt.empty()) body["system"] = system_prompt;
    body["messages"] = json_messages;

    std::string auth = "X-API-Key: " + api_key_.to_string(); // Anthropic custom header

    auto res = execute_secure_request("https://anthropic.com", body.dump(), auth, std::chrono::seconds(30), stream_cb ? &stream_cb : nullptr);
    if (res.is_err()) return res;
    
    try {
        auto parsed = json::parse(res.value());
        return security::Result<std::string>::ok(parsed["content"][0]["text"].get<std::string>());
    } catch (...) {
        return security::Result<std::string>::err("Failed parsing Anthropic payload response structures");
    }
}

security::Result<void> AnthropicChat::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    (void)config; 
    auto result = generate(messages, on_chunk);
    if (result.is_ok()) return security::Result<void>::ok();
    return security::Result<void>::err(result.error());
}

// LocalLLM Implementation (Stub ready for llama.cpp integration)

class LocalLLM::Impl {
public:
    Impl(const LocalLLM::Config& cfg) : config_(cfg) {
        // Initialize llama.cpp backend blobal resources exactly once
        llama_backend_init();

        // Configure hardware load properties matching user constraints
        llama_model_params model_params = llama_model_default_params();
        model_params.n_gpu_layers = config_.gpu_layers;
        model_params.use_mmap = config_.use_mmap;
        model_params.use_mlock = config_.use_mlock;

        // Load GGUF weights from local path safely
        model_ = llama_model_load_from_file(config_.model_path.c_str(), model_params);
        if (model_) {
            llama_context_params ctx_params = llama_context_default_params();
            ctx_params.n_ctx = config_.context_size;
            ctx_params.n_batch = 512;
            
            ctx_ = llama_init_from_model(model_, ctx_params);
        }
    }

    ~Impl() {
        if (ctx_) {
            llama_free(ctx_);
        }
        if (model_) {
            llama_model_free(model_);
        }
        llama_backend_free();
    }

    bool is_ready() const { return model_ != nullptr && ctx_ != nullptr; }
    
    security::Result<std::string> generate([[maybe_unused]] const std::vector<Message>& messages) {
        if (is_ready()) {
            return security::Result<std::string>::err("Local engine failed: GGUF model files not loaded correctly from " + config_.model_path);
        }

        // Build a compiled text payload out of conversational message inputs
        std::string raw_prompt = "";
        for (const auto& msg : messages) {
            raw_prompt += msg.content + "\n";
        }

        // Fetch the distinct vocabulary instance from the modern engine layout
        const struct llama_vocab* vocab = llama_model_get_vocab(model_);
        if (!vocab) {
            return security::Result<std::string>::err("Local engine failure: Failed to extract model vocabulary map.");
        }

        // Tokenize input prompt string into integers matching vocabulary matrices
        std::vector<llama_token> tokens(raw_prompt.size() + 4);
        int n_tokens = llama_tokenize(vocab, raw_prompt.c_str(), raw_prompt.size(), tokens.data(), tokens.size(), true, true);
        if (n_tokens < 0) {
            return security::Result<std::string>::err("Local tokenization tracking array bounds overflow.");
        }
        tokens.resize(n_tokens);

        // Simple deterministic greedy sampling token generation loop (placeholder layout for v0.1 inference)
        std::string result_text = "Local offline execution simulation successful for text input size: " + std::to_string(n_tokens) + " tokens.";
        return security::Result<std::string>::ok(std::move(result_text));
    }
    
private:
    LocalLLM::Config config_;
    llama_model* model_ = nullptr;
    llama_context* ctx_ = nullptr;
};

security::Result<std::unique_ptr<LocalLLM>> LocalLLM::create(Config cfg) {
    struct MakeWritableLocal : public LocalLLM { MakeWritableLocal() : LocalLLM() {} };
    auto llm = std::make_unique<MakeWritableLocal>();
    llm->impl_ = std::make_unique<Impl>(cfg);
    return security::Result<std::unique_ptr<LocalLLM>>::ok(std::move(llm));
}

LocalLLM::~LocalLLM() = default;

// Overload 1: Satisfies the pure virtual interface contract for BaseLLM
security::Result<std::string> LocalLLM::generate(const std::vector<Message>& messages, const ModelConfig& config) {
    (void)config; // Unused in this overload
    return generate(messages, nullptr);
}

// Overload 2: Satisfies the specialized signature pattern (Line 186 in llm.hpp)
security::Result<std::string> LocalLLM::generate(const std::vector<Message>& messages, StreamCallback stream_cb) {
    std::string result_str;
    std::string error_msg;
    bool success = false;

    // Route safely through your verified execute_safe Sandbox method loop
    auto run_res = security::Sandbox::execute_safe([&]() -> security::Result<void> {
        auto gen_res = impl_->generate(messages);
        if (gen_res.is_ok()) {
            result_str = gen_res.value();
            success = true;
            return security::Result<void>::ok();
        } else {
            error_msg = gen_res.error();
            return security::Result<void>::err(error_msg);
        }
    }, security::SecurityLimits::strict());

    if (!run_res.is_ok()) return security::Result<std::string>::err(run_res.error());
    if (!success) return security::Result<std::string>::err(error_msg);
    
    return security::Result<std::string>::ok(std::move(result_str));
}

security::Result<void> LocalLLM::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    (void)config;
    // Explicitly pass nullptr to select overload 2 unambiguously
    auto result = generate(messages, nullptr);
    if (result.is_ok()) {
        on_chunk(result.value());
        return security::Result<void>::ok();
    }
    return security::Result<void>::err(result.error());
}

// Implementation of count tokens
size_t OpenAIChat::count_tokens(const std::string& text) const {
    if (text.empty()) return 0;
    return std::max(size_t(1), text.length() / 4); // Rough heuristic: 1 token ~ 4 characters
}

size_t AnthropicChat::count_tokens(const std::string& text) const {
    if (text.empty()) return 0;
    return std::max(size_t(1), text.length() / 4); // Rough heuristic: 1 token ~ 4 characters
}

size_t LocalLLM::count_tokens(const std::string& text) const {
    if (text.empty()) return 0;
    return std::max(size_t(1), text.length() / 4); // Rough heuristic: 1 token ~ 4 characters
}

}