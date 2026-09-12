#include "chaincpp/models/llm.hpp"
#include "chaincpp/security/secrets.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <llama.h>
#include <ggml.h>

#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <random>
#include <cmath>
#include <limits>
#include <sodium.h>

using json = nlohmann::json;

namespace chaincpp::models {

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

    // safe exception boundaries on downstream callback
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

    // Safe allocation directly via standard protected constructor
    auto chat = std::unique_ptr<OpenAIChat>(new OpenAIChat());
    chat->api_key_ = std::move(key_res.value());
    chat->config_ = std::move(cfg);
    return security::Result<std::unique_ptr<OpenAIChat>>::ok(std::move(chat));
}
OpenAIChat::~OpenAIChat() = default;

// Overload 1: Satisfies the pure virtual interface contract for BaseLLM
security::Result<std::string> OpenAIChat::generate(const std::vector<Message>& messages, const ModelConfig& config) {
    json body = {
        {"model", config.model_name.empty()? "gpt-4o-mini" : config.model_name},
        {"temperature", config.temperature},
        {"max_tokens", config.max_tokens}
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

    std::string auth;
    api_key_.with_c_str([&](const char* raw){
        auth = "Authorization: Bearer " + std::string(raw);
    });
    auto res = execute_secure_request(config_.base_url + "/chat/completions", body.dump(), auth, config.timeout);
    sodium_memzero(auth.data(), auth.size()); // Zero sensitive memory immediately after use
    return res;
}

// Overload 2: Satisfies localized streaming API execution loop
security::Result<std::string> OpenAIChat::generate(const std::vector<Message>& messages, StreamCallback stream_cb) {
    ModelConfig default_cfg;
    default_cfg.model_name = "gpt-4o-mini";
    if (stream_cb) {
        return stream_generate(messages, stream_cb, default_cfg).is_ok() 
            ? security::Result<std::string>::ok("[Streaming Completed]")
            : security::Result<std::string>::err("Streaming failed");
    }
    return generate(messages, default_cfg);
}

// Dynamic config assignment and clean return mapping logic
security::Result<void> OpenAIChat::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    json body = {
        {"model", config.model_name.empty()? "gpt-4o-mini" : config.model_name},
        {"max_tokens", config.max_tokens},
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

    std::string auth;
    api_key_.with_c_str([&](const char* raw){
        auth = "Authorization: Bearer " + std::string(raw);
    });
    auto res = execute_secure_request(config_.base_url + "/chat/completions", body.dump(), auth, config.timeout, &on_chunk);
    sodium_memzero(auth.data(), auth.size()); // Zero sensitive memory immediately after use
    if (res.is_err()) return security::Result<void>::err(res.error());
    return security::Result<void>::ok();
}

// Anthropic Implementation

security::Result<std::unique_ptr<AnthropicChat>> AnthropicChat::create() { 
    return create(Config()); 
}
security::Result<std::unique_ptr<AnthropicChat>> AnthropicChat::create(Config cfg) {
    auto key_res = security::SecretsManager::instance().load_from_env(cfg.api_key_env_var);
    if (key_res.is_err()) return security::Result<std::unique_ptr<AnthropicChat>>::err(key_res.error());

    auto chat = std::unique_ptr<AnthropicChat>(new AnthropicChat());
    chat->api_key_ = std::move(key_res.value());
    chat->config_ = std::move(cfg);
    return security::Result<std::unique_ptr<AnthropicChat>>::ok(std::move(chat));
}

AnthropicChat::~AnthropicChat() = default;

security::Result<std::string> AnthropicChat::generate(const std::vector<Message>& messages, const ModelConfig& config) {
    std::string model_to_use = config.model_name.empty()? "claude-3-5-sonnet-20241022" : config.model_name;
    if (model_to_use.rfind("gpt",0)==0 || model_to_use.rfind("o1",0)==0) {
        model_to_use = "claude-3-5-sonnet-20241022";
    }

    json body = {
        {"model", model_to_use},
        {"max_tokens", config.max_tokens>0? config.max_tokens : 4096},
        {"temperature", config.temperature}
    };

    std::string system_prompt;
    json json_messages = json::array();
    for (const auto& msg : messages) {
        if (msg.role == Message::Role::SYSTEM) system_prompt = msg.content;
        else {
            std::string role_str = (msg.role == Message::Role::ASSISTANT)? "assistant" : "user";
            json_messages.push_back({{"role", role_str}, {"content", msg.content}});
        }
    }
    if (!system_prompt.empty()) body["system"] = system_prompt;
    body["messages"] = json_messages;

    std::string auth_header;
    api_key_.with_c_str([&](const char* raw){ auth_header = "x-api-key: " + std::string(raw); });

    auto timeout = config.timeout.count()>0? config.timeout : std::chrono::seconds(30);
    auto res = execute_secure_request(config_.base_url + "/v1/messages", body.dump(), auth_header, timeout);
    sodium_memzero(auth_header.data(), auth_header.size());

    if (res.is_err()) return res;
    try {
        auto parsed = json::parse(res.value());
        return security::Result<std::string>::ok(parsed["content"][0]["text"].get<std::string>());
    } catch (...) {
        return security::Result<std::string>::err("Failed parsing Anthropic response");
    }
}

security::Result<std::string> AnthropicChat::generate(const std::vector<Message>& messages, StreamCallback stream_cb) {
    ModelConfig cfg;
    cfg.model_name = "claude-3-5-sonnet-20241022";
    cfg.max_tokens = 4096;
    cfg.temperature = 0.7f;
    cfg.timeout = std::chrono::seconds(30);

    json body = {
        {"model", cfg.model_name},
        {"max_tokens", cfg.max_tokens},
        {"temperature", cfg.temperature}
    };
    std::string system_prompt;
    json json_messages = json::array();
    for (const auto& msg : messages) {
        if (msg.role == Message::Role::SYSTEM) system_prompt = msg.content;
        else {
            std::string role_str = (msg.role == Message::Role::ASSISTANT)? "assistant" : "user";
            json_messages.push_back({{"role", role_str}, {"content", msg.content}});
        }
    }
    if (!system_prompt.empty()) body["system"] = system_prompt;
    body["messages"] = json_messages;

    std::string auth_header;
    api_key_.with_c_str([&](const char* raw){ auth_header = "x-api-key: " + std::string(raw); });

    auto res = execute_secure_request(config_.base_url + "/v1/messages", body.dump(), auth_header, cfg.timeout, stream_cb? &stream_cb : nullptr);
    sodium_memzero(auth_header.data(), auth_header.size());

    if (res.is_err()) return res;
    try {
        auto parsed = json::parse(res.value());
        if (stream_cb) return security::Result<std::string>::ok("[Streaming]");
        return security::Result<std::string>::ok(parsed["content"][0]["text"].get<std::string>());
    } catch (...) {
        return security::Result<std::string>::err("Failed parsing Anthropic response");
    }
}

security::Result<void> AnthropicChat::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    auto result = generate(messages, config.model_name.empty()? ModelConfig{} : config);
    if (result.is_ok()) {
        if (on_chunk) {
            on_chunk(result.value());
        }
        return security::Result<void>::ok();
    }
    return security::Result<void>::err(result.error());
}

// LocalLLM Engine Private Implementation
static void ensure_llama_backend_init() {
    // Global thread-safe backend allocation fence
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        llama_backend_init();
        // Free at process exit, not leak per-instance
        std::atexit([]() { llama_backend_free(); });
    });
}

class LocalLLM::Impl {
public:
    Impl(const Config& cfg) : config_(cfg) {
        // Initialize llama.cpp backend blobal resources exactly once
        ensure_llama_backend_init();

        // Configure hardware load properties matching user constraints
        llama_model_params model_params = llama_model_default_params();
        model_params.n_gpu_layers = config_.gpu_layers;
        model_params.use_mmap = config_.use_mmap;
        model_params.use_mlock = config_.use_mlock;

        // Load GGUF weights from local path safely
        model_ = llama_load_model_from_file(config_.model_path.c_str(), model_params);
        if (model_) {
            llama_context_params ctx_params = llama_context_default_params();
            ctx_params.n_ctx = config_.context_size;
            ctx_params.n_batch = 512;
            ctx_params.n_threads = 4;
            ctx_ = llama_new_context_with_model(model_, ctx_params);
        }
    }

    ~Impl() {
        if (ctx_) llama_free(ctx_);
        if (model_) llama_free_model(model_);
        // Global llama_backend_free completely removed from instance destructor to fix memory corruption crashes;
    }

    bool is_ready() const { return model_ != nullptr && ctx_ != nullptr; }

    size_t count_tokens_real(const std::string& text) const {
        if (!model_ || text.empty()) return 0;
        int n = llama_tokenize(model_, text.c_str(), text.size(), nullptr, 0, true, true);
        if (n < 0) n = -n;
        if (n <= 0) return std::max(size_t(1), text.length() / 4);
        std::vector<llama_token> tmp(n);
        int n2 = llama_tokenize(model_, text.c_str(), text.size(), tmp.data(), tmp.size(), true, true);
        if (n2 < 0) return std::max(size_t(1), text.length() / 4);
        return static_cast<size_t>(n2);
    }
    
    security::Result<std::string> generate([[maybe_unused]] const std::vector<Message>& messages, const ModelConfig& config) {
        if (!is_ready()) {
            return security::Result<std::string>::err("Local engine failed: GGUF model files not loaded correctly from " + config_.model_path);
        }

        // Build a compiled text payload out of conversational message inputs
        std::string raw_prompt;
        for (const auto& msg : messages) raw_prompt += msg.content + "\n";

        // Exponential allocation expansion loop to prevent token array boundaries truncation
        std::vector<llama_token> tokens(1024);
        int n_tokens = llama_tokenize(model_, raw_prompt.c_str(), raw_prompt.size(), tokens.data(), tokens.size(), true, true);
        if (n_tokens < 0) {
            tokens.resize(-n_tokens);
            n_tokens = llama_tokenize(model_, raw_prompt.c_str(), raw_prompt.size(), tokens.data(), tokens.size(), true, true);
        }
        tokens.resize(std::max(0, n_tokens));

        if (tokens.empty()) {
            return security::Result<std::string>::ok("");
        }

        // Native autoregressive llama_decode evaluation token stream sampler loop
        struct llama_batch batch = llama_batch_get_one(tokens.data(), tokens.size());
        
        if (llama_decode(ctx_, batch) != 0) {
            return security::Result<std::string>::err("Local inference failure: Initial batch evaluation matrix sequence failed.");
        }

        // llama-sampler - 0 allocs in loop
        llama_sampler* smpl = llama_sampler_chain_init(llama_sampler_chain_default_params());
        llama_sampler_chain_add(smpl, llama_sampler_init_temp(config.temperature > 0? config.temperature : 0.7f));
        llama_sampler_chain_add(smpl, llama_sampler_init_top_p(0.95f, 1));
        llama_sampler_chain_add(smpl, llama_sampler_init_dist(0));

        std::string out;
        int max_tokens = std::min<int>(config.max_tokens > 0 ? config.max_tokens : 512, 4096);
        for (int i = 0; i < max_tokens; ++i) {
            llama_token tok = llama_sampler_sample(smpl, ctx_, -1);
            if (tok == llama_token_eos(model_)) break;
            char buf[256];
            int len = llama_token_to_piece(model_, tok, buf, sizeof(buf), 0, true);
            if (len < 0) { 
                std::vector<char> b(-len); 
                len = llama_token_to_piece(model_, tok, b.data(), b.size(), 0, true); 
                if (len > 0) out.append(b.data(), len); 
            } else if (len > 0) out.append(buf, len);
            batch = llama_batch_get_one(&tok, 1);
            if (llama_decode(ctx_, batch) != 0) break;
        }
        llama_sampler_free(smpl);
        return security::Result<std::string>::ok(std::move(out));
    }
    
private:
    Config config_;
    llama_model* model_ = nullptr;
    llama_context* ctx_ = nullptr;
};

security::Result<std::unique_ptr<LocalLLM>> LocalLLM::create(Config cfg) {
    auto llm = std::unique_ptr<LocalLLM>(new LocalLLM());
    llm->impl_ = std::make_unique<Impl>(cfg);
    if (!llm->impl_->is_ready()) {
        return security::Result<std::unique_ptr<LocalLLM>>::err("Failed to load GGUF model");
    }
    return security::Result<std::unique_ptr<LocalLLM>>::ok(std::move(llm));
}

LocalLLM::~LocalLLM() = default;

// Satisfies the pure virtual interface contract for BaseLLM
security::Result<std::string> LocalLLM::generate(const std::vector<Message>& messages, const ModelConfig& config) {
    // Forward variables directly to the implementation unit execution chain
    return impl_->generate(messages, config);
}

// Satisfies the specialized signature pattern (Line 186 in llm.hpp)
security::Result<std::string> LocalLLM::generate(const std::vector<Message>& messages, StreamCallback stream_cb) {
    ModelConfig default_config;
    default_config.max_tokens = 512;
    std::string result_str;
    std::string error_msg;
    bool success = false;

    // Route safely through your verified execute_in_process Sandbox method loop
    auto run_res = security::Sandbox::execute_in_process([&]() -> int {
        auto gen_res = impl_->generate(messages, default_config);
        if (gen_res.is_ok()) {
            result_str = gen_res.value();
            if (stream_cb) stream_cb(result_str);
            success = true;
            return 0;
        } else {
            error_msg = gen_res.error();
            return 1;
        }
    }, security::SecurityLimits::strict());

    if (run_res.is_err()) return security::Result<std::string>::err(run_res.error());
    if (!success) return security::Result<std::string>::err(error_msg);
    return security::Result<std::string>::ok(std::move(result_str));
}

security::Result<void> LocalLLM::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    // Explicitly pass nullptr to select overload 2 unambiguously
    auto result = generate(messages, nullptr);
    if (result.is_ok()) {
        if (on_chunk) on_chunk(result.value());
        return security::Result<void>::ok();
    }
    return security::Result<void>::err(result.error());
}

// Implementation of count tokens
size_t OpenAIChat::count_tokens(const std::string& text) const {
    if (text.empty()) return 0;
    return std::max(size_t(1), text.length() / 4); // Rough heuristic: 1 token 4 characters
}

size_t AnthropicChat::count_tokens(const std::string& text) const {
    if (text.empty()) return 0;
    return std::max(size_t(1), text.length() / 4); // Rough heuristic: 1 token 4 characters
}

size_t LocalLLM::count_tokens(const std::string& text) const {
    if (!impl_) return std::max(size_t(1), text.length() / 4);
    return impl_->count_tokens_real(text);
}

}