#include "chaincpp/models/llm.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <thread>
#include <atomic>

using json = nlohmann::json;

namespace chaincpp::models {

// Message helpers
Message Message::system(std::string content) {
    return {Role::SYSTEM, std::move(content), {}};
}

Message Message::user(std::string content) {
    return {Role::USER, std::move(content), {}};
}

Message Message::assistant(std::string content) {
    return {Role::ASSISTANT, std::move(content), {}};
}

Message Message::tool(std::string content, std::string name) {
    return {Role::TOOL, std::move(content), std::move(name)};
}

// ============================================================================
// CURL Helpers
// ============================================================================

struct CurlGlobalInit {
    CurlGlobalInit() { curl_global_init(CURL_GLOBAL_ALL); }
    ~CurlGlobalInit() { curl_global_cleanup(); }
};

static CurlGlobalInit curl_init;

struct WriteData {
    std::string* buffer = nullptr;
    StreamCallback* stream_callback = nullptr;
    std::atomic<bool>* cancelled = nullptr;
};

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    auto* data = static_cast<WriteData*>(userp);
    
    if (data->stream_callback && data->stream_callback) {
        std::string_view chunk(static_cast<char*>(contents), total_size);
        // Note: In production, you'd handle the Result here
        (*data->stream_callback)(chunk);
    }
    
    if (data->buffer) {
        data->buffer->append(static_cast<char*>(contents), total_size);
    }
    
    return total_size;
}

static security::Result<std::string> curl_request(
    const std::string& url,
    const std::string& body,
    const std::string& auth_header,
    std::chrono::seconds timeout,
    StreamCallback stream_cb = nullptr
) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return security::Result<std::string>::err("Failed to initialize CURL");
    }
    
    std::string response;
    WriteData write_data;
    write_data.buffer = &response;
    if (stream_cb) {
        write_data.stream_callback = &stream_cb;
    }
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header.c_str());
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout.count());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return security::Result<std::string>::err(curl_easy_strerror(res));
    }
    
    if (http_code != 200) {
        return security::Result<std::string>::err("HTTP " + std::to_string(http_code) + ": " + response);
    }
    
    return security::Result<std::string>::ok(std::move(response));
}

// ============================================================================
// OpenAI Implementation
// ============================================================================

security::Result<std::unique_ptr<OpenAIChat>> OpenAIChat::create(Config cfg) {
    auto key_result = security::SecretsManager::instance().load_from_env(cfg.api_key_env_var);
    if (key_result.is_err()) {
        return security::Result<std::unique_ptr<OpenAIChat>>::err(key_result.error());
    }
    
    auto chat = std::unique_ptr<OpenAIChat>(new OpenAIChat());
    chat->api_key_ = std::move(key_result.value());
    chat->config_ = std::move(cfg);
    
    return security::Result<std::unique_ptr<OpenAIChat>>::ok(std::move(chat));
}

OpenAIChat::~OpenAIChat() = default;

security::Result<std::string> OpenAIChat::generate(
    const std::vector<Message>& messages,
    const ModelConfig& config
) {
    return make_request(messages, config);
}

security::Result<void> OpenAIChat::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    auto result = make_request(messages, config, on_chunk);
    if (result.is_err()) {
        return security::Result<void>::err(result.error());
    }
    return security::Result<void>::ok();
}

security::Result<std::string> OpenAIChat::make_request(
    const std::vector<Message>& messages,
    const ModelConfig& config,
    StreamCallback on_chunk
) {
    // Build messages JSON
    json messages_array = json::array();
    for (const auto& msg : messages) {
        std::string role_str;
        switch (msg.role) {
            case Message::Role::SYSTEM: role_str = "system"; break;
            case Message::Role::USER: role_str = "user"; break;
            case Message::Role::ASSISTANT: role_str = "assistant"; break;
            case Message::Role::TOOL: role_str = "tool"; break;
        }
        
        json msg_obj = {{"role", role_str}, {"content", msg.content}};
        if (!msg.name.empty()) {
            msg_obj["name"] = msg.name;
        }
        messages_array.push_back(msg_obj);
    }
    
    json request_body = {
        {"model", config.model_name},
        {"messages", messages_array},
        {"temperature", config.temperature},
        {"top_p", config.top_p},
        {"max_tokens", config.max_tokens},
        {"stream", on_chunk != nullptr}
    };
    
    std::string body = request_body.dump();
    std::string auth_header = "Authorization: Bearer " + api_key_.to_string();
    
    if (!config_.organization.empty()) {
        auth_header += "\nOpenAI-Organization: " + config_.organization;
    }
    
    std::string url = config_.base_url + "/chat/completions";
    
    auto response = curl_request(url, body, auth_header, config.timeout, on_chunk);
    if (response.is_err()) {
        return security::Result<std::string>::err(response.error());
    }
    
    if (on_chunk) {
        return security::Result<std::string>::ok("");
    }
    
    json response_json = json::parse(response.value());
    return security::Result<std::string>::ok(
        response_json["choices"][0]["message"]["content"].get<std::string>()
    );
}

size_t OpenAIChat::count_tokens(const std::string& text) const {
    // Simple approximation: ~4 chars per token for English
    return text.length() / 4;
}

// ============================================================================
// Anthropic Implementation
// ============================================================================

security::Result<std::unique_ptr<AnthropicChat>> AnthropicChat::create(Config cfg) {
    auto key_result = security::SecretsManager::instance().load_from_env(cfg.api_key_env_var);
    if (key_result.is_err()) {
        return security::Result<std::unique_ptr<AnthropicChat>>::err(key_result.error());
    }
    
    auto chat = std::unique_ptr<AnthropicChat>(new AnthropicChat());
    chat->api_key_ = std::move(key_result.value());
    chat->config_ = std::move(cfg);
    
    return security::Result<std::unique_ptr<AnthropicChat>>::ok(std::move(chat));
}

AnthropicChat::~AnthropicChat() = default;

security::Result<std::string> AnthropicChat::generate(
    const std::vector<Message>& messages,
    const ModelConfig& config
) {
    // Find system message
    std::string system_prompt;
    std::string user_prompt;
    
    for (const auto& msg : messages) {
        if (msg.role == Message::Role::SYSTEM) {
            system_prompt = msg.content;
        } else if (msg.role == Message::Role::USER) {
            user_prompt = msg.content;
        }
    }
    
    json request_body = {
        {"model", config.model_name},
        {"max_tokens", config.max_tokens},
        {"messages", json::array({{{"role", "user"}, {"content", user_prompt}}})}
    };
    
    if (!system_prompt.empty()) {
        request_body["system"] = system_prompt;
    }
    
    std::string body = request_body.dump();
    std::string auth_header = "x-api-key: " + api_key_.to_string();
    std::string url = config_.base_url + "/messages";
    
    auto response = curl_request(url, body, auth_header, config.timeout);
    if (response.is_err()) {
        return security::Result<std::string>::err(response.error());
    }
    
    json response_json = json::parse(response.value());
    return security::Result<std::string>::ok(
        response_json["content"][0]["text"].get<std::string>()
    );
}

security::Result<void> AnthropicChat::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    // Similar to generate but with streaming
    // Simplified for now
    auto result = generate(messages, config);
    if (result.is_ok()) {
        on_chunk(result.value());
    }
    return result.is_ok() ? security::Result<void>::ok() 
                          : security::Result<void>::err(result.error());
}

size_t AnthropicChat::count_tokens(const std::string& text) const {
    return text.length() / 4;
}

// ============================================================================
// LocalLLM Implementation (stub - requires llama.cpp integration)
// ============================================================================

class LocalLLM::Impl {
public:
    Impl(const LocalLLM::Config& cfg) : config_(cfg) {}
    
    security::Result<std::string> generate(const std::vector<Message>& messages, const ModelConfig& config) {
        // Stub - will integrate with llama.cpp
        return security::Result<std::string>::ok("Local LLM response (placeholder)");
    }
    
private:
    LocalLLM::Config config_;
};

security::Result<std::unique_ptr<LocalLLM>> LocalLLM::create(Config cfg) {
    auto llm = std::unique_ptr<LocalLLM>(new LocalLLM());
    llm->impl_ = std::make_unique<Impl>(cfg);
    return security::Result<std::unique_ptr<LocalLLM>>::ok(std::move(llm));
}

LocalLLM::~LocalLLM() = default;

security::Result<std::string> LocalLLM::generate(
    const std::vector<Message>& messages,
    const ModelConfig& config
) {
    return security::Sandbox::execute_safe_result<std::string>(
        [this, &messages, &config]() {
            return impl_->generate(messages, config);
        },
        security::SecurityLimits::strict()
    );
}

security::Result<void> LocalLLM::stream_generate(
    const std::vector<Message>& messages,
    StreamCallback on_chunk,
    const ModelConfig& config
) {
    auto result = generate(messages, config);
    if (result.is_ok()) {
        on_chunk(result.value());
        return security::Result<void>::ok();
    }
    return security::Result<void>::err(result.error());
}

size_t LocalLLM::count_tokens(const std::string& text) const {
    return text.length() / 4;
}

} // namespace chaincpp::models