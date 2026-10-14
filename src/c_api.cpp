#include "chaincpp/c_api.h"
#include "chaincpp/models/llm.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <cstdlib>

// Internal implementations
struct ChainCpp_LLM {
    std::unique_ptr<chaincpp::models::LLM> impl;
};

struct ChainCpp_Messages {
    std::vector<chaincpp::models::Message> msgs;
};

static thread_local std::string g_last_error;

extern "C" {

const char* chaincpp_last_error_message() {
    return g_last_error.c_str();
}

int chaincpp_version_major() { return CHAINCPP_VERSION_MAJOR; }
int chaincpp_version_minor() { return CHAINCPP_VERSION_MINOR; }
int chaincpp_version_patch() { return CHAINCPP_VERSION_PATCH; }
const char* chaincpp_version_string() { 
    static const char* v = "0.1.0";
    return v;
}

static const char* alloc_c_string(const std::string& s) {
    char* out = (char*)malloc(s.size() + 1);
    if (!out) return nullptr;
    memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

void chaincpp_string_free(const char* str) {
    if (str) free((void*)str);
}

chaincpp_messages_t chaincpp_messages_create() {
    return new ChainCpp_Messages();
}

void chaincpp_messages_destroy(chaincpp_messages_t msgs) {
    delete msgs;
}

chaincpp_error_t chaincpp_messages_add(chaincpp_messages_t msgs, const char* role, const char* content) {
    if (!msgs || !role || !content) return CHAINCPP_ERR_INVALID_ARG;
    chaincpp::models::Message m;
    std::string r(role);
    if (r == "system") m.role = chaincpp::models::Role::System;
    else if (r == "assistant") m.role = chaincpp::models::Role::Assistant;
    else m.role = chaincpp::models::Role::User;
    m.content = content;
    msgs->msgs.push_back(std::move(m));
    return CHAINCPP_OK;
}

chaincpp_llm_t chaincpp_llm_create(const chaincpp_llm_config_t* config, chaincpp_error_t* error_out) {
    if (!config) {
        if (error_out) *error_out = CHAINCPP_ERR_INVALID_ARG;
        g_last_error = "config is null";
        return nullptr;
    }
    try {
        auto wrapper = new ChainCpp_LLM();

        if (config->type == CHAINCPP_LLM_LOCAL) {
            if (!config->model_path) {
                delete wrapper;
                if (error_out) *error_out = CHAINCPP_ERR_INVALID_ARG;
                g_last_error = "model_path required for LOCAL";
                return nullptr;
            }
            auto local = std::make_unique<chaincpp::models::LocalLLM>();
            auto res = local->load_model(config->model_path);
            if (res.is_err()) {
                delete wrapper;
                if (error_out) *error_out = CHAINCPP_ERR_NOT_FOUND;
                g_last_error = res.error();
                return nullptr;
            }
            wrapper->impl = std::move(local);
        } else if (config->type == CHAINCPP_LLM_OPENAI) {
            auto remote = std::make_unique<chaincpp::models::OpenAIChat>();
            if (config->api_key) remote->set_api_key(config->api_key);
            if (config->model_name) remote->set_model(config->model_name);
            if (config->base_url) remote->set_base_url(config->base_url);
            wrapper->impl = std::move(remote);
        } else {
            // Fallback to OpenAI-compatible for Anthropic etc if class not present
            auto remote = std::make_unique<chaincpp::models::OpenAIChat>();
            if (config->api_key) remote->set_api_key(config->api_key);
            if (config->model_name) remote->set_model(config->model_name);
            wrapper->impl = std::move(remote);
        }
        if (error_out) *error_out = CHAINCPP_OK;
        return wrapper;
    } catch (const std::exception& e) {
        if (error_out) *error_out = CHAINCPP_ERR_RUNTIME;
        g_last_error = e.what();
        return nullptr;
    }
}

void chaincpp_llm_destroy(chaincpp_llm_t llm) {
    delete llm;
}

const char* chaincpp_llm_generate_simple(chaincpp_llm_t llm, const char* prompt) {
    if (!llm || !prompt) {
        g_last_error = "llm or prompt null";
        return nullptr;
    }
    try {
        std::vector<chaincpp::models::Message> msgs;
        msgs.push_back({chaincpp::models::Role::User, std::string(prompt)});
        auto res = llm->impl->generate(msgs);
        if (res.is_err()) {
            g_last_error = res.error();
            return nullptr;
        }
        return alloc_c_string(res.value());
    } catch (const std::exception& e) {
        g_last_error = e.what();
        return nullptr;
    }
}

const char* chaincpp_llm_generate_chat(chaincpp_llm_t llm, chaincpp_messages_t msgs) {
    if (!llm || !msgs) {
        g_last_error = "llm or msgs null";
        return nullptr;
    }
    try {
        auto res = llm->impl->generate(msgs->msgs);
        if (res.is_err()) {
            g_last_error = res.error();
            return nullptr;
        }
        return alloc_c_string(res.value());
    } catch (const std::exception& e) {
        g_last_error = e.what();
        return nullptr;
    }
}

} // extern C
