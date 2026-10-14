#include "chaincpp/c_api.h"
#include "chaincpp/models/llm.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <cstdlib>

struct ChainCpp_LLM {
    std::unique_ptr<chaincpp::models::BaseLLM> impl;
};

struct ChainCpp_Messages {
    std::vector<chaincpp::models::Message> msgs;
};

static thread_local std::string g_last_error;

extern "C" {

const char* chaincpp_last_error_message() { return g_last_error.c_str(); }
int chaincpp_version_major() { return CHAINCPP_VERSION_MAJOR; }
int chaincpp_version_minor() { return CHAINCPP_VERSION_MINOR; }
int chaincpp_version_patch() { return CHAINCPP_VERSION_PATCH; }
const char* chaincpp_version_string() { static const char* v="0.1.0"; return v; }

static const char* alloc_c_string(const std::string& s) {
    char* out = (char*)malloc(s.size()+1);
    if(!out) return nullptr;
    memcpy(out, s.c_str(), s.size()+1);
    return out;
}
void chaincpp_string_free(const char* str){ if(str) free((void*)str); }

chaincpp_messages_t chaincpp_messages_create(){ return new ChainCpp_Messages(); }
void chaincpp_messages_destroy(chaincpp_messages_t m){ delete m; }

chaincpp_error_t chaincpp_messages_add(chaincpp_messages_t msgs, const char* role, const char* content){
    if(!msgs||!role||!content) return CHAINCPP_ERR_INVALID_ARG;
    std::string r(role);
    chaincpp::models::Message msg;
    if(r=="system"||r=="SYSTEM") msg = chaincpp::models::Message::system(content);
    else if(r=="assistant"||r=="ASSISTANT") msg = chaincpp::models::Message::assistant(content);
    else if(r=="tool"||r=="TOOL") msg = chaincpp::models::Message::tool(content);
    else msg = chaincpp::models::Message::user(content);
    msgs->msgs.push_back(std::move(msg));
    return CHAINCPP_OK;
}

chaincpp_llm_t chaincpp_llm_create(const chaincpp_llm_config_t* config, chaincpp_error_t* error_out){
    if(!config){ if(error_out) *error_out=CHAINCPP_ERR_INVALID_ARG; g_last_error="config null"; return nullptr; }
    try{
        auto wrapper = new ChainCpp_LLM();
        if(config->type==CHAINCPP_LLM_LOCAL){
            if(!config->model_path){ delete wrapper; if(error_out) *error_out=CHAINCPP_ERR_INVALID_ARG; g_last_error="model_path required"; return nullptr; }
            chaincpp::models::LocalLLM::Config cfg;
            cfg.model_path = config->model_path;
            cfg.context_size = 4096;
            auto res = chaincpp::models::LocalLLM::create(std::move(cfg));
            if(res.is_err()){ delete wrapper; if(error_out) *error_out=CHAINCPP_ERR_NOT_FOUND; g_last_error=res.error(); return nullptr; }
            wrapper->impl = std::move(res.value());
        } else if(config->type==CHAINCPP_LLM_ANTHROPIC){
            chaincpp::models::AnthropicChat::Config acfg;
            if(config->base_url) acfg.base_url = config->base_url;
            auto res = chaincpp::models::AnthropicChat::create(acfg);
            if(res.is_err()){ delete wrapper; if(error_out) *error_out=CHAINCPP_ERR_RUNTIME; g_last_error=res.error(); return nullptr; }
            wrapper->impl = std::move(res.value());
        } else {
            chaincpp::models::OpenAIChat::Config ocfg;
            if(config->base_url) ocfg.base_url = config->base_url;
            auto res = chaincpp::models::OpenAIChat::create(ocfg);
            if(res.is_err()){ delete wrapper; if(error_out) *error_out=CHAINCPP_ERR_RUNTIME; g_last_error=res.error(); return nullptr; }
            wrapper->impl = std::move(res.value());
        }
        if(error_out) *error_out=CHAINCPP_OK;
        return wrapper;
    }catch(const std::exception& e){ if(error_out) *error_out=CHAINCPP_ERR_RUNTIME; g_last_error=e.what(); return nullptr; }
}

void chaincpp_llm_destroy(chaincpp_llm_t llm){ delete llm; }

const char* chaincpp_llm_generate_simple(chaincpp_llm_t llm, const char* prompt){
    if(!llm||!prompt){ g_last_error="null arg"; return nullptr; }
    try{
        std::vector<chaincpp::models::Message> msgs;
        msgs.push_back(chaincpp::models::Message::user(prompt));
        auto res = llm->impl->generate(msgs);
        if(res.is_err()){ g_last_error=res.error(); return nullptr; }
        return alloc_c_string(res.value());
    }catch(const std::exception& e){ g_last_error=e.what(); return nullptr; }
}

const char* chaincpp_llm_generate_chat(chaincpp_llm_t llm, chaincpp_messages_t msgs){
    if(!llm||!msgs){ g_last_error="null arg"; return nullptr; }
    try{
        auto res = llm->impl->generate(msgs->msgs);
        if(res.is_err()){ g_last_error=res.error(); return nullptr; }
        return alloc_c_string(res.value());
    }catch(const std::exception& e){ g_last_error=e.what(); return nullptr; }
}

} // extern C
