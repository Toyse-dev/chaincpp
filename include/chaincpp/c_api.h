#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHAINCPP_VERSION_MAJOR 0
#define CHAINCPP_VERSION_MINOR 1
#define CHAINCPP_VERSION_PATCH 0

// Opaque handles
typedef struct ChainCpp_LLM* chaincpp_llm_t;
typedef struct ChainCpp_Agent* chaincpp_agent_t;
typedef struct ChainCpp_Messages* chaincpp_messages_t;

// Error codes
typedef enum {
    CHAINCPP_OK = 0,
    CHAINCPP_ERR_INVALID_ARG = 1,
    CHAINCPP_ERR_NOT_FOUND = 2,
    CHAINCPP_ERR_RUNTIME = 3,
    CHAINCPP_ERR_OOM = 4
} chaincpp_error_t;

// LLM type
typedef enum {
    CHAINCPP_LLM_LOCAL = 0,
    CHAINCPP_LLM_OPENAI = 1,
    CHAINCPP_LLM_ANTHROPIC = 2
} chaincpp_llm_type_t;

// Config for creation
typedef struct {
    chaincpp_llm_type_t type;
    const char* model_path;   // for LOCAL
    const char* model_name;   // for OPENAI/ANTHROPIC (e.g. gpt-4o)
    const char* api_key;      // for remote
    const char* base_url;     // optional
    int32_t max_tokens;
    float temperature;
} chaincpp_llm_config_t;

// --- LLM ---

// Create LLM from config. Returns NULL on failure, check error_out.
chaincpp_llm_t chaincpp_llm_create(const chaincpp_llm_config_t* config, chaincpp_error_t* error_out);
void chaincpp_llm_destroy(chaincpp_llm_t llm);

// Simple generate: prompt -> string (caller must free with chaincpp_string_free)
const char* chaincpp_llm_generate_simple(chaincpp_llm_t llm, const char* prompt);

// Chat API
chaincpp_messages_t chaincpp_messages_create();
void chaincpp_messages_destroy(chaincpp_messages_t msgs);
chaincpp_error_t chaincpp_messages_add(chaincpp_messages_t msgs, const char* role, const char* content); // role: system/user/assistant
const char* chaincpp_llm_generate_chat(chaincpp_llm_t llm, chaincpp_messages_t msgs);

// Memory management
void chaincpp_string_free(const char* str);
const char* chaincpp_last_error_message();

// Version
int chaincpp_version_major();
int chaincpp_version_minor();
int chaincpp_version_patch();
const char* chaincpp_version_string();

#ifdef __cplusplus
}
#endif
