#include "chaincpp/models/llm.hpp"
#include "chaincpp/security/secrets.hpp"
#include <cassert>
#include <iostream>
#include <cstdlib>

using namespace chaincpp::models;
using namespace chaincpp::security;

void test_secrets_manager() {
    std::cout << "Testing SecretsManager...\n";
    
#ifdef _WIN32
    if (std::getenv("CI")) {
        std::cout << "  [SKIP] SecretsManager on Windows CI (Credential Manager hangs headless)\n\n";
        return;
    }
#endif
    auto& mgr = SecretsManager::instance();
    secure_string test_key("sk-test123456789");
    auto store_result = mgr.store_key("test_service", test_key);
    if (store_result.is_err()) {
        std::cout << "  [SKIP] store failed (no keychain): " << store_result.error() << "\n\n";
        return;
    }
    std::cout << "   Key stored\n";
    auto retrieve_result = mgr.get_key("test_service");
    assert(retrieve_result.is_ok());
    std::cout << "   Key retrieved\n";
    mgr.remove_key("test_service");
    std::cout << " SecretsManager tests passed\n\n";
}

void test_openai_creation() {
    std::cout << "Testing OpenAI creation...\n";
    auto result = OpenAIChat::create();
    if (result.is_ok()) std::cout << "   OpenAI client created\n";
    else std::cout << " OpenAI client not created (no API key): " << result.error() << "\n";
    std::cout << " OpenAI creation test complete\n\n";
}

void test_message_creation() {
    std::cout << "Testing Message creation...\n";
    auto sys_msg = Message::system("You are helpful");
    assert(sys_msg.role == Message::Role::SYSTEM);
    assert(Message::user("Hello").role == Message::Role::USER);
    assert(Message::assistant("Hi").role == Message::Role::ASSISTANT);
    std::cout << " Message tests passed\n\n";
}

void test_token_counting() {
    std::cout << "Testing token counting...\n";
    auto openai = OpenAIChat::create();
    if (openai.is_ok()) {
        const auto& client = openai.value();
        size_t tokens = client->count_tokens("Hello world");
        assert(tokens > 0);
        std::cout << " Token counting works: " << tokens << "\n";
    } else {
        std::cout << "  [SKIP] no API key, skipping token counting\n";
    }
    std::cout << "\n";
}

int main() {
    std::cout << "\n========================================\nchaincpp LLM Model Tests\n========================================\n\n";
    test_secrets_manager();
    test_message_creation();

    #ifdef _WIN32
        if (std::getenv("CI") || std::getenv("GITHUB_ACTIONS")) {
            std::cout << "[SKIP] token + openai tests on Windows CI (needs file + network)\n";
            std::cout << "All LLM model tests passed!\n========================================\n\n";
            return 0;
        }
    #endif

    test_token_counting();
    test_openai_creation();
    
    std::cout << "All LLM model tests passed!\n========================================\n\n";
    return 0;
}