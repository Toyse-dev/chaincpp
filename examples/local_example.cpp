#include "chaincpp/models/llm.hpp"
#include "chaincpp/core/prompt.hpp"
#include <iostream>
#include <vector>
#include <map>

using namespace chaincpp::models;
using namespace chaincpp::core;

int main() {
    std::cout << "========================================\n";
    std::cout << "chaincpp - Pure Offline Local LLM Demo\n";
    std::cout << "========================================\n\n";

    // Initialize local offline embeddings via llama.cpp (No keys, no internet!)
    LocalLLM::Config local_config;
    local_config.model_path = "models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    local_config.context_size = 2048;
    local_config.gpu_layers = 0; // Set to > 0 if we want GPU acceleration later

    std::cout << "Loading local model weights into memory...\n";
    auto local_result = LocalLLM::create(local_config);
    
    if (local_result.is_err()) {
        std::cerr << "Initialization Error: " << local_result.error() << "\n";
        std::cerr << "Please ensure the model file exists in models/\n";
        return 1;
    }
    auto llm = std::move(local_result.value());
    std::cout << "Local model loaded successfully!\n\n";

    // Format a secure prompt template
    auto prompt_result = PromptTemplate::create(
        "You are a helpful AI assistant. Answer the question: {question}\nAnswer:"
    );
    auto prompt_template = std::move(prompt_result.value());

    std::map<std::string, std::string> vars = {{"question", "What is the capital of Nigeria?"}};
    auto formatted = prompt_template.format_safe(vars).value();

    std::vector<Message> messages = { Message::user(formatted) };

    // 3. Run on-device generation
    ModelConfig execution_config;
    execution_config.max_tokens = 100;
    execution_config.temperature = 0.7f;

    std::cout << "Generating local offline inference response...\n";
    auto response = llm->generate(messages, execution_config);

    if (response.is_ok()) {
        std::cout << "\nResponse:\n" << response.value() << "\n";
    } else {
        std::cerr << "Inference Fault: " << response.error() << "\n";
    }

    std::cout << "\n========================================\n";
    return 0;
}
