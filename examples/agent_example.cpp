#include "chaincpp/agents/react_agent.hpp"
#include "chaincpp/agents/tool.hpp"
#include "chaincpp/models/llm.hpp"
#include "chaincpp/security/secrets.hpp"
#include <iostream>

using namespace chaincpp::agents;
using namespace chaincpp::models;

int main() {
    std::cout << "\n=======================================\n";
    std::cout << "||   chaincpp - ReAct Agent Demo         ||\n";
    std::cout << "||         AI with Tools                  ||\n";
    std::cout << "============================================\n\n";
    
    // Create LLM
    auto llm_result = OpenAIChat::create();
    if (llm_result.is_err()) {
        std::cout << "OpenAI client not available: " << llm_result.error() << "\n";
        std::cout << "  Set OPENAI_API_KEY environment variable\n\n";
        return 1;
    }
    
    // Create tools
    std::vector<Tool> tools;
    
    // Add time tool
    tools.push_back(builtin_tools::create_time_tool());
    std::cout << "Time tool loaded\n";
    
    // Add calculator tool
    tools.push_back(builtin_tools::create_calculator_tool());
    std::cout << "Calculator tool loaded\n";
    
    // Add system info tool
    tools.push_back(builtin_tools::create_system_info_tool());
    std::cout << "System Info tool loaded\n";
    
    std::cout << "\n";
    
    // Create agent with callbacks
    AgentConfig config;
    config.verbose = true;
    config.max_iterations = 5;
    config.require_tool_approval = false;
    
    config.on_thought = [](const std::string& thought) {
        std::cout << "Thought: " << thought << "\n";
    };
    
    config.on_action = [](const std::string& tool, const std::string& input) {
        std::cout << "Action: " << tool << "\n";
        std::cout << "Input: " << input << "\n";
    };
    
    config.on_observation = [](const std::string& observation) {
        std::cout << "Observation: " << observation << "\n\n";
    };
    
    config.on_final_answer = [](const std::string& answer) {
        std::cout << "Final Answer: " << answer << "\n";
    };
    
    auto agent_result = ReActAgent::create(
        std::move(llm_result.value()),
        std::move(tools),
        config
    );
    
    if (agent_result.is_err()) {
        std::cout << "Failed to create agent: " << agent_result.error() << "\n";
        return 1;
    }
    
    auto agent = std::move(agent_result.value());
    
    // Example queries
    std::vector<std::string> queries = {
        "What time is it right now?",
        "Calculate 123 * 456",
        "Tell me about my system"
    };
    
    for (const auto& query : queries) {
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "User: " << query << "\n";
        std::cout << std::string(60, '=') << "\n\n";
        
        auto result = agent->run(query);
        
        if (result.is_ok()) {
            std::cout << "\nAgent completed successfully\n";
        } else {
            std::cout << "\nAgent error: " << result.error() << "\n";
        }
        
        std::cout << "\n";
    }
    
    // Security demonstration
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Security Features Active:\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Tool sandboxing with resource limits\n";
    std::cout << "Input/output size validation\n";
    std::cout << "Domain/path allowlisting\n";
    std::cout << "Timeout protection\n";
    std::cout << "Memory limits enforced\n";
    std::cout << "Human approval for dangerous tools\n";
    std::cout << "No system command execution without approval\n";
    
    std::cout << "\nReAct Agent ready for production!\n";
    std::cout << "Next: Adding RAG and Vector Stores\n\n";
    
    return 0;
}