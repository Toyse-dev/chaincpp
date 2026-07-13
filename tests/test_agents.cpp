#include "chaincpp/agents/tool.hpp"
#include "chaincpp/agents/react_agent.hpp"
#include "chaincpp/models/llm.hpp"
#include <iostream>
#include <cassert>

using namespace chaincpp::agents;
using namespace chaincpp::models;
using namespace chaincpp::security;

void test_tool_creation() {
    std::cout << "Testing Tool creation...\n";
    
    // Test valid tool
    Tool time_tool = builtin_tools::create_time_tool();
    std::cout << " Time tool created\n";
    
    // Test tool execution
    auto result = time_tool.execute("{}");
    assert(result.is_ok());
    std::cout << "  Time tool executed: " << result.value().substr(0, 20) << "...\n";
    
    // Test calculator tool
    auto calc_tool = builtin_tools::create_calculator_tool();
    auto calc_result = calc_tool.execute(R"({"expression": "2 + 3 * 4"})");
    assert(calc_result.is_ok());
    std::cout << "  Calculator: " << calc_result.value() << "\n";
    
    std::cout << "Tool tests passed\n\n";
}

void test_tool_registry() {
    std::cout << "Testing ToolRegistry...\n";
    
    auto& registry = ToolRegistry::instance();
    
    auto tool = builtin_tools::create_system_info_tool();
    auto register_result = registry.register_tool(tool);
    assert(register_result.is_ok());
    std::cout << "  Tool registered\n";
    
    assert(registry.has_tool("system_info"));
    std::cout << "  Tool found\n";
    
    auto retrieved = registry.get_tool("system_info");
    assert(retrieved.is_ok());
    std::cout << "  Tool retrieved\n";
    
    auto tools = registry.list_tools();
    assert(!tools.empty());
    std::cout << "  Tools listed: " << tools.size() << " tools\n";
    
    std::cout << "ToolRegistry tests passed\n\n";
}

void test_tool_security() {
    std::cout << "Testing Tool security...\n";
    
    // Create tool with restricted capabilities
    auto caps = ToolCapabilities::safe_web_tool();
    caps.allowed_domains = {"api.github.com"};
    
    auto tool = Tool::create(
        "safe_web",
        "Safe web tool",
        [](const std::string&) -> chaincpp::security::Result<std::string> {
            return chaincpp::security::Result<std::string>::ok("OK");
        },
        caps
    );
    
    assert(tool.is_ok());
    std::cout << "  Secure tool created\n";
    
    // Test capability validation
    auto invalid_caps = caps;
    invalid_caps.needs_network = true;
    invalid_caps.allowed_domains.clear();
    
    auto invalid_tool = Tool::create(
        "invalid",
        "Invalid tool",
        [](const std::string&) -> chaincpp::security::Result<std::string> {
            return chaincpp::security::Result<std::string>::ok("OK");
        },
        invalid_caps
    );
    
    assert(invalid_tool.is_err());
    std::cout << "  Invalid capabilities rejected\n";
    
    std::cout << "Tool security tests passed\n\n";
}

void test_simple_agent() {
    std::cout << "Testing SimpleAgent...\n";
    
    auto llm_result = OpenAIChat::create();
    if (llm_result.is_err()) {
        std::cout << "  !! Skipping SimpleAgent test (no API key)\n\n";
        return;
    }
    
    auto agent_result = SimpleAgent::create(std::move(llm_result.value()));
    assert(agent_result.is_ok());
    
    auto agent = std::move(agent_result.value());
    auto response = agent->chat("Say hello in one word");
    
    if (response.is_ok()) {
        std::cout << "  Agent response: " << response.value() << "\n";
    }
    
    std::cout << "SimpleAgent tests passed\n\n";
}

int main() {
    std::cout << "\n========================================\n";
    std::cout << "chaincpp Agent Security Tests\n";
    std::cout << "========================================\n\n";
    
    test_tool_creation();
    test_tool_registry();
    test_tool_security();
    test_simple_agent();
    
    std::cout << "========================================\n";
    std::cout << "All agent tests passed!\n";
    std::cout << "========================================\n\n";
    
    return 0;
}