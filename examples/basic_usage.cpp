#include "chaincpp/security/sandbox.hpp"
#include <iostream>
#include <string>
#include <thread>

using namespace chaincpp::security;

// Example tool that simulates a safe operation
Result<void> safe_tool_example() {
    std::cout << "  Tool: Calculating something safe...\n";
    
    // Simulate work
    int result = 0;
    for (int i = 0; i < 100; i++) {
        result += i;
    }
    
    std::cout << "  Tool: Result = " << result << "\n";
    return Result<void>::ok();
}

// Example of a tool that might be dangerous
Result<void> potentially_dangerous_tool() {
    std::cout << "  Tool: Attempting system call...\n";
    
    // In a real sandbox, this would be blocked
    // system("echo 'This would be dangerous!'");
    
    return Result<void>::ok(); // The sandbox might block or restrict this
}

int main() {
    std::cout << "\n========================================\n";
    std::cout << "|     chaincpp - Secure LLM Library      |\n";
    std::cout << "|         Sandbox Demonstration          |\n";
    std::cout << "==========================================\n\n";
    
    // Example 1: Safe execution
    std::cout << "Example 1: Executing safe tool\n";
    std::cout << "----------------------------------------\n";
    
    auto safe_result = Sandbox::execute_safe(safe_tool_example, SecurityLimits::safe_defaults());
    if (safe_result.is_ok()) {
        std::cout << "Tool executed successfully\n";
    } else {
        std::cout << "Tool failed: " << safe_result.error() << "\n";
    }
    
    // Example 2: Strict limits
    std::cout << "\nExample 2: Executing with strict limits\n";
    std::cout << "----------------------------------------\n";
    
    auto strict_limits = SecurityLimits::strict();
    auto strict_result = Sandbox::execute_safe(safe_tool_example, strict_limits);
    
    if (strict_result.is_ok()) {
        std::cout << "Tool executed within strict limits\n";
    } else {
        std::cout << "Tool failed: " << strict_result.error() << "\n";
    }
    
    // Example 3: Timeout demonstration
    std::cout << "\nExample 3: Tool that might hang\n";
    std::cout << "----------------------------------------\n";
    
    auto hanging_tool = []() -> Result<void> {
        std::cout << "  Tool: Starting long operation...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        std::cout << "  Tool: Operation complete\n";
        return Result<void>::ok();
    };
    
    auto timeout_limits = SecurityLimits::strict(); // 1 second timeout
    auto timeout_result = Sandbox::execute_safe(hanging_tool, timeout_limits);
    
    if (timeout_result.is_ok()) {
        std::cout << "Tool completed before timeout\n";
    } else {
        std::cout << "Tool was interrupted: " << timeout_result.error() << "\n";
    }
    
    // Example 4: Demonstrating security boundaries
    std::cout << "\nExample 4: Security boundaries\n";
    std::cout << "----------------------------------------\n";
    std::cout << "The sandbox enforces:\n";
    std::cout << "  • Memory limits (prevents DoS)\n";
    std::cout << "  • Timeout protection (prevents infinite loops)\n";
    std::cout << "  • Environment sanitization\n";
    std::cout << "  • Network restrictions (configurable)\n";
    std::cout << "  • Filesystem restrictions (configurable)\n";
    
    // Show current limits
    auto defaults = SecurityLimits::safe_defaults();
    std::cout << "\nDefault security limits:\n";
    std::cout << "  Timeout: " << defaults.timeout.count() << "ms\n";
    std::cout << "  Max memory: " << defaults.max_memory_bytes / (1024*1024) << "MB\n";
    std::cout << "  Max output: " << defaults.max_output_bytes / 1024 << "KB\n";
    std::cout << "  Network: " << (defaults.allow_network ? "allowed" : "blocked") << "\n";
    std::cout << "  Filesystem: " << (defaults.allow_filesystem ? "allowed" : "blocked") << "\n";
    
    std::cout << "\nSandbox ready for LLM tool execution!\n";
    std::cout << "Next step: Adding PromptTemplate with injection protection\n\n";
    
    return 0;
}