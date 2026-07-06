#pragma once

#include "../security/sandbox.hpp"
#include <string>
#include <vector>
#include <functional>
#include <map>
#include <chrono>

namespace chaincpp::agents {

// ============================================================================
// Tool Capabilities - Declarative security manifest
// ============================================================================

struct ToolCapabilities {
    bool needs_network = false;
    std::vector<std::string> allowed_domains;
    bool needs_filesystem = false;
    std::vector<std::string> allowed_paths;
    bool can_execute_commands = false;
    bool needs_user_input = false;
    size_t max_input_bytes = 10 * 1024;  // 10KB
    size_t max_output_bytes = 1024 * 1024;  // 1MB
    std::chrono::milliseconds timeout{30000};  // 30 seconds
    
    // Human approval required before execution
    bool requires_approval = false;
    
    // Validation
    security::Result<void> validate() const {
        if (needs_network && allowed_domains.empty()) {
            return security::Result<void>::err("Network access requires allowed domains");
        }
        if (needs_filesystem && allowed_paths.empty()) {
            return security::Result<void>::err("Filesystem access requires allowed paths");
        }
        if (can_execute_commands && !requires_approval) {
            return security::Result<void>::err("Command execution requires human approval");
        }
        return security::Result<void>::ok();
    }
    
    static ToolCapabilities safe_web_tool() {
        ToolCapabilities caps;
        caps.needs_network = true;
        caps.allowed_domains = {"api.github.com", "api.openweathermap.org"};
        caps.timeout = std::chrono::seconds(10);
        return caps;
    }
    
    static ToolCapabilities read_only_file() {
        ToolCapabilities caps;
        caps.needs_filesystem = true;
        caps.allowed_paths = {"/tmp/chaincpp_readonly", "./data"};
        caps.max_output_bytes = 100 * 1024;  // 100KB
        return caps;
    }
    
    static ToolCapabilities dangerous_command() {
        ToolCapabilities caps;
        caps.can_execute_commands = true;
        caps.requires_approval = true;
        caps.timeout = std::chrono::seconds(5);
        return caps;
    }
};

// ============================================================================
// Tool Class - Executable function with security
// ============================================================================

class Tool {
public:
    using ToolFunc = std::function<security::Result<std::string>(const std::string&)>;
    
    // Create a new tool
    static security::Result<Tool> create(
        std::string name,
        std::string description,
        ToolFunc func,
        ToolCapabilities caps,
        std::string input_schema = "{}"  // JSON Schema
    );
    
    // Get tool info
    const std::string& name() const { return name_; }
    const std::string& description() const { return description_; }
    const ToolCapabilities& capabilities() const { return caps_; }
    
    // Execute the tool with security checks
    security::Result<std::string> execute(const std::string& input);
    
    // Check if input matches schema
    security::Result<void> validate_input(const std::string& input) const;
    
    // For serialization
    json to_json() const;
    
private:
    Tool() = default;
    
    std::string name_;
    std::string description_;
    ToolFunc func_;
    ToolCapabilities caps_;
    std::string input_schema_;
};

// ============================================================================
// Tool Registry - Manage available tools
// ============================================================================

class ToolRegistry {
public:
    static ToolRegistry& instance();
    
    // Register a tool
    security::Result<void> register_tool(Tool tool);
    
    // Get a tool by name
    security::Result<Tool> get_tool(const std::string& name) const;
    
    // List all tools
    std::vector<Tool> list_tools() const;
    
    // Check if tool exists
    bool has_tool(const std::string& name) const;
    
    // Unregister tool
    security::Result<void> unregister_tool(const std::string& name);
    
private:
    ToolRegistry() = default;
    std::map<std::string, Tool> tools_;
};

// ============================================================================
// Built-in Tools
// ============================================================================

namespace builtin_tools {

// Time tool - safe
Tool create_time_tool();

// Calculator - safe
Tool create_calculator_tool();

// Web search - requires approval
Tool create_web_search_tool();

// File reader - read-only
Tool create_file_reader_tool(const std::vector<std::string>& allowed_paths);

// System info - safe read-only
Tool create_system_info_tool();

} // namespace builtin_tools

} // namespace chaincpp::agents