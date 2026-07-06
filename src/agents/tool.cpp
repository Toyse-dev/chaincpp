#include "chaincpp/agents/tool.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <regex>
#include <chrono>
#include <sstream>
#include <random>
#include <iomanip>

using json = nlohmann::json;

namespace chaincpp::agents {

// Tool Implementation

security::Result<Tool> Tool::create(
    std::string name,
    std::string description,
    ToolFunc func,
    ToolCapabilities caps,
    std::string input_schema
) {
    // Validate name
    if (name.empty()) {
        return security::Result<Tool>::err("Tool name cannot be empty");
    }
    
    if (!std::regex_match(name, std::regex("^[a-zA-Z_][a-zA-Z0-9_]*$"))) {
        return security::Result<Tool>::err("Invalid tool name: " + name);
    }
    
    // Validate capabilities
    auto caps_valid = caps.validate();
    if (caps_valid.is_err()) {
        return security::Result<Tool>::err(caps_valid.error());
    }
    
    // Parse schema to validate it's valid JSON
    try {
        [[maybe_unused]] auto dummy_parsed = json::parse(input_schema);
    } catch (const std::exception& e) {
        return security::Result<Tool>::err("Invalid JSON schema: " + std::string(e.what()));
    }
    
    Tool tool;
    tool.name_ = std::move(name);
    tool.description_ = std::move(description);
    tool.func_ = std::move(func);
    tool.caps_ = std::move(caps);
    tool.input_schema_ = std::move(input_schema);
    
    return security::Result<Tool>::ok(std::move(tool));
}

security::Result<std::string> Tool::execute(const std::string& input) {
    // Validate input size
    if (input.size() > caps_.max_input_bytes) {
        return security::Result<std::string>::err(
            "Input too large: " + std::to_string(input.size()) + 
            " bytes (max: " + std::to_string(caps_.max_input_bytes) + ")"
        );
    }
    
    // Validate input against schema
    auto validation = validate_input(input);
    if (validation.is_err()) {
        // Explicitly convert the Result<void> error into a Result<std::string> error
        return security::Result<std::string>::err(validation.error());
    }
    
    // Execute with timeout and memory limits
    auto limits = security::SecurityLimits::safe_defaults();
    limits.timeout = caps_.timeout;
    limits.max_memory_bytes = 100 * 1024 * 1024;  // 100MB
    limits.allow_network = caps_.needs_network;
    limits.allow_filesystem = caps_.needs_filesystem;
    
    if (caps_.needs_network && !caps_.allowed_domains.empty()) {
        limits.allowed_domains = caps_.allowed_domains;
    }
    
    if (caps_.needs_filesystem && !caps_.allowed_paths.empty()) {
        limits.allowed_paths = caps_.allowed_paths;
    }

    // Use the verified execute_safe container loop with safe thread extraction
    std::string result;
    std::string error_msg;
    bool success = false;
    
    auto sandbox_result = security::Sandbox::execute_safe(
        [&]() -> security::Result<void> {
            auto run_res = func_(input);
            if (run_res.is_ok()) {
                result = run_res.value();
                success = true;
                return security::Result<void>::ok();
            } else {
                error_msg = run_res.error();
                return security::Result<void>::err(error_msg);
            }
        },
        limits
    );
    
    if (!sandbox_result.is_ok()) {
        return security::Result<std::string>::err(sandbox_result.error());
    }
    if (!success) {
        return security::Result<std::string>::err(error_msg);
    }
    
    // Check output size
    if (result.size() > caps_.max_output_bytes) {
        return security::Result<std::string>::err(
            "Output too large: " + std::to_string(result.size()) + 
            " bytes (max: " + std::to_string(caps_.max_output_bytes) + ")"
        );
    }
    
    return security::Result<std::string>::ok(std::move(result));
}

security::Result<void> Tool::validate_input(const std::string& input) const {
    if (input_schema_ == "{}" || input_schema_.empty()) {
        return security::Result<void>::ok();
    }
    
    try {
        auto schema = json::parse(input_schema_);
        auto input_json = json::parse(input);
        
        // Basic schema validation
        if (schema.contains("required")) {
            for (const auto& req : schema["required"]) {
                if (!input_json.contains(req)) {
                    return security::Result<void>::err("Missing required field: " + req.get<std::string>());
                }
            }
        }
        
        // Type checking
        if (schema.contains("properties")) {
            for (auto& [key, value] : schema["properties"].items()) {
                if (input_json.contains(key)) {
                    std::string expected_type = value["type"];
                    std::string actual_type = input_json[key].type_name();
                    
                    if (expected_type == "string" && actual_type != "string") {
                        return security::Result<void>::err("Field '" + key + "' should be string");
                    } else if (expected_type == "number" && actual_type != "number") {
                        return security::Result<void>::err("Field '" + key + "' should be number");
                    } else if (expected_type == "boolean" && actual_type != "boolean") {
                        return security::Result<void>::err("Field '" + key + "' should be boolean");
                    }
                }
            }
        }
        
    } catch (const std::exception& e) {
        return security::Result<void>::err("Input validation failed: " + std::string(e.what()));
    }
    
    return security::Result<void>::ok();
}

json Tool::to_json() const {
    return json{
        {"name", name_},
        {"description", description_},
        {"capabilities", {
            {"needs_network", caps_.needs_network},
            {"needs_filesystem", caps_.needs_filesystem},
            {"requires_approval", caps_.requires_approval}
        }},
        {"input_schema", json::parse(input_schema_)}
    };
}

// ToolRegistry Implementation

ToolRegistry& ToolRegistry::instance() {
    static ToolRegistry registry;
    return registry;
}

security::Result<void> ToolRegistry::register_tool(Tool tool) {
    auto name = tool.name();
    
    if (tools_.find(name) != tools_.end()) {
        return security::Result<void>::err("Tool already registered: " + name);
    }
    
    tools_[name] = std::move(tool);
    return security::Result<void>::ok();
}

security::Result<Tool> ToolRegistry::get_tool(const std::string& name) const {
    auto it = tools_.find(name);
    if (it == tools_.end()) {
        return security::Result<Tool>::err("Tool not found: " + name);
    }
    return security::Result<Tool>::ok(it->second);
}

std::vector<Tool> ToolRegistry::list_tools() const {
    std::vector<Tool> result;
    for (const auto& [name, tool] : tools_) {
        result.push_back(tool);
    }
    return result;
}

bool ToolRegistry::has_tool(const std::string& name) const {
    return tools_.find(name) != tools_.end();
}

security::Result<void> ToolRegistry::unregister_tool(const std::string& name) {
    auto it = tools_.find(name);
    if (it == tools_.end()) {
        return security::Result<void>::err("Tool not found: " + name);
    }
    tools_.erase(it);
    return security::Result<void>::ok();
}

// Built-in Tools Implementation

namespace builtin_tools {

Tool create_time_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = false;
    
    auto func = [](const std::string& input) -> security::Result<std::string> {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << "Current time: " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        
        return security::Result<std::string>::ok(ss.str());
    };
    
    return Tool::create(
        "get_current_time",
        "Get the current system date and time",
        func,
        caps,
        R"({"type": "object", "properties": {}})"
    ).value();
}

Tool create_calculator_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = false;
    
    auto func = [](const std::string& input) -> security::Result<std::string> {
        try {
            auto expr_json = json::parse(input);
            if (!expr_json.contains("expression")) {
                return security::Result<std::string>::err("Missing 'expression' field");
            }
            
            std::string expression = expr_json["expression"];
            
            // Simple expression evaluator (for demo - use proper math lib in production)
            std::regex num_pattern(R"(\d+(\.\d+)?)");
            std::vector<double> numbers;
            std::vector<char> ops;
            
            std::stringstream ss(expression);
            double num;
            char op;
            
            ss >> num;
            numbers.push_back(num);
            
            while (ss >> op >> num) {
                ops.push_back(op);
                numbers.push_back(num);
            }
            
            double result = numbers[0];
            for (size_t i = 0; i < ops.size(); ++i) {
                switch (ops[i]) {
                    case '+': result += numbers[i + 1]; break;
                    case '-': result -= numbers[i + 1]; break;
                    case '*': result *= numbers[i + 1]; break;
                    case '/': 
                        if (numbers[i + 1] == 0) {
                            return security::Result<std::string>::err("Division by zero");
                        }
                        result /= numbers[i + 1]; 
                        break;
                    default:
                        return security::Result<std::string>::err("Unknown operator: " + std::string(1, op));
                }
            }
            
            std::stringstream result_ss;
            result_ss << expression << " = " << result;
            return security::Result<std::string>::ok(result_ss.str());
            
        } catch (const std::exception& e) {
            return security::Result<std::string>::err("Calculation error: " + std::string(e.what()));
        }
    };
    
    return Tool::create(
        "calculate",
        "Perform mathematical calculations",
        func,
        caps,
        R"({
            "type": "object",
            "properties": {
                "expression": {"type": "string"}
            },
            "required": ["expression"]
        })"
    ).value();
}

Tool create_web_search_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = true;  // User must approve web searches
    
    auto func = [](const std::string& input) -> security::Result<std::string> {
        // In production, integrate with a search API
        // This is a stub for demonstration
        return security::Result<std::string>::ok(
            "Web search would execute here. In production, integrate with Google/Bing API"
        );
    };
    
    return Tool::create(
        "web_search",
        "Search the web for information (requires approval)",
        func,
        caps,
        R"({
            "type": "object",
            "properties": {
                "query": {"type": "string"}
            },
            "required": ["query"]
        })"
    ).value();
}

Tool create_file_reader_tool(const std::vector<std::string>& allowed_paths) {
    auto caps = ToolCapabilities::read_only_file();
    caps.allowed_paths = allowed_paths;
    
    auto func = [allowed_paths](const std::string& input) -> security::Result<std::string> {
        auto input_json = json::parse(input);
        std::string filepath = input_json["filepath"];
        
        // Security: Check path is allowed
        bool allowed = false;
        for (const auto& path : allowed_paths) {
            if (filepath.find(path) == 0) {
                allowed = true;
                break;
            }
        }
        
        if (!allowed) {
            return security::Result<std::string>::err("Access denied: " + filepath);
        }
        
        // Read file
        std::ifstream file(filepath);
        if (!file) {
            return security::Result<std::string>::err("Cannot open file: " + filepath);
        }
        
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        
        if (content.size() > 1024 * 1024) {  // 1MB limit
            return security::Result<std::string>::err("File too large");
        }
        
        return security::Result<std::string>::ok(content);
    };
    
    return Tool::create(
        "read_file",
        "Read a file from the filesystem",
        func,
        caps,
        R"({
            "type": "object",
            "properties": {
                "filepath": {"type": "string"}
            },
            "required": ["filepath"]
        })"
    ).value();
}

Tool create_system_info_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = false;
    
    auto func = [](const std::string& input) -> security::Result<std::string> {
        std::stringstream info;
        
        #ifdef _WIN32
        info << "OS: Windows\n";
        #elif __APPLE__
        info << "OS: macOS\n";
        #elif __linux__
        info << "OS: Linux\n";
        #endif
        
        info << "C++ Standard: " << __cplusplus << "\n";
        
        // Get CPU info (platform-specific)
        #ifdef __linux__
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                info << "CPU: " << line.substr(line.find(":") + 2) << "\n";
                break;
            }
        }
        #endif
        
        return security::Result<std::string>::ok(info.str());
    };
    
    return Tool::create(
        "system_info",
        "Get information about the system",
        func,
        caps,
        R"({"type": "object", "properties": {}})"
    ).value();
}

} // namespace builtin_tools

} // namespace chaincpp::agents