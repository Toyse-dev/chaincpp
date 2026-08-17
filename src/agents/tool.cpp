#include "chaincpp/agents/tool.hpp"
#include "chaincpp/security/sandbox.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>
#include <sstream>
#include <random>
#include <iomanip>
#include <cctype>

using json = nlohmann::json;

namespace chaincpp::agents {

// --- helper: no regex name validation (prevents ReDoS) ---
static bool is_valid_tool_name(const std::string& name) {
    if (name.empty()) return false;
    if (!std::isalpha((unsigned char)name[0]) && name[0]!= '_') return false;
    for (char c : name) {
        if (!std::isalnum((unsigned char)c) && c!= '_') return false;
    }
    return true;
}

security::Result<Tool> Tool::create(
    std::string name,
    std::string description,
    ToolFunc func,
    ToolCapabilities caps,
    std::string input_schema
) {
    if (name.empty()) {
        return security::Result<Tool>::err("Tool name cannot be empty");
    }

    if (!is_valid_tool_name(name)) {
        return security::Result<Tool>::err("Invalid tool name: " + name + " (must match ^[a-zA-Z_][a-zA-Z0-9_]*$)");
    }

    auto caps_valid = caps.validate();
    if (caps_valid.is_err()) {
        return security::Result<Tool>::err(caps_valid.error());
    }

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
    if (input.size() > caps_.max_input_bytes) {
        return security::Result<std::string>::err(
            "Input too large: " + std::to_string(input.size()) +
            " bytes (max: " + std::to_string(caps_.max_input_bytes) + ")"
        );
    }

    auto validation = validate_input(input);
    if (validation.is_err()) {
        return security::Result<std::string>::err(validation.error());
    }

    auto limits = security::SecurityLimits::safe_defaults();
    limits.timeout = caps_.timeout;
    limits.max_memory_bytes = 100 * 1024 * 1024;
    limits.allow_network = caps_.needs_network;
    limits.allow_filesystem = caps_.needs_filesystem;

    if (caps_.needs_network &&!caps_.allowed_domains.empty()) {
        limits.allowed_domains = caps_.allowed_domains;
    }
    if (caps_.needs_filesystem &&!caps_.allowed_paths.empty()) {
        limits.allowed_paths = caps_.allowed_paths;
    }

    // SECURITY FIX: REAL ISOLATION
    // BEFORE: Sandbox::execute_safe (thread - cannot kill, detach leak)
    // AFTER: Sandbox::execute_in_process (fork + RLIMIT_AS + SIGKILL / Job Object + TerminateJobObject)
    std::string result;
    std::string error_msg;
    bool success = false;

    security::Sandbox sandbox;
    auto sandbox_result = security::Sandbox::execute_in_process(
    [&]() -> int {
        auto run_res = func_(input);
        if (run_res.is_ok()) {
            result = run_res.value();
            success = true;
            return 0;
        } else {
            error_msg = run_res.error();
            return 1;
        }
    },
    limits
);

    if (sandbox_result.is_err()) {
        // This now means true timeout/kill, not just "gave up waiting"
        return security::Result<std::string>::err(sandbox_result.error() + (error_msg.empty()?"": " | Tool error: " + error_msg));
    }
    if (!success) {
        return security::Result<std::string>::err(error_msg);
    }

    if (result.size() > caps_.max_output_bytes) {
        return security::Result<std::string>::err(
            "Output too large: " + std::to_string(result.size()) +
            " bytes (max: " + std::to_string(caps_.max_output_bytes) + ")"
        );
    }

    return security::Result<std::string>::ok(std::move(result));
}

security::Result<void> Tool::validate_input(const std::string& input) const {
    if (input_schema_ == "{}" || input_schema_.empty()) return security::Result<void>::ok();

    try {
        auto schema = json::parse(input_schema_);
        auto input_json = json::parse(input);

        if (schema.contains("required")) {
            for (const auto& req : schema["required"]) {
                if (!input_json.contains(req)) {
                    return security::Result<void>::err("Missing required field: " + req.get<std::string>());
                }
            }
        }

        if (schema.contains("properties")) {
            for (auto& [key, value] : schema["properties"].items()) {
                if (input_json.contains(key)) {
                    std::string expected_type = value["type"];
                    std::string actual_type = input_json[key].type_name();
                    if (expected_type == "string" && actual_type!= "string") {
                        return security::Result<void>::err("Field '" + key + "' should be string");
                    } else if (expected_type == "number" && actual_type!= "number") {
                        return security::Result<void>::err("Field '" + key + "' should be number");
                    } else if (expected_type == "boolean" && actual_type!= "boolean") {
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

ToolRegistry& ToolRegistry::instance() {
    static ToolRegistry registry;
    return registry;
}

security::Result<void> ToolRegistry::register_tool(Tool tool) {
    auto name = tool.name();
    if (tools_.find(name)!= tools_.end()) return security::Result<void>::err("Tool already registered: " + name);
    tools_[name] = std::move(tool);
    return security::Result<void>::ok();
}

security::Result<Tool> ToolRegistry::get_tool(const std::string& name) const {
    auto it = tools_.find(name);
    if (it == tools_.end()) return security::Result<Tool>::err("Tool not found: " + name);
    return security::Result<Tool>::ok(it->second);
}

std::vector<Tool> ToolRegistry::list_tools() const {
    std::vector<Tool> result;
    for (const auto& [name, tool] : tools_) result.push_back(tool);
    return result;
}

bool ToolRegistry::has_tool(const std::string& name) const { return tools_.find(name)!= tools_.end(); }

security::Result<void> ToolRegistry::unregister_tool(const std::string& name) {
    auto it = tools_.find(name);
    if (it == tools_.end()) return security::Result<void>::err("Tool not found: " + name);
    tools_.erase(it);
    return security::Result<void>::ok();
}

namespace builtin_tools {

Tool create_time_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = false;
    auto func = [](const std::string&) -> security::Result<std::string> {
        auto now = std::chrono::system_clock::now();
        auto time_t_val = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
    #ifdef _WIN32
        if (localtime_s(&tm_buf, &time_t_val) != 0) {
            return security::Result<std::string>::err("localtime_s failed");
        }
    #else
        if (localtime_r(&time_t_val, &tm_buf) == nullptr) {
            return security::Result<std::string>::err("localtime_r failed");
        }
    #endif
        char buf[64];
        if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
            return security::Result<std::string>::err("strftime failed");
        }
        std::stringstream ss;
        ss<< "Current time: " << buf;
        return security::Result<std::string>::ok(ss.str());
    };
    return Tool::create("get_current_time","Get the current system date and time",func,caps,R"({"type": "object", "properties": {}})").value();
}

Tool create_calculator_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = false;

    auto func = [](const std::string& input) -> security::Result<std::string> {
        try {
            auto expr_json = json::parse(input);
            if (!expr_json.contains("expression")) return security::Result<std::string>::err("Missing 'expression' field");
            std::string expression = expr_json["expression"];

            // No regex - manual parse to prevent ReDoS
            std::stringstream ss(expression);
            double num;
            char op;
            std::vector<double> numbers;
            std::vector<char> ops;

            if (!(ss >> num)) return security::Result<std::string>::err("Invalid expression");
            numbers.push_back(num);
            while (ss >> op >> num) {
                if (op!='+' && op!='-' && op!='*' && op!='/') return security::Result<std::string>::err("Unknown operator: " + std::string(1, op));
                ops.push_back(op);
                numbers.push_back(num);
            }

            double result = numbers[0];
            for (size_t i = 0; i < ops.size(); ++i) {
                switch (ops[i]) {
                    case '+': result += numbers[i+1]; break;
                    case '-': result -= numbers[i+1]; break;
                    case '*': result *= numbers[i+1]; break;
                    case '/':
                        if (numbers[i+1]==0) return security::Result<std::string>::err("Division by zero");
                        result /= numbers[i+1]; break;
                    default: break;
                }
            }
            std::stringstream result_ss;
            result_ss << expression << " = " << result;
            return security::Result<std::string>::ok(result_ss.str());
        } catch (const std::exception& e) {
            return security::Result<std::string>::err("Calculation error: " + std::string(e.what()));
        }
    };

    return Tool::create("calculate","Perform mathematical calculations",func,caps,
        R"({"type": "object","properties": {"expression": {"type": "string"}},"required": ["expression"]})").value();
}

Tool create_web_search_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = true;
    auto func = [](const std::string&) -> security::Result<std::string> {
        return security::Result<std::string>::ok("Web search stub - integrate search API in production");
    };
    return Tool::create("web_search","Search the web (requires approval)",func,caps,
        R"({"type": "object","properties": {"query": {"type": "string"}},"required": ["query"]})").value();
}

Tool create_file_reader_tool(const std::vector<std::string>& allowed_paths) {
    auto caps = ToolCapabilities::read_only_file();
    caps.allowed_paths = allowed_paths;
    auto func = [allowed_paths](const std::string& input) -> security::Result<std::string> {
        auto input_json = json::parse(input);
        std::string filepath = input_json["filepath"];
        bool allowed = false;
        for (const auto& path : allowed_paths) if (filepath.rfind(path,0)==0) { allowed=true; break; }
        if (!allowed) return security::Result<std::string>::err("Access denied: " + filepath);
        std::ifstream file(filepath);
        if (!file) return security::Result<std::string>::err("Cannot open file: " + filepath);
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (content.size() > 1024*1024) return security::Result<std::string>::err("File too large");
        return security::Result<std::string>::ok(content);
    };
    return Tool::create("read_file","Read a file from the filesystem",func,caps,
        R"({"type": "object","properties": {"filepath": {"type": "string"}},"required": ["filepath"]})").value();
}

Tool create_system_info_tool() {
    auto caps = ToolCapabilities::safe_web_tool();
    caps.requires_approval = false;
    auto func = [](const std::string&) -> security::Result<std::string> {
        std::stringstream info;
        #ifdef _WIN32
        info << "OS: Windows\n";
        #elif __APPLE__
        info << "OS: macOS\n";
        #elif __linux__
        info << "OS: Linux\n";
        #endif
        info << "C++ Standard: " << __cplusplus << "\n";
        return security::Result<std::string>::ok(info.str());
    };
    return Tool::create("system_info","Get information about the system",func,caps,R"({"type": "object", "properties": {}})").value();
}

} // namespace builtin_tools
} // namespace chaincpp::agents