#pragma once

#include "../security/sandbox.hpp"
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <optional>

namespace chaincpp::core {

// Output Sanitizer - Prevents injection attacks

class OutputSanitizer {
public:
    enum class Context {
        JSON,      // Escape for JSON strings
        SHELL,     // Escape for shell commands
        SQL,       // Escape for SQL queries
        HTML,      // Escape for HTML output
        PLAIN      // Plain text (no escaping)
    };
    
    // Main escape function
    static std::string escape(std::string_view input, Context context);
    
    // Detect if string contains dangerous patterns
    static bool has_dangerous_patterns(std::string_view input);
    
private:
    static std::string escape_json(std::string_view input);
    static std::string escape_shell(std::string_view input);
    static std::string escape_sql(std::string_view input);
    static std::string escape_html(std::string_view input);
};

// Injection Detector - Identifies prompt injection attempts

class InjectionDetector {
public:
    struct DetectionResult {
        bool is_injection = false;
        std::string pattern_matched;
        int severity = 0; // 0-10, higher = more dangerous
    };
    
    // Check if text contains injection patterns
    static DetectionResult detect(std::string_view text);
    
    // Quick check (returns true if injection detected)
    static bool is_potential_injection(std::string_view text) {
        return detect(text).is_injection;
    }
    
private:
    static const std::vector<std::pair<std::string, std::pair<std::string, int>>>& get_patterns();
};

// Prompt Template - Safe string interpolation

class PromptTemplate {
public:
    // Create from string template (validates syntax)
    static security::Result<PromptTemplate> create(std::string_view template_str);
    
    // Format with variables (auto-sanitizes based on context)
    security::Result<std::string> format(
        const std::map<std::string, std::string>& variables,
        OutputSanitizer::Context context = OutputSanitizer::Context::PLAIN
    ) const;
    
    // Format with validation (blocks injection attempts)
    security::Result<std::string> format_safe(
        const std::map<std::string, std::string>& variables
    ) const;
    
    // Get list of required variables
    const std::vector<std::string>& required_variables() const { return required_vars_; }
    
    // Get raw template (for debugging)
    std::string raw_template() const { return template_str_; }
    
private:
    PromptTemplate() = default;
    
    std::string template_str_;
    std::vector<std::string> required_vars_;
    std::vector<std::pair<size_t, size_t>> variable_positions_; // For validation
};

// ============================================================================
// System Prompt Guard - Prevents prompt leaking
// ============================================================================

class SystemPromptGuard {
public:
    // Wraps system prompt with boundaries
    static std::string wrap_system_prompt(std::string_view system_prompt);
    
    // Checks if user input tries to override system prompt
    static bool user_input_overrides_system(std::string_view user_input);
    
    // Creates a locked prompt that can't be overridden
    static std::string create_locked_prompt(std::string_view instruction);
    
private:
    static constexpr const char* BOUNDARY_START = "=== SYSTEM PROMPT START ===\n";
    static constexpr const char* BOUNDARY_END = "\n=== SYSTEM PROMPT END ===\n";
    static constexpr const char* LOCK_MARKER = "[SYSTEM_LOCKED]";
};

} // namespace chaincpp::core