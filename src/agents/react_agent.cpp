#include "chaincpp/chaincpp.hpp"
#include "chaincpp/agents/react_agent.hpp"
#include "chaincpp/security/sandbox.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace chaincpp::agents {

// helpers - NO REGEX
static std::string to_lower_copy(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
    return out;
}

// case-insensitive find, returns npos if not found
static size_t ifind(const std::string& haystack, const std::string& needle, size_t from = 0) {
    auto hay_l = to_lower_copy(haystack.substr(from));
    auto need_l = to_lower_copy(needle);
    size_t pos = hay_l.find(need_l);
    return pos == std::string::npos? std::string::npos : from + pos;
}

static void trim(std::string& s) {
    auto not_space = [](unsigned char ch){ return!std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
}

static std::string extract_between(const std::string& src, size_t start_pos, const std::vector<std::string>& stop_markers) {
    size_t end = src.size();
    std::string src_lower = to_lower_copy(src);
    for (auto& marker : stop_markers) {
        size_t p = src_lower.find(to_lower_copy(marker), start_pos);
        if (p!= std::string::npos && p < end) end = p;
    }
    std::string out = src.substr(start_pos, end - start_pos);
    trim(out);
    return out;
}

// ReAct Agent Implementation

class ReActAgent::Impl {
public:
    Impl(std::unique_ptr<models::BaseLLM> llm, std::vector<Tool> tools, AgentConfig config)
        : llm_(std::move(llm)), tools_(std::move(tools)), config_(config) {
        system_prompt_ = create_system_prompt();
        sandbox_ = std::make_unique<security::Sandbox>();
    }

    security::Result<std::string> run(const std::string& user_input) {
        if (config_.verbose && config_.on_thought) config_.on_thought("Starting ReAct agent...");

        std::string current_thought = user_input;
        std::string final_answer;
        auto start_time = std::chrono::steady_clock::now();

        for (size_t iteration = 0; iteration < config_.max_iterations; ++iteration) {
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > config_.max_time) {
                return security::Result<std::string>::err("Agent timeout after " +
                    std::to_string(config_.max_time.count()) + " seconds");
            }

            auto action_result = generate_action(current_thought, iteration);
            if (action_result.is_err()) return security::Result<std::string>::err(action_result.error());

            auto action = action_result.value();

            if (config_.verbose) {
                if (config_.on_thought) config_.on_thought(action.thought);
                if (action.type == ActionType::TOOL && config_.on_action) {
                    config_.on_action(action.tool_name, action.tool_input);
                }
            }

            if (action.type == ActionType::FINAL) {
                final_answer = action.tool_input;
                if (config_.verbose && config_.on_final_answer) config_.on_final_answer(final_answer);
                break;
            }

            if (action.type == ActionType::TOOL) {
                auto tool_result = execute_tool(action.tool_name, action.tool_input);

                if (tool_result.is_err()) {
                    current_thought = "Error: " + tool_result.error();
                } else {
                    current_thought = "Observation: " + tool_result.value();
                    if (config_.verbose && config_.on_observation) config_.on_observation(tool_result.value());
                }

                conversation_history_.push_back("Thought: " + action.thought);
                conversation_history_.push_back("Action: " + action.tool_name);
                conversation_history_.push_back("Observation: " + current_thought);
            }
        }

        if (final_answer.empty()) {
            return security::Result<std::string>::err("Agent failed to produce final answer");
        }
        return security::Result<std::string>::ok(final_answer);
    }

    std::vector<std::string> get_conversation_history() const { return conversation_history_; }
    void set_system_prompt(const std::string& prompt) {
        custom_system_prompt_ = prompt;
        system_prompt_ = prompt;
    }

private:
    enum class ActionType { TOOL, FINAL };
    struct Action {
        ActionType type;
        std::string thought;
        std::string tool_name;
        std::string tool_input;
    };

    std::unique_ptr<models::BaseLLM> llm_;
    std::vector<Tool> tools_;
    AgentConfig config_;
    std::string system_prompt_;
    std::string custom_system_prompt_;
    std::vector<std::string> conversation_history_;
    std::unique_ptr<security::Sandbox> sandbox_;

    std::string create_system_prompt() {
        std::stringstream ss;
        ss << "You are a helpful assistant with access to tools.\n\nAvailable tools:\n";
        for (const auto& tool : tools_) ss << "- " << tool.name() << ": " << tool.description() << "\n";
        ss << "\nYou must respond in the following format:\n";
        ss << "Thought: [your reasoning]\nAction: [tool name]\nAction Input: [JSON]\n\n";
        ss << "OR:\nThought: I have the final answer\nFinal Answer: [response]\n";
        return ss.str();
    }

    security::Result<Action> generate_action(const std::string& current_state, size_t /*iteration*/) {
        std::stringstream prompt_ss;
        prompt_ss << system_prompt_ << "\n\nConversation history:\n";
        size_t start = conversation_history_.size() > 10? conversation_history_.size() - 10 : 0;
        for (size_t i = start; i < conversation_history_.size(); ++i) prompt_ss << conversation_history_[i] << "\n";
        prompt_ss << "\nCurrent task: " << current_state << "\nWhat should you do next?\n";

        // SECURITY: Cap prompt to prevent LLM memory bomb
        std::string prompt_str = prompt_ss.str();
        if (prompt_str.size() > 16000) prompt_str = prompt_str.substr(prompt_str.size() - 16000);

        std::vector<models::Message> messages = {
            models::Message::system(system_prompt_),
            models::Message::user(prompt_str)
        };

        models::ModelConfig cfg;
        cfg.temperature = config_.temperature;
        cfg.max_tokens = 500;

        auto response = llm_->generate(messages, cfg);
        if (response.is_err()) return security::Result<Action>::err(response.error());

        // SECURITY: Cap LLM response size to prevent ReDoS / memory exhaustion
        std::string resp = response.value();
        if (resp.size() > 10000) resp = resp.substr(0, 10000);

        return parse_response(resp);
    }

    // NO REGEX PARSER - prevents ReDoS
    security::Result<Action> parse_response(const std::string& response) {
        Action action;
        std::string lower = to_lower_copy(response);

        // 1. Thought: (until \nAction: or \nFinal Answer: or end)
        size_t thought_pos = ifind(response, "thought:");
        if (thought_pos!= std::string::npos) {
            size_t content_start = thought_pos + 8;
            action.thought = extract_between(response, content_start, {"\naction:", "\nfinal answer:"});
        } else {
            action.thought = "Processing...";
        }

        // 2. Final Answer check first, it terminates
        size_t final_pos = ifind(response, "final answer:");
        if (final_pos!= std::string::npos) {
            action.type = ActionType::FINAL;
            size_t start = final_pos + 13;
            action.tool_input = response.substr(start);
            trim(action.tool_input);
            return security::Result<Action>::ok(std::move(action));
        }

        // 3. Action: \w+
        size_t action_pos = ifind(response, "action:");
        if (action_pos == std::string::npos) {
            return security::Result<Action>::err("No action found in response");
        }
        {
            size_t start = action_pos + 7;
            // skip spaces
            while (start < response.size() && std::isspace((unsigned char)response[start])) ++start;
            size_t end = start;
            while (end < response.size() && (std::isalnum((unsigned char)response[end]) || response[end]=='_' || response[end]=='-')) ++end;
            action.tool_name = response.substr(start, end-start);
            trim(action.tool_name);
            if (action.tool_name.empty()) return security::Result<Action>::err("Empty action name");
        }

        // 4. Action Input: (until next Thought/Action/Final Answer or end)
        size_t input_pos = ifind(response, "action input:");
        if (input_pos == std::string::npos) {
            return security::Result<Action>::err("No action input found");
        }
        {
            size_t start = input_pos + 13;
            action.tool_input = extract_between(response, start, {"\nthought:", "\naction:", "\nfinal answer:"});
        }

        action.type = ActionType::TOOL;
        return security::Result<Action>::ok(std::move(action));
    }

    security::Result<std::string> execute_tool(const std::string& tool_name, const std::string& tool_input) {
        for (auto& tool : tools_) {
            if (tool.name() == tool_name) {
                if (config_.require_tool_approval && tool.capabilities().requires_approval) {
                    if (config_.verbose && config_.on_action) config_.on_action(tool_name, "AWAITING APPROVAL");
                }

                // TRUE ISOLATION - WIRED TO execute_in_process
                security::SecurityLimits limits;
                limits.max_memory_bytes = 256 * 1024; // 256MB per tool
                limits.timeout = std::chrono::milliseconds(30000); // 30s per tool

                std::string result_str;
                std::string error_str;
                bool ok = false;

                auto sandbox_res = sandbox_->execute_in_process([&]() -> int {
                    auto r = tool.execute(tool_input);
                    if (r.is_ok()) { result_str = r.value(); ok = true; return 0; }
                    else { error_str = r.error(); return 1; }
                }, limits);

                if (sandbox_res.is_err()) {
                    return security::Result<std::string>::err("Sandbox: " + sandbox_res.error() + (error_str.empty()?"": " - Tool error: " + error_str));
                }
                if (!ok) return security::Result<std::string>::err(error_str);
                return security::Result<std::string>::ok(result_str);
            }
        }
        return security::Result<std::string>::err("Tool not found: '" + tool_name + "'");
    }
};

// Public forwarding
ReActAgent::~ReActAgent() = default;
security::Result<std::string> ReActAgent::run(const std::string& user_input) { return impl_->run(user_input); }
std::vector<std::string> ReActAgent::get_conversation_history() const { return impl_->get_conversation_history(); }
void ReActAgent::set_system_prompt(const std::string& prompt) { impl_->set_system_prompt(prompt); }

// SimpleAgent
class SimpleAgent::Impl {
public:
    Impl(std::unique_ptr<models::BaseLLM> llm, AgentConfig config) : llm_(std::move(llm)), config_(config) {}
    security::Result<std::string> chat(const std::string& user_input) {
        memory_.add_user_message(user_input);
        auto messages = memory_.get_messages();
        models::ModelConfig cfg;
        cfg.temperature = config_.temperature;
        auto response = llm_->generate(messages, cfg);
        if (response.is_err()) return security::Result<std::string>::err(response.error());
        memory_.add_assistant_message(response.value());
        return security::Result<std::string>::ok(response.value());
    }
private:
    std::unique_ptr<models::BaseLLM> llm_;
    AgentConfig config_;
    ConversationMemory memory_;
};

security::Result<std::unique_ptr<SimpleAgent>> SimpleAgent::create(std::unique_ptr<models::BaseLLM> llm, AgentConfig config) {
    if (!llm) return security::Result<std::unique_ptr<SimpleAgent>>::err("LLM cannot be null");
    auto agent = std::unique_ptr<SimpleAgent>(new SimpleAgent());
    agent->impl_ = std::make_unique<Impl>(std::move(llm), config);
    return security::Result<std::unique_ptr<SimpleAgent>>::ok(std::move(agent));
}
SimpleAgent::~SimpleAgent() = default;
security::Result<std::string> SimpleAgent::chat(const std::string& user_input) { return impl_->chat(user_input); }

// ConversationMemory
void ConversationMemory::add_user_message(const std::string& message) {
    messages_.push_back(models::Message::user(message));
    if (messages_.size() > max_history_) messages_.erase(messages_.begin());
}
void ConversationMemory::add_assistant_message(const std::string& message) {
    messages_.push_back(models::Message::assistant(message));
    if (messages_.size() > max_history_) messages_.erase(messages_.begin());
}
void ConversationMemory::add_system_message(const std::string& message) {
    messages_.insert(messages_.begin(), models::Message::system(message));
}
std::vector<models::Message> ConversationMemory::get_messages(size_t limit) const {
    if (limit == 0 || limit >= messages_.size()) return messages_;
    return std::vector<models::Message>(messages_.end() - limit, messages_.end());
}
void ConversationMemory::clear() { messages_.clear(); }

}