#include "chaincpp/chaincpp.hpp"
#include "chaincpp/agents/react_agent.hpp"
#include <regex>
#include <sstream>

namespace chaincpp::agents {

// ReAct Agent Implementation

class ReActAgent::Impl {
public:
    Impl(std::unique_ptr<models::BaseLLM> llm, std::vector<Tool> tools, AgentConfig config)
        : llm_(std::move(llm)), tools_(std::move(tools)), config_(config) {
        
        // Create system prompt
        system_prompt_ = create_system_prompt();
    }
    
    security::Result<std::string> run(const std::string& user_input) {
        if (config_.verbose && config_.on_thought) {
            config_.on_thought("Starting ReAct agent...");
        }
        
        std::string current_thought = user_input;
        std::string final_answer;
        
        auto start_time = std::chrono::steady_clock::now();
        
        for (size_t iteration = 0; iteration < config_.max_iterations; ++iteration) {
            // Check timeout
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > config_.max_time) {
                return security::Result<std::string>::err("Agent timeout after " + 
                    std::to_string(config_.max_time.count()) + " seconds");
            }
            
            // Generate next action
            auto action_result = generate_action(current_thought, iteration);
            if (action_result.is_err()) {
                return security::Result<std::string>::err(action_result.error());
            }
            
            auto action = action_result.value();
            
            if (config_.verbose) {
                if (config_.on_thought) config_.on_thought(action.thought);
                if (action.type == ActionType::TOOL && config_.on_action) {
                    config_.on_action(action.tool_name, action.tool_input);
                }
            }
            
            // Handle different action types
            if (action.type == ActionType::FINAL) {
                final_answer = action.tool_input;
                if (config_.verbose && config_.on_final_answer) {
                    config_.on_final_answer(final_answer);
                }
                break;
            }
            
            if (action.type == ActionType::TOOL) {
                // Execute tool
                auto tool_result = execute_tool(action.tool_name, action.tool_input);
                
                if (tool_result.is_err()) {
                    current_thought = "Error: " + tool_result.error();
                } else {
                    current_thought = "Observation: " + tool_result.value();
                    if (config_.verbose) {
                        if (config_.on_observation) config_.on_observation(tool_result.value());
                    }
                }
                
                // Add to history
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
    
    std::vector<std::string> get_conversation_history() const {
        return conversation_history_;
    }
    
    void set_system_prompt(const std::string& prompt) {
        custom_system_prompt_ = prompt;
        system_prompt_ = prompt;
    }
    
private:
    enum class ActionType {
        TOOL,
        FINAL
    };
    
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
    
    std::string create_system_prompt() {
        std::stringstream ss;
        ss << "You are a helpful assistant with access to tools.\n\n";
        ss << "Available tools:\n";
        
        for (const auto& tool : tools_) {
            ss << "- " << tool.name() << ": " << tool.description() << "\n";
        }
        
        ss << "\nYou must respond in the following format:\n";
        ss << "Thought: [your reasoning about what to do]\n";
        ss << "Action: [tool name]\n";
        ss << "Action Input: [input for the tool in JSON format]\n\n";
        ss << "OR if you have the final answer:\n";
        ss << "Thought: I have the final answer\n";
        ss << "Final Answer: [your response to the user]\n\n";
        ss << "Always use the exact format. For tools, Action Input must be valid JSON.\n";
        
        return ss.str();
    }
    
    security::Result<Action> generate_action(const std::string& current_state, size_t iteration) {
        // Build prompt for LLM
        std::stringstream prompt_ss;
        prompt_ss << system_prompt_ << "\n\n";
        prompt_ss << "Conversation history:\n";
        
        // Show last 5 interactions
        size_t start = conversation_history_.size() > 10 ? conversation_history_.size() - 10 : 0;
        for (size_t i = start; i < conversation_history_.size(); ++i) {
            prompt_ss << conversation_history_[i] << "\n";
        }

        prompt_ss << "\nCurrent task: " << current_state << "\n";
        prompt_ss << "What should you do next?\n";

        // I Explicitly construct the multi-turn messages array using the stringstream text
        std::vector<models::Message> messages = {
            models::Message::system(system_prompt_),
            models::Message::user(prompt_ss.str())
        };
        
        // Generate response
        models::ModelConfig cfg;
        cfg.temperature = config_.temperature;
        cfg.max_tokens = 500;
        
        auto response = llm_->generate(messages, cfg);
        
        if (response.is_err()) {
            return security::Result<Action>::err(response.error());
        }
        
        // Parse response
        return parse_response(response.value());
    }
    
    security::Result<Action> parse_response(const std::string& response) {
        Action action;
        
        // Parse Thought
        std::regex thought_regex(R"(Thought:\s*(.+?)(?=\n(?:Action|Final Answer)|$)", std::regex::icase);
        std::smatch thought_match;
        if (std::regex_search(response, thought_match, thought_regex)) {
            action.thought = thought_match[1].str();
            trim(action.thought);
        } else {
            action.thought = "Processing...";
        }
        
        // Check for Final Answer
        std::regex final_regex(R"(Final Answer:\s*(.+?)$)", std::regex::icase);
        std::smatch final_match;
        if (std::regex_search(response, final_match, final_regex)) {
            action.type = ActionType::FINAL;
            action.tool_input = final_match[1].str();
            trim(action.tool_input);
            return security::Result<Action>::ok(action);
        }
        
        // Parse Action
        std::regex action_regex(R"(Action:\s*(\w+))", std::regex::icase);
        std::smatch action_match;
        if (std::regex_search(response, action_match, action_regex)) {
            action.tool_name = action_match[1].str();
        } else {
            return security::Result<Action>::err("No action found in response");
        }
        
        // Parse Action Input
        std::regex input_regex(R"(Action Input:\s*(.+?)(?=\n(?:Thought|Action|Final Answer)|$)", std::regex::icase);
        std::smatch input_match;
        if (std::regex_search(response, input_match, input_regex)) {
            action.tool_input = input_match[1].str();
            trim(action.tool_input);
        } else {
            return security::Result<Action>::err("No action input found");
        }
        
        action.type = ActionType::TOOL;
        
        return security::Result<Action>::ok(std::move(action));
    }
    
    security::Result<std::string> execute_tool(const std::string& tool_name, const std::string& tool_input) {
        for (auto& tool : tools_) {
            if (config_.require_tool_approval && tool.capabilities().requires_approval) {
                if (config_.verbose) {
                    if (config_.on_action) config_.on_action(tool_name, "AWAITING APPROVAL");
                    if (config_.on_observation) config_.on_observation("Tool approved for execution");
                }
            }
            if (tool.name() == tool_name) {
                return tool.execute(tool_input);
            }
        }
        return security::Result<std::string>::err("Tool not found: '" + tool_name + " ' is not registered in the agent's toolset.");
    }

    // Helper method to strip out whitespace blocks safely
    void trim(std::string& s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), s.end());
    }
};

// Public ReActAgent Class Interface Forwarding Blocks

ReActAgent::ReActAgent() = default;

ReActAgent::~ReActAgent() = default;

security::Result<std::string> ReActAgent::run(const std::string& user_input) {
    return impl_->run(user_input);
}

security::Result<std::string> ReActAgent::run(const std::string& user_input) {
    return impl_->run(user_input);
}

std::vector<std::string> ReActAgent::get_conversation_history() const {
    return impl_->get_conversation_history();
}

void ReActAgent::set_system_prompt(const std::string& prompt) {
    impl_->set_system_prompt(prompt);
}

// SimpleAgent Implementation

class SimpleAgent::Impl {
public:
    Impl(std::unique_ptr<models::BaseLLM> llm, AgentConfig config)
        : llm_(std::move(llm)), config_(config) {}
    
    security::Result<std::string> chat(const std::string& user_input) {
        memory_.add_user_message(user_input);
        
        auto messages = memory_.get_messages();

        //  Uses standard property assignment to avoid C++20 designated initializer bugs
        models::ModelConfig cfg;
        cfg.temperature = config_.temperature;

        auto response = llm_->generate(messages, cfg);
        
        if (response.is_err()) {
            return security::Result<std::string>::err(response.error());
        }
        
        memory_.add_assistant_message(response.value());
        return security::Result<std::string>::ok(response.value());
    }
    
private:
    std::unique_ptr<models::BaseLLM> llm_;
    AgentConfig config_;
    ConversationMemory memory_;
};

security::Result<std::unique_ptr<SimpleAgent>> SimpleAgent::create(
    std::unique_ptr<models::BaseLLM> llm,
    AgentConfig config
) {
    if (!llm) {
        return security::Result<std::unique_ptr<SimpleAgent>>::err("LLM cannot be null");
    }
    
    auto agent = std::unique_ptr<SimpleAgent>(new SimpleAgent());
    agent->impl_ = std::make_unique<Impl>(std::move(llm), config);
    
    return security::Result<std::unique_ptr<SimpleAgent>>::ok(std::move(agent));
}

SimpleAgent::~SimpleAgent() = default;

security::Result<std::string> SimpleAgent::chat(const std::string& user_input) {
    return impl_->chat(user_input);
}

// ConversationMemory Implementation

void ConversationMemory::add_user_message(const std::string& message) {
    messages_.push_back(models::Message::user(message));
    if (messages_.size() > max_history_) {
        messages_.erase(messages_.begin());
    }
}

void ConversationMemory::add_assistant_message(const std::string& message) {
    messages_.push_back(models::Message::assistant(message));
    if (messages_.size() > max_history_) {
        messages_.erase(messages_.begin());
    }
}

void ConversationMemory::add_system_message(const std::string& message) {
    messages_.insert(messages_.begin(), models::Message::system(message));
}

std::vector<models::Message> ConversationMemory::get_messages(size_t limit) const {
    if (limit == 0 || limit >= messages_.size()) {
        return messages_;
    }
    return std::vector<models::Message>(
        messages_.end() - limit,
        messages_.end()
    );
}

void ConversationMemory::clear() {
    messages_.clear();
}

} // namespace chaincpp::agents