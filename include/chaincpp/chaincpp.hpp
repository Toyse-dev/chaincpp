#pragma once

#include "security/sandbox.hpp"
#include "security/secrets.hpp"
#include "core/prompt.hpp"
#include "models/llm.hpp"
#include <map>
#include <string>
#include <vector>
#include <utility>

namespace chaincpp {

// PipelineInput wrapper to safely transport local std::map variable states
struct PipelineInput {
    std::map<std::string, std::string> vars;
};

// Step 1: Bind inputs map straight to a prompt template target (vars | template)
inline std::pair<const core::PromptTemplate&, std::map<std::string, std::string>> operator|(
    std::map<std::string, std::string> vars,
    const core::PromptTemplate& prompt_template
) {
    return {prompt_template, std::move(vars)};
}

// Step 2: Feed that pipeline bundle directly into an LLM engine instance ((vars | template) | llm)
inline security::Result<std::string> operator|(
    std::pair<const core::PromptTemplate&, std::map<std::string, std::string>> pipeline,
    models::BaseLLM& llm
) {
    // Format variables using my validated secure logic layer
    auto format_res = pipeline.first.format_safe(pipeline.second);
    if (format_res.is_err()) {
        return security::Result<std::string>::err(format_res.error());
    }

    // Build the standardized multi-turn message vector payload
    std::vector<models::Message> messages = {
        models::Message::user(format_res.value())
    };

    // Execute completion through the runtime client
    return llm.generate(messages);
}

}
