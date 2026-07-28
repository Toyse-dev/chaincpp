# chaincpp — Security-First LangChain for C++20

A zero-overhead, security-hardened orchestration library for LLMs, Agents, and RAG pipelines. Built for low-latency systems, edge inference, and regulatory enterprise environments.

`chaincpp` delivers a defensive baseline with microsecond-level orchestration overhead, eliminating the virtual environments, interpreter startup lag, and deployment vulnerabilities of Python wrappers.

## 10-Line Hero Snippet

```cpp
#include "chaincpp/chaincpp.hpp"
#include <iostream>

int main() {
    auto llm = chaincpp::models::OpenAIChat::create().value();
    auto prompt = chaincpp::core::PromptTemplate::create("Explain {topic} briefly.").value();
    
    // Microsecond-level, security-isolated orchestration pipeline
    auto response = {{"topic", "RAII Memory Management"}} | prompt | *llm;
    
    std::cout << response.value() << "\n";
    return 0;
}
```

## Quick Start (No API Key or Internet Needed)

`chaincpp` natively embeds `llama.cpp` to run quantized GGUF weights directly on your device with zero cloud dependencies.

```cpp
#include "chaincpp/models/llm.hpp"
#include <iostream>

int main() {
    // Run models fully on-device, offline, completely free
    auto llm = chaincpp::models::LocalLLM::create({
        .model_path = "models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
    }).value();
    
    auto messages = {chaincpp::models::Message::user("Hello local model!")};
    auto response = llm->generate(messages, chaincpp::models::ModelConfig{}).value();
    
    std::cout << response << "\n";
}
```

## Optional: Remote Cloud Models (OpenAI/Anthropic)

To use cloud backends, add your API configurations inside a local `.env` environment layout:
```bash
OPENAI_API_KEY=sk-proj-xxxx
ANTHROPIC_API_KEY=sk-ant-xxxx
```


---

## Core Security Architecture

* **Zero-Interpreter Performance**: Compiles straight to raw machine code with no Python Global Interpreter Lock (GIL), providing predictable under-100ms edge execution.
* **Kernel-Level Sandboxing**: True multi-process isolation leveraging Linux `fork()` and Windows kernel **Job Objects** to forcefully terminate malicious tool executions at the OS layer.
* **Memory-Locked Key Protection**: API tokens are pinned in physical RAM using `VirtualLock`/`mlock` with volatile-forced memory scrubbing in destructors to prevent secrets from swapping onto disk.
* **Prompt Injection Shielding**: Context inputs and multi-turn loops are automatically wrapped within explicit boundary frames and validated using non-regex word-boundary token matching.

---

## Status & Roadmap

`chaincpp` is currently in **v0.1 Alpha**. Core architectures are audited, verified, and stable.

* [x] **Hardened Remote Models**: OpenAI / Anthropic integration with native OS certificate TLS verification.
* [x] **Native Local Inference**: Embedded `llama.cpp` weights execution with dynamic token vector sizing.
* [x] **Safe Document Ingestion**: TextSplitter token formatting with directory traversal block filters.
* [x] **Agent State Machine**: Complete multi-turn ReAct loops utilizing PIMPL encapsulation layouts.
* [ ] **Vector Storage Persistence** (v0.2 Roadmap)
* [ ] **Windows DPAPI Persistent Secrets Storage** (v0.2 Roadmap)

---

## Build and Verification

`chaincpp` utilizes standard CMake configurations and has zero third-party system dependencies.

```bash
# 1. Generate project build targets cleanly
cmake -B build -G "MinGW Makefiles"

# 2. Compile libraries, tests, and code examples
cmake --build build

# 3. Execute the automated regression test tree
cd build && ctest --output-on-failure
```

## License

Distributed under the **MIT License**. See `LICENSE` for details.
