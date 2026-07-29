# chaincpp — Security-First LangChain for C++20

A zero-overhead, security-hardened orchestration library for LLMs, Agents, and RAG pipelines. Built for low-latency systems, edge inference, and regulated enterprise environments.

Compiles to a 20MB static binary, no Python, no venv, no interpreter lag. Runs fully offline.

> **v0.1.0-alpha proven on:** Intel i3-4005U @ 1.70GHz, 8GB DDR3, Intel HD, CPU-only, Windows.
> Offline Q&A: "What is the capital of Nigeria?" → **"Abuja"** — no API key, no internet.

---

## Quick Start (No API Key, No Internet, Free)

`chaincpp` embeds `llama.cpp` and runs quantized GGUF directly on-device.

```bash
# 1. Download tiny model (~600MB, needs 1.2GB RAM)
mkdir -p models
curl -L -o models/tinyllama-1.1b.gguf https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf

# 2. Build (use -j2 on 2-core i3)
cmake -B build
cmake --build build -j2

# 3. Run — fully offline
./build/examples/local_example
# Response: Correct Answer: Abuja
```

```cpp
#include "chaincpp/models/llm.hpp"
#include "chaincpp/core/prompt.hpp"
#include <iostream>

int main() {
    chaincpp::models::LocalLLM::Config cfg;
    cfg.model_path = "models/tinyllama-1.1b.gguf";
    cfg.context_size = 512; // low RAM friendly
    cfg.gpu_layers = 0; // CPU-only, works on i3
    
    auto llm = chaincpp::models::LocalLLM::create(cfg).value();
    
    auto prompt = chaincpp::core::PromptTemplate::create(
        "<|system|>\nYou are helpful.</s>\n<|user|>\n{question}</s>\n<|assistant|>\n"
    ).value();
    
    auto formatted = prompt.format_safe({{"question", "What is the capital of Nigeria?"}}).value();
    
    auto response = llm->generate(
        {chaincpp::models::Message::user(formatted)},
        {.max_tokens = 128}
    ).value();
    
    std::cout << response << "\n"; // -> Abuja
}
```

---

## Optional: Remote Models (OpenAI / Anthropic / OpenRouter)

```bash
# .env — never commit this file
OPENAI_API_KEY=sk-proj-xxxx
ANTHROPIC_API_KEY=sk-ant-xxxx
# OpenRouter has free models, no credit card: openrouter.ai
OPENROUTER_API_KEY=sk-or-xxxx
```

```cpp
#include "chaincpp/models/llm.hpp"
#include "chaincpp/core/prompt.hpp"
#include <iostream>

int main() {
    auto llm = chaincpp::models::OpenAIChat::create().value(); // reads OPENAI_API_KEY
    auto prompt = chaincpp::core::PromptTemplate::create("Explain {topic} briefly.").value();
    auto formatted = prompt.format({{"topic", "RAII"}}).value();
    auto response = llm->generate({chaincpp::models::Message::user(formatted)}).value();
    std::cout << response << "\n";
}
```

---

## Core Security Architecture

* **Zero-Interpreter**: C++20, no GIL, no venv. Predictable latency for edge.
* **Execution Isolation**: v0.1 execute_safe with thread timeout + exception boundaries. v0.2: Linux fork()+RLIMIT_AS/CPU+seccomp, Windows Job Objects JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE + JobMemoryLimit (kernel-enforced).
* **Memory-Locked Secrets**: API keys in secure_string with VirtualLock / mlock + volatile zeroing on destruction. No swap, no core dump.
* **Prompt Injection Shield**: No regex (prevents ReDoS). Word-boundary token matching blocks ignore previous instructions, system prompt, etc., without false positives on names like "Jordan".
* **Hardened TLS**: CURLOPT_SSL_VERIFYPEER=1, VERIFYHOST=2, native CA store (CURLSSLOPT_NATIVE_CA on Windows, /etc/ssl/certs/ca-certificates.crt on Linux).

---

## Status & Roadmap

chaincpp is v0.1.0-alpha — core local + remote inference stable and tested on low-spec hardware.

* [x] Hardened Remote Models (OpenAI / Anthropic) with native TLS
* [x] Native Local Inference (llama.cpp GGUF) with safe detokenization
* [x] Safe Document Ingestion (TextSplitter + traversal checks)
* [x] Agent State Machine (multi-turn ReAct with PIMPL)
* [x] C ABI (c_api.h) for future Python/Rust/JS bindings
* [ ] Vector Storage Persistence (v0.2)
* [ ] DPAPI + libsecret Persistent Secrets (v0.2)
* [ ] pip install chaincpp via nanobind (v0.2)

---

## Build and Verification

**Dependencies:** libcurl, nlohmann_json, llama.cpp, libsodium (via vcpkg/CMake).

```bash
cmake -B build
cmake --build build -j2
cd build && ctest --output-on-failure
```

---

## Why C++20?

LangChain Python needs 2GB venv and can't run securely offline on 8GB edge devices. chaincpp is 20MB, offline, with mlock secrets and OS-level isolation that Python cannot enforce. Long-term: One secure C++ core, thin wrappers for Python, Rust, Node.

---

## License

Distributed under the **MIT License**. See `LICENSE` for details. 
Copyright (c) 2026 Toyse-dev.
