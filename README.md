# chaincpp — C++20 LLM orchestration library

A C++20 library for LLM inference, agents, and RAG that runs offline on low-spec hardware. Embeds llama.cpp (b4242) for GGUF inference, with optional remote providers (OpenAI / Anthropic / OpenRouter). No Python runtime required.

* **Tested on:** Intel i3-4005U @ 1.70GHz, 8GB DDR3, Intel HD Graphics, Windows 11, CPU-only.
* **Offline test:** *What is the capital of Nigeria?* → Abuja (TinyLlama Q4_K_M, no API key, no network).

---

## What it is
* **Local inference:** Loads quantized GGUF via llama.cpp (`llama_load_model_from_file`, `llama_new_context_with_model`, sampler API).
* **Remote inference:** OpenAI / Anthropic / OpenRouter via libcurl with `SSL_VERIFYPEER=1`, `VERIFYHOST=2`, native CA store.
* **Core primitives:** `PromptTemplate` with `format_safe`, `TextSplitter`, simple ReAct agent loop, C ABI in `c_api.h`.
* **Alpha status:** v0.1.0-alpha, API may change. Core local + remote generate is stable on the machine listed above.

### What it is not (yet)
Vector DB persistence, Python pip package, GPU auto-offload. These are scheduled for v0.2.

---

## Quick start — offline, no API key

**Requires:** CMake >=3.20, Ninja or MSYS2 UCRT64 `g++.exe` (C++20), libcurl, nlohmann_json (via vcpkg or FetchContent). 

> **Avoid paths with spaces:** `C:\dev\chaincpp` works perfectly; `C:\Users\...\All my projects\chaincpp` breaks Ninja + MSYS2 include escaping.

```bash
# 1. Clone and get model (636 MB Q4_K_M)
git clone https://github.com/Toyse-dev/chaincpp.git
cd chaincpp
mkdir -p models
curl -L -o models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf

# 2. Build (use -j2 on dual-core hardware)
cmake -B build -G Ninja -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2

# 3. Run local example (fully offline)
./build/examples/local_example
```

On UCRT64 bash, use forward slashes for the benchmark executable:
```bash
./build/benchmark_local.exe models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf 128
```

### Usage Example

```cpp
#include "chaincpp/models/llm.hpp"
#include "chaincpp/core/prompt.hpp"
#include <iostream>

int main() {
    chaincpp::models::LocalLLM::Config cfg;
    cfg.model_path = "models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    cfg.context_size = 512;
    cfg.gpu_layers = 0; // CPU-only

    auto llm_res = chaincpp::models::LocalLLM::create(cfg);
    if (!llm_res) return 1;
    auto llm = std::move(llm_res.value());

    auto prompt_res = chaincpp::core::PromptTemplate::create(
        "<|system|>\nYou are helpful.</s>\n<|user|>\n{question}</s>\n<|assistant|>\n"
    );
    if (!prompt_res) return 1;

    auto formatted = prompt_res.value().format_safe({{"question", "What is the capital of Nigeria?"}});
    if (!formatted) return 1;

    auto resp = llm->generate(
        {chaincpp::models::Message::user(formatted.value())},
        {.max_tokens = 128}
    );
    if (resp) std::cout << resp.value() << "\n";
}
```

### Remote Models (Optional Setup)

Create a local `.env` file (do not commit this to version control):
```text
OPENAI_API_KEY=sk-proj-...
ANTHROPIC_API_KEY=sk-ant-...
OPENROUTER_API_KEY=sk-or-...
```

```cpp
auto llm = chaincpp::models::OpenAIChat::create().value();
auto prompt = chaincpp::core::PromptTemplate::create("Explain {topic} briefly.").value();
auto response = llm->generate({chaincpp::models::Message::user(prompt.format({{"topic","RAII"}}).value())}).value();
```

---

## Benchmarks

Measured with `tests/benchmark_local.cpp` (b4242-compatible manual `llama_batch` fill, `logits=true` for generation, sampler chain `temp=0.7` + dist).

**Hardware:** Intel i3-4005U @ 1.70GHz (2C/4T), 8GB DDR3, Windows 11, UCRT64, CPU-only, `n_threads=4`, `n_ctx=2048`.

| Model | File | Quant | Tokens | Tokens/sec | Model Load | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| TinyLlama 1.1B Chat | tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf | Q4_K_M (4.85 BPW) | 128 | ~25-35 | 636 MiB + 44 MiB KV | First run slower due to kernel compile |

*Peak RSS reports 0 on Windows (getrusage not implemented) and ~650-900 MiB on Linux (model 636 MiB + KV 44 MiB + 148 MiB compute buffer). GitHub Actions ubuntu-latest reproduces Linux numbers.*

To reproduce metrics:
```bash
./build/benchmark_local.exe models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf 128
# output: CSV: chaincpp,<tps>,<rss_mb>
```

---

## Security Notes

Implemented features in `v0.1.0-alpha`:
* **TLS configuration:** `CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`, `CURLSSLOPT_NATIVE_CA` on Windows, `/etc/ssl/certs/ca-certificates.crt` on Linux.
* **Secrets Handling:** `secure_string` with `VirtualLock`/`mlock` + explicit memory zeroing in the destructor. Secrets are not yet persisted.
* **Prompt Handling:** `format_safe` validates token placeholders. The injection filter relies on word-boundary matching instead of regex to protect against Regular Expression Denial of Service (ReDoS) vulnerabilities.
* **Execution Safety:** `execute_safe` wraps tool execution pathways within thread timeouts and structured exception boundaries. OS-level isolation primitives (like Linux seccomp or Windows Job Objects) are on the roadmap but not yet enforced.

---

## Project Layout

* `include/chaincpp/` — Contains `core/prompt.hpp`, `models/llm.hpp`, `security/`, and the C-compatible `c_api.h`.
* `src/models/llm.cpp` — Implements `LocalLLM` (llama.cpp b4242) + OpenAI/Anthropic clients.
* `tests/benchmark_local.cpp` — Script for processing local execution metrics (adapted for the b4242 manual batch API).
* `examples/local_example.cpp` — Sample implementation for offline Q&A scripts.
* `models/` — Local runtime folder for storage of `.gguf` files (ignored by git).

---

## Build and Verification

```bash
cmake -B build -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

> **Troubleshooting Build Failures:** If you log a compiler error stating `llama_batch_add was not declared`, your environment is correctly operating on b4242. Make sure you utilize manual batch array fills exactly as structured inside `tests/benchmark_local.cpp`.

---

## Known Limitations
* Build pathways containing system character spaces (e.g. `All my projects`) break MSYS2 Ninja internal include flags. Relocate the library source home to a clean index like `C:\dev\chaincpp`.
* llama.cpp pinned to version b4242 (legacy sampler API `llama_sampler_chain_*` + manual execution allocations). An upgrade to modern runtime releases is planned.
* No internal vector store persistence layer or native Python bindings currently exist. The native C ABI is exposed to accommodate future wrapper generation.
* Windows execution instances tracking `get_peak_rss_mb()` return 0; rely on Linux build metrics for validation.

---

## Roadmap

* [x] Local GGUF inference (CPU execution contexts) featuring safe string detokenization
* [x] Hardened Remote Provider wrappers (OpenAI/Anthropic implementations) using locked TLS
* [x] Modular `TextSplitter` ingestion utilities + deep directory traversal filtering
* [x] Agent state machine management (multi-turn ReAct architecture via PIMPL)
* [x] Universal C ABI layout layer (`c_api.h`) built for Python/Rust/JS bindings
* [ ] Vector Engine Storage Persistence frameworks (Target: `v0.2`)
* [ ] DPAPI / libsecret persistent context storage structures (Target: `v0.2`)
* [ ] Python deployment pathways via native nanobind configurations (`pip install chaincpp`) (Target: `v0.2`)
* [ ] Native sandbox boundaries (Linux `fork()` + `RLIMIT` + `seccomp` / Windows Job Object processing caps)

---

## License

Distributed under the **MIT License**. See `LICENSE` for details. 

Copyright (c) 2026 Toyse-dev.
