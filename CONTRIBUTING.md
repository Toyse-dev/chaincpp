# Contributing to chaincpp

Thanks for checking out chaincpp! We are building a zero-overhead, security-first C++20 alternative to LangChain that runs completely offline on 8GB laptops. 

Because this is a native security library, we maintain strict requirements for memory safety and defensive programming, but we are highly welcoming to contributors of all skill levels.

---

## Quick Start for Contributors

```bash
# 1. Clone your personal fork
git clone https://github.com/Toyse-dev/chaincpp
cd chaincpp

# 2. Configure and build framework targets
cmake -B build
cmake --build build -j2

# 3. Verify the automated regression test tree
cd build && ctest --output-on-failure
```

If all tests return a green pass, your local workspace environment is fully synchronized and ready!

---

## What We Need Most (v0.1 -> v0.2)

You do not need an advanced systems architecture background to help out. We highly welcome everything from minor documentation typo fixes to core module feature additions:

* **Vector Store Optimizations**: SQLite integration + local matrix cosine similarity filters.
* **Multi-Language Extensions**: Python bindings (via `nanobind`/`pybind11`) and Node.js extensions.
* **Hardware Profile Testing**: Testing quantized GGUF file performance limits on low-RAM devices.
* **Documentation & Examples**: Clean walkthrough scripts showing native tool routing chains.

---

## Non-Negotiable Core Principles

If you are modifying core source files or logic engines, your contributions must preserve these security invariants:

1. **Defense-in-Depth**: All text payloads from external files, LLMs, or user prompts must cross an explicit sanitation, allowlisting, or multi-process sandbox boundary (`Sandbox::execute_in_process`).
2. **No Secret Leaks**: Sensitive material (API keys, infrastructure tokens) must be held in `secure_string` (`mlock`/`VirtualLock` + volatile zeroing) containers for long-term storage. Temporary `std::string` copies are permitted only when strictly required by a third-party API interface (e.g., cURL headers) and must be zeroed out immediately after use with `secure_zero`.
3. **Smart Pointer Ownership**: Never track heap allocations using raw pointers (`Type*`). Use `std::unique_ptr` or `std::shared_ptr` to enforce explicit ownership semantics.
4. **Enforced Handshake TLS**: Network requests must validate encryption endpoints natively (`CURLOPT_SSL_VERIFYPEER = 1`, `CURLOPT_SSL_VERIFYHOST = 2`) via the host OS certificate channel.

---

## Code Style Guidelines

* **Compiler Safety**: Ensure your code builds cleanly with zero compilation warnings or type crashes across all toolchains (`-Wall -Wextra -Wpedantic -Werror` compliance) across GCC, Clang, and MSVC.
* **Modern Semantics**: Prefer passing variables by constant reference (`const&`) and utilize `std::string_view` for read-only text parameters.
* **Exception Isolation**: Wrap internal `llama.cpp` sequence and libcurl callbacks tightly inside localized `try/catch (...)` blocks to prevent external dependency library errors from triggering an immediate runtime crash.
* **Signature Alignment**: Keep function parameters, default values, and `const` qualifiers fully in sync between your header (`.hpp`) specifications and source (`.cpp`) implementation blocks.

---

## Pull Request Flow

1. Fork the repository and branch off from `main` using an explicit branch name naming convention:
   ```bash
   git checkout -b feature/your-feature
   # Or for bug fixes
   git checkout -b fix/your-bug
   ```
2. Write your code changes. If you are adding core engine logic, remember to append a corresponding automated unit test case inside the `tests/` directory.
3. Run your build and verify the regression testing execution suites:
   ```bash
   cmake --build build -j2
   cd build && ctest --output-on-failure
   ```
   All 4 core test pipelines (`SandboxSecurityTests`, `PromptSecurityTests`, `ModelTests`, and `AgentRegistrySecurityTests`) must return a perfect clean pass on Linux, macOS, and Windows environments.
4. Commit your changes using clean semantic formatting markers (`fix:`, `feature:`, `docs:`), push your branch, and open a Pull Request against `main`!

---

## For Maintainers

The structural automation CI matrix actively targets `ubuntu-latest`, `macos-latest`, and `windows-latest` runners. Note that the custom sandbox memory baseline verification routine intentionally allocates a `500MB` layout space block against a strict enforced limit of `100MB`. This run path is expected to be intentionally terminated by the framework's internal RSS growth tracking mechanism, rather than failing standard allocations via a throw of `std::bad_alloc`.

***

Thank you for helping make local, secure LLM tooling practical!
