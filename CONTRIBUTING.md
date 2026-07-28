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

1. **Defense-in-Depth**: All text payloads from external files, LLMs, or user prompts must cross an explicit sanitation, allowlisting, or multi-process sandbox boundary.
2. **No Secret Leaks**: Sensitive infrastructure keys or tokens must be managed exclusively within the `secure_string` (`mlock`/`VirtualLock` + volatile zeroing) container—never raw `std::string` heaps.
3. **Smart Pointer Ownership**: Never track heap allocations using raw pointers (`Type*`). Use `std::unique_ptr` or `std::shared_ptr`.
4. **Enforced Handshake TLS**: Network requests must validate encryption endpoints natively (`CURLOPT_SSL_VERIFYPEER = 1`, `VERIFYHOST = 2`) via the host OS certificate channel.

---

## Code Style Guidelines

* **Compiler Safety**: Ensure your code builds cleanly with zero compilation warnings or type crashes (`-Werror` compliance) across GCC, Clang, and MSVC.
* **Modern Semantics**: Prefer passing variables by constant reference (`const&`) and utilize `std::string_view` for read-only text parameters.
* **Exception Isolation**: Wrap internal cURL or `llama.cpp` sequence callbacks tightly inside a `try/catch (...)` block to prevent internal errors from triggering an immediate runtime crash.
* **Signature Alignment**: Keep function parameters, default values, and `const` qualifiers fully in sync between your header (`.hpp`) specifications and source (`.cpp`) implementation blocks.

---

## Pull Request Flow

1. Fork the repository and branch off from `main` using an explicit branch name layout:
   ```bash
   git checkout -b feature/your-feature
   # Or for bug fixes
   git checkout -b fix/your-bug
   ```
2. Write your code changes. If you are adding core engine logic, remember to append a corresponding automated test case inside the `tests/` directory.
3. Run your build and verify the regression testing suites:
   ```bash
   cmake --build build
   cd build && ctest --output-on-failure
   ```
4. Commit your changes with a clear message payload, push your branch, and open a Pull Request!
