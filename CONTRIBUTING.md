# Contributing to chaincpp

Thank you for your interest in contributing to `chaincpp`! This framework is built to be a security-first, low-overhead C++20 alternative to LangChain. 

Because this is a security library operating in native code, we maintain exceptionally high standards for memory safety, architectural patterns, and defensive programming.

---

## Core Architectural Principles

When writing code for `chaincpp`, you must adhere to the following principles:

1. **Defense-in-Depth**: Never trust external inputs. All raw inputs from LLMs, users, or filesystems must cross an explicit sanitation, allowlisting, or sandbox boundary.
2. **Sub-Millisecond Overhead**: Avoid heavy heap allocations inside processing loops. Use contiguous memory containers (`std::vector`, `std::string_view`) and pass variables by constant reference where possible.
3. **Encapsulation (PIMPL)**: High-level public APIs (like Agents or Chains) should expose clean interfaces. Hide state variables and external dependencies inside private implementation (`Impl`) classes to protect translation units.
4. **No Cross-Platform Handshake Drops**: Network operations must be cross-platform compatible and leverage native operating system certificate stores (`CURLSSLOPT_NATIVE_CA` on Windows).

---

## Code Style & Defensive Requirements

### 1. Memory Safety & Pinned Secrets
* Never use raw pointers (`Type*`) for ownership tracking; utilize `std::unique_ptr` or `std::shared_ptr`.
* Sensitive authentication strings (like API keys) must always be stored in the custom `secure_string` container to ensure they call `VirtualLock`/`mlock` and clear memory physically upon destruction.

### 2. Strict C++20 Compliance
* **No JavaScript Short-Circuits**: Do not use `&&` to conditionally evaluate `void` lambdas. Use explicit `if` statements.
* **No Mixed Designated Initializers**: Avoid using designated initializers (`.param = x`) on structures containing default in-class initializers inside standard templates to prevent MinGW GCC compilation flags from breaking.

### 3. Exception Boundaries
* Network callbacks (like cURL write streams) or sandboxed tool execution paths must be wrapped inside a `try/catch (...)` block. Never allow exceptions to leak into third-party library execution loops, which triggers immediate runtime crashes.

---

## Git Workflow & Pull Requests

We follow a structured pull request branch workflow:

1. **Fork the Repository**: Create a personal fork of the engine repository workspace.
2. **Create a Feature Branch**: Branch off from `main` using a descriptive name:
   ```bash
   git checkout -b feature/secure-dpapi-backend
   # Or for bug fixes
   git checkout -b fix/cosine-similarity-bounds
   ```
3. **Commit Cleanly**: Write meaningful, concise commit messages. Fix trailing spaces or unused variables before pushing.
4. **Keep Signatures Synchronized**: Ensure that any changes to your implementation (`.cpp`) files match both the `const` qualifiers and default parameters declared inside header (`.hpp`) files exactly.

---

## Testing Requirements

We practice strict test-driven development. **No pull request will be merged without matching test coverage.**

* If you add a new capability or module, you must add a corresponding test target inside the `tests/` directory (e.g., `tests/test_rag.cpp`).
* Wire your executable test natively into the root `CMakeLists.txt` configuration using the `add_test()` macro.
* Before submitting a pull request, your branch **must compile to 100% complete** and pass the complete regression testing suite with zero failures:
  ```bash
  cmake -B build -G "MinGW Makefiles"
  cmake --build build
  cd build
  ctest --output-on-failure
  ```

Thank you for helping us build what LangChain should have been!
