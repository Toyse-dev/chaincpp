cmake_minimum_required(VERSION 3.20)
project(chaincpp VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options toggle (Deafult OFF for fast compilation safety)
option(CHAINCOO_STATIC_EXE "Build static standalone executable binaries" OFF)

if (CHAINCPP_STATIC_EXE AND WIN32)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

# Find Dependencies
find_package(Zstd REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(llama REQUIRED)

# Try native config discovery first, fallback safely to PkgConfig for MSYS2 UCRT64 compatibility
find_package(unofficial-sodium CONFIG QUIET)
if(NOT unofficial-sodium_FOUND)
# Use PkgConfig to find libsodium safely on Windows/MSYS2
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)
endif()

# Build options
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)

# Hardened compilation flags
if(MSVC)
    add_compile_options(/W4 /WX /guard:cf /DYNAMICBASE /NXCOMPAT)
    add_compile_options(/D_CRT_SECURE_NO_WARNINGS)
else()
    # Standard warnings
    add_compile_options(-Wall -Wextra -Wpedantic)

    if(WIN32)
        add_link_options(-static -static-libgcc -static-libstdc++)
    endif()
    
    # ONLY apply -z flags if we are on a Unix/Linux system
    if(UNIX AND NOT APPLE)
        add_link_options(-pie -Wl,-z,now,-z,relro)
    endif()
endif()

# Main library
add_library(chaincpp STATIC
    src/security/sandbox.cpp
    src/security/secrets.cpp
    src/core/prompt.cpp
    src/models/llm.cpp
    src/agents/tool.cpp
    src/agents/react_agent.cpp
    src/rag/document.cpp
    src/rag/embeddings.cpp
    src/rag/vector_store.cpp
)

target_link_libraries(chaincpp
    PUBLIC
    CURL::libcurl
    nlohmann_json::nlohmann_json
    PkgConfig::LIBSODIUM
    zstd::libzstd_static
)

# Bind libsodium accurately based on discovery paths
if(unofficial-sodium_FOUND)
    target_link_libraries(chaincpp PUBLIC unofficial-sodium::sodium)
else()
    target_link_libraries(chaincpp PUBLIC PkgConfig::LIBSODIUM)
endif()

# Smart llama target naming check mechanism
if(TARGET llama::llama)
    target_link_libraries(chaincpp PUBLIC llama::llama)
else()
    target_link_libraries(chaincpp PUBLIC llama)
endif()

# Platform-specific libraries for security features
if(WIN32)
    target_link_libraries(chaincpp PRIVATE crypt32 ws2_32 wldap32)
    # Advanced binary exploit protections (CFG, ASLR, DEP)
    target_link_options(chaincpp PRIVATE "/guard:cf" "/DYNAMICBASE" "/NXCOMPAT")
endif()

# For Linux, add pthread if needed
if(UNIX AND NOT APPLE)
    target_link_libraries(chaincpp PRIVATE pthread)
    # Enterprise binary hardening parameters (Position Independent Executable + Relro)
    target_link_options(chaincpp PRIVATE "-pie" "-Wl,-z,now,-z,relro")
endif()

target_include_directories(chaincpp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Set properties for better debugging
target_compile_definitions(chaincpp PRIVATE $<$<CONFIG:Debug>:CHAINCPP_DEBUG>)

# Testing
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_sandbox
        tests/test_sandbox.cpp
    )
    target_link_libraries(test_sandbox chaincpp)
    target_compile_definitions(test_sandbox PRIVATE CHAINCPP_TESTING)
    add_test(NAME SandboxSecurityTests COMMAND test_sandbox)

    add_executable(test_prompt
        tests/test_prompt.cpp
    )
    target_link_libraries(test_prompt chaincpp)
    add_test(NAME PromptSecurityTests COMMAND test_prompt)

    # Model test
    add_executable(test_models tests/test_models.cpp)
    target_link_libraries(test_models chaincpp)
    add_test(NAME ModelTests COMMAND test_models)

    add_executable(test_agents tests/test_agents.cpp)
    target_link_libraries(test_agents chaincpp)
    add_test(NAME AgentRegistrySecurityTests COMMAND test_agents)
endif()

# Examples
if(BUILD_EXAMPLES)
    add_executable(basic_usage
        examples/basic_usage.cpp
    )
    target_link_libraries(basic_usage chaincpp)

    add_executable(prompt_example
        examples/prompt_example.cpp
    )
    target_link_libraries(prompt_example chaincpp)

    # LLM Example
    add_executable(llm_example examples/llm_example.cpp)
    target_link_libraries(llm_example chaincpp)
endif()

# Installation
install(TARGETS chaincpp
    EXPORT chaincppTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/chaincpp DESTINATION include)