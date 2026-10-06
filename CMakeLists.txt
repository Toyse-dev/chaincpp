cmake_minimum_required(VERSION 3.20)
project(chaincpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CHAINCPP_STATIC_EXE "Build static standalone executable" OFF)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)

# Static linking only if explicitly requested
if(CHAINCPP_STATIC_EXE AND WIN32 AND NOT MSVC)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

include(FetchContent)

# --- Dependencies ---
find_package(CURL REQUIRED)

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found, fetching")
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# --- llama.cpp : single, shallow clone ---
# Disable ccache for llama (your earlier fix for CI)
set(LLAMA_CCACHE OFF CACHE BOOL "" FORCE)
set(GGML_CCACHE OFF CACHE BOOL "" FORCE)
set(CMAKE_C_COMPILER_LAUNCHER "" CACHE STRING "" FORCE)
set(CMAKE_CXX_COMPILER_LAUNCHER "" CACHE STRING "" FORCE)

# If you have a local copy at C:/dev/llama.cpp or external/llama.cpp, use it to save data
if(EXISTS "C:/dev/llama.cpp/CMakeLists.txt")
    message(STATUS "Using local llama.cpp at C:/dev/llama.cpp")
    add_subdirectory(C:/dev/llama.cpp ${CMAKE_BINARY_DIR}/_deps/llama-build)
elseif(EXISTS ${CMAKE_SOURCE_DIR}/external/llama.cpp/CMakeLists.txt)
    message(STATUS "Using local llama.cpp at external/llama.cpp")
    add_subdirectory(${CMAKE_SOURCE_DIR}/external/llama.cpp ${CMAKE_BINARY_DIR}/_deps/llama-build)
else()
    FetchContent_Declare(
        llama
        GIT_REPOSITORY https://github.com/ggerganov/llama.cpp.git
        GIT_TAG b4242
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
    )
    FetchContent_MakeAvailable(llama)
endif()

if(TARGET llama)
    target_compile_options(llama PRIVATE -Wno-error -Wno-deprecated-declarations)
endif()
if(TARGET ggml)
    target_compile_options(ggml PRIVATE -Wno-error)
endif()
if(TARGET ggml-base)
    target_compile_options(ggml-base PRIVATE -Wno-error)
endif()

find_package(PkgConfig REQUIRED)
find_package(unofficial-sodium CONFIG QUIET)
if(NOT unofficial-sodium_FOUND)
    pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)
endif()
find_package(Zstd QUIET)

# --- Hardened flags ---
if(MSVC)
    add_compile_options(/W4 /DYNAMICBASE /NXCOMPAT /D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(UNIX AND NOT APPLE)
        add_link_options(-pie -Wl,-z,now,-z,relro)
    endif()
endif()

# --- Main library ---
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

target_include_directories(chaincpp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(chaincpp PUBLIC
    CURL::libcurl
    nlohmann_json::nlohmann_json
)

if(unofficial-sodium_FOUND)
    target_link_libraries(chaincpp PUBLIC unofficial-sodium::sodium)
else()
    target_link_libraries(chaincpp PUBLIC PkgConfig::LIBSODIUM)
endif()

if(Zstd_FOUND)
    target_link_libraries(chaincpp PUBLIC zstd::libzstd_static)
endif()

if(TARGET llama::llama)
    target_link_libraries(chaincpp PUBLIC llama::llama)
elseif(TARGET llama)
    target_link_libraries(chaincpp PUBLIC llama)
endif()

if(WIN32)
    target_link_libraries(chaincpp PRIVATE crypt32 ws2_32 wldap32)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(chaincpp PRIVATE pthread)
endif()

target_compile_definitions(chaincpp PRIVATE $<$<CONFIG:Debug>:CHAINCPP_DEBUG>)

# --- Testing ---
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_sandbox tests/test_sandbox.cpp)
    target_link_libraries(test_sandbox PRIVATE chaincpp)
    target_compile_definitions(test_sandbox PRIVATE CHAINCPP_TESTING)
    add_test(NAME SandboxSecurityTests COMMAND test_sandbox)

    add_executable(test_prompt tests/test_prompt.cpp)
    target_link_libraries(test_prompt PRIVATE chaincpp)
    add_test(NAME PromptSecurityTests COMMAND test_prompt)

    # These two need model file / key - will be skipped on Windows CI via ctest -R
    if(EXISTS ${CMAKE_SOURCE_DIR}/tests/test_models.cpp)
        add_executable(test_models tests/test_models.cpp)
        target_link_libraries(test_models PRIVATE chaincpp)
        add_test(NAME ModelTests COMMAND test_models)
    elseif(EXISTS ${CMAKE_SOURCE_DIR}/tests/test_model.cpp)
        add_executable(test_models tests/test_model.cpp)
        target_link_libraries(test_models PRIVATE chaincpp)
        add_test(NAME ModelTests COMMAND test_models)
    endif()

    if(EXISTS ${CMAKE_SOURCE_DIR}/tests/test_agents.cpp)
        add_executable(test_agents tests/test_agents.cpp)
        target_link_libraries(test_agents PRIVATE chaincpp)
        add_test(NAME AgentRegistrySecurityTests COMMAND test_agents)
    elseif(EXISTS ${CMAKE_SOURCE_DIR}/tests/test_agent.cpp)
        add_executable(test_agents tests/test_agent.cpp)
        target_link_libraries(test_agents PRIVATE chaincpp)
        add_test(NAME AgentRegistrySecurityTests COMMAND test_agents)
    endif()

    if(EXISTS ${CMAKE_SOURCE_DIR}/tests/benchmark_local.cpp)
        add_executable(benchmark_local tests/benchmark_local.cpp)
        if(TARGET llama::llama)
            target_link_libraries(benchmark_local PRIVATE chaincpp llama::llama)
        else()
            target_link_libraries(benchmark_local PRIVATE chaincpp llama)
        endif()
    endif()
endif()

# --- Examples ---
if(BUILD_EXAMPLES)
    add_executable(basic_usage examples/basic_usage.cpp)
    target_link_libraries(basic_usage PRIVATE chaincpp)
    add_executable(prompt_example examples/prompt_example.cpp)
    target_link_libraries(prompt_example PRIVATE chaincpp)
    add_executable(local_example examples/local_example.cpp)
    target_link_libraries(local_example PRIVATE chaincpp)
    add_executable(llm_example examples/llm_example.cpp)
    target_link_libraries(llm_example PRIVATE chaincpp)
endif()

install(TARGETS chaincpp EXPORT chaincppTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(DIRECTORY include/chaincpp DESTINATION include)
