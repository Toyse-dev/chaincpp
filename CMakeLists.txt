cmake_minimum_required(VERSION 3.20)
project(chaincpp VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find Dependencies
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)

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
)

target_link_libraries(chaincpp
    PUBLIC
    CURL::libcurl
    nlohmann_json::nlohmann_json
)

# Platform-specific libraries for security features
if(WIN32)
    target_link_libraries(chaincpp PRIVATE crypt32 ws2_32 wldap32)
endif()

# For Linux, add pthread if needed
if(UNIX AND NOT APPLE)
    target_link_libraries(chaincpp PRIVATE pthread)
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
endif()

# Examples
if(BUILD_EXAMPLES)
    add_executable(basic_usage
        examples/basic_usage.cpp
    )
    target_link_libraries(basic_usage chaincpp)

    # Adding crypt32
    target_link_libraries(chaincpp PUBLIC CURL::libcurl nlohmann_json::nlohmann_json crypt32)

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