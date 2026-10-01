#include "chaincpp/security/sandbox.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>

using namespace chaincpp::security;

int main() {
    std::cout << "\n========================================\n";
    std::cout << "chaincpp Sandbox Security Tests\n";
    std::cout << "========================================\n\n";
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    // Test 1: Safe function execution
    {
        std::cout << "Test 1: Safe function execution... ";
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            return Result<void>::ok();
        }, SecurityLimits::safe_defaults());
        if (result.is_ok()) { std::cout << "PASSED\n"; tests_passed++; }
        else { std::cout << "FAILED: " << result.error() << "\n"; tests_failed++; }
    }
    
    // Test 2: Error propagation
    {
        std::cout << "Test 2: Error propagation... ";
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            return Result<void>::err("Test error message");
        }, SecurityLimits::safe_defaults());
        if (result.is_err() && result.error() == "Test error message") { std::cout << "PASSED\n"; tests_passed++; }
        else { std::cout << "FAILED\n"; tests_failed++; }
    }
    
    // Test 3: Timeout detection
    {
        std::cout << "Test 3: Timeout detection (1 second)... ";
        auto start = std::chrono::steady_clock::now();
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            return Result<void>::ok();
        }, SecurityLimits::strict());
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        if (result.is_err() && result.error().find("timeout") != std::string::npos) {
            std::cout << "PASSED (after " << elapsed.count() << "ms)\n"; tests_passed++;
        } else { std::cout << "FAILED\n"; tests_failed++; }
    }
    
    // Test 4: Successful computation
    {
        std::cout << "Test 4: Successful computation... ";
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            [[maybe_unused]] int sum = 0;
            for (int i = 0; i < 1000; i++) sum += i;
            return Result<void>::ok();
        }, SecurityLimits::safe_defaults());
        if (result.is_ok()) { std::cout << "PASSED\n"; tests_passed++; }
        else { std::cout << "FAILED\n"; tests_failed++; }
    }
    
    // Test 5: Multiple sequential calls
    {
        std::cout << "Test 5: Multiple sequential safe calls... ";
        bool all_ok = true;
        for (int i = 0; i < 10; i++) {
            auto result = Sandbox::execute_safe([]() -> Result<void> { return Result<void>::ok(); }, SecurityLimits::safe_defaults());
            if (result.is_err()) { all_ok = false; break; }
        }
        if (all_ok) { std::cout << "PASSED\n"; tests_passed++; }
        else { std::cout << "FAILED\n"; tests_failed++; }
    }
    
    // Test 6: Large memory allocation prevention - USES execute_in_process FOR REAL ISOLATION
    {
        std::cout << "Test 6: Large memory allocation prevention (100MB limit, try 300MB)... ";
        SecurityLimits strict_limits;
        strict_limits.max_memory_bytes = 100 * 1024 * 1024; // 100MB
        strict_limits.timeout = std::chrono::milliseconds(10000);

        // Use execute_in_process which has real isolation (fork + setrlimit on Unix, Job Object on Windows)
        auto result = Sandbox::execute_in_process([]() -> int {
            try {
                // Try 300MB - should fail with 100MB limit
                std::vector<char> large;
                large.reserve(300 * 1024 * 1024);
                large.resize(300 * 1024 * 1024);
                for (size_t i = 0; i < large.size(); i += 4096) large[i] = 'x';
                return 0; // If we reach here, limit NOT enforced
            } catch (const std::bad_alloc&) {
                return 1; // bad_alloc = limit enforced -> return non-zero to signal prevention
            } catch (...) {
                return 1;
            }
        }, strict_limits);

        // result.is_err() means process was killed by setrlimit/Job Object (good)
        // result.is_ok() but child returned 0 means allocation succeeded (bad - limit not enforced)
        // result.is_ok() but child returned non-zero via our catch would be ok, but we return err for non-zero exit
        // So: is_err() = PASS, is_ok() = FAIL
        if (result.is_err()) {
            std::cout << "PASSED (prevented: " << result.error() << ")\n";
            tests_passed++;
        } else {
            std::cout << "FAILED (300MB succeeded despite 100MB limit)\n";
            tests_failed++;
        }
    }

    // Test 6b: Small allocation within limit - positive control
    {
        std::cout << "Test 6b: Small allocation within limit (150MB limit, 5MB alloc)... ";
        SecurityLimits normal_limits = SecurityLimits::safe_defaults();
        normal_limits.max_memory_bytes = 150 * 1024 * 1024;
        normal_limits.timeout = std::chrono::milliseconds(10000);

        auto result = Sandbox::execute_in_process([]() -> int {
            try {
                std::vector<char> small(5 * 1024 * 1024, 'x');
                small[0] = 'y';
                return 0;
            } catch (...) {
                return 2;
            }
        }, normal_limits);
        
        if (result.is_ok()) {
            std::cout << "PASSED\n";
            tests_passed++;
        } else {
            std::cout << "FAILED: " << result.error() << "\n";
            tests_failed++;
        }
    }
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Test Results: Passed: " << tests_passed << " Failed: " << tests_failed << "\n";
    std::cout << "========================================\n";
    return tests_failed == 0 ? 0 : 1;
}
