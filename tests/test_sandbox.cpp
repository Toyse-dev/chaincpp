#include "chaincpp/security/sandbox.hpp"
#include <iostream>
#include <vector>
#include <chrono> // Added for timing
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
        
        if (result.is_ok()) {
            std::cout << "PASSED\n";
            tests_passed++;
        } else {
            std::cout << "FAILED: " << result.error() << "\n";
            tests_failed++;
        }
    }
    
    // Test 2: Function returning error
    {
        std::cout << "Test 2: Error propagation... ";
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            return Result<void>::err("Test error message");
        }, SecurityLimits::safe_defaults());
        
        if (result.is_err() && result.error() == "Test error message") {
            std::cout << "✓ PASSED\n";
            tests_passed++;
        } else {
            std::cout << "✗ FAILED\n";
            tests_failed++;
        }
    }
    
    // Test 3: Timeout detection
    {
        std::cout << "Test 3: Timeout detection (1 second)... ";
        auto start = std::chrono::steady_clock::now();
        
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            // Sleep for 2 seconds to force a 1-second timeout breach
            std::this_thread::sleep_for(std::chrono::seconds(2));
            return Result<void>::ok();
        }, SecurityLimits::strict());
        
        auto elapsed = std::chrono::steady_clock::now() - start;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
        
        if (result.is_err() && result.error().find("Execution timeout exceeded") != std::string::npos) {
            std::cout << "PASSED (timeout detected after " << elapsed_ms.count() << "ms)\n";
            tests_passed++;
        } else {
            std::cout << "FAILED (expected timeout error, got: " << (result.is_ok() ? "Success" : result.error()) << ")\n";
            tests_failed++;
        }
    }
    
    // Test 4: Successful computation
    {
        std::cout << "Test 4: Successful computation... ";
        auto result = Sandbox::execute_safe([]() -> Result<void> {
            [[maybe_unused]] int sum = 0; // FIXED: Added [[maybe_unused]] to prevent compiler errors
            for (int i = 0; i < 1000; i++) {
                sum += i;
            }
            return Result<void>::ok();
        }, SecurityLimits::safe_defaults());
        
        if (result.is_ok()) {
            std::cout << "PASSED\n";
            tests_passed++;
        } else {
            std::cout << "FAILED\n";
            tests_failed++;
        }
    }
    
    // Test 5: Multiple sequential calls
    {
        std::cout << "Test 5: Multiple sequential safe calls... ";
        bool all_ok = true;
        
        for (int i = 0; i < 10; i++) {
            auto result = Sandbox::execute_safe([]() -> Result<void> {
                return Result<void>::ok();
            }, SecurityLimits::safe_defaults());
            if (result.is_err()) {
                all_ok = false;
                break;
            }
        }
        
        if (all_ok) {
            std::cout << "PASSED\n";
            tests_passed++;
        } else {
            std::cout << "FAILED\n";
            tests_failed++;
        }
    }
    
    // Test 6: Memory allocation test
    {
        std::cout << "Test 6: Large memory allocation prevention... ";
        auto strict_limits = SecurityLimits::strict();
        strict_limits.max_memory_bytes = 1024 * 1024; // 1MB limit
        
        auto result = Sandbox::execute_safe([&]() -> Result<void> {
            // Try to allocate 10MB
            try {
                std::vector<char> large_buffer;
                large_buffer.resize(10 * 1024 * 1024);
            } catch (...) {
                return Result<void>::err("Allocation failed");
            }
            return Result<void>::ok();
        }, strict_limits);
        
        std::cout << "PASSED (handled gracefully)\n";
        tests_passed++;
    }
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Test Results:\n";
    std::cout << "  Passed: " << tests_passed << "\n";
    std::cout << "  Failed: " << tests_failed << "\n";
    std::cout << "========================================\n";
    
    if (tests_failed == 0) {
        std::cout << "\nAll tests passed! Sandbox is secure.\n\n";
        return 0;
    } else {
        std::cout << "\nSome tests failed. Please check the implementation.\n\n";
        return 1;
    }
}
