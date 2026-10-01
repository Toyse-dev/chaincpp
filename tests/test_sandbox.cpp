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
    
    // Test 1-5 use execute_safe (cooperative timeout)
    {
        std::cout << "Test 1: Safe function execution... ";
        auto r = Sandbox::execute_safe([]() -> Result<void> { return Result<void>::ok(); }, SecurityLimits::safe_defaults());
        if (r.is_ok()) { std::cout << "PASSED\n"; tests_passed++; } else { std::cout << "FAILED\n"; tests_failed++; }
    }
    {
        std::cout << "Test 2: Error propagation... ";
        auto r = Sandbox::execute_safe([]() -> Result<void> { return Result<void>::err("Test error message"); }, SecurityLimits::safe_defaults());
        if (r.is_err() && r.error() == "Test error message") { std::cout << "PASSED\n"; tests_passed++; } else { std::cout << "FAILED\n"; tests_failed++; }
    }
    {
        std::cout << "Test 3: Timeout detection (1 second)... ";
        auto start = std::chrono::steady_clock::now();
        auto r = Sandbox::execute_safe([]() -> Result<void> { std::this_thread::sleep_for(std::chrono::seconds(2)); return Result<void>::ok(); }, SecurityLimits::strict());
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        if (r.is_err() && r.error().find("timeout") != std::string::npos) { std::cout << "PASSED (" << elapsed.count() << "ms)\n"; tests_passed++; } else { std::cout << "FAILED\n"; tests_failed++; }
    }
    {
        std::cout << "Test 4: Successful computation... ";
        auto r = Sandbox::execute_safe([]() -> Result<void> { int s=0; for(int i=0;i<1000;i++) s+=i; return Result<void>::ok(); }, SecurityLimits::safe_defaults());
        if (r.is_ok()) { std::cout << "PASSED\n"; tests_passed++; } else { std::cout << "FAILED\n"; tests_failed++; }
    }
    {
        std::cout << "Test 5: Multiple sequential safe calls... ";
        bool ok=true; for(int i=0;i<10;i++){ auto r=Sandbox::execute_safe([]()->Result<void>{return Result<void>::ok();}, SecurityLimits::safe_defaults()); if(r.is_err()){ok=false;break;}} 
        if(ok){ std::cout<<"PASSED\n"; tests_passed++; } else { std::cout<<"FAILED\n"; tests_failed++; }
    }
    
    // Test 6: Large memory - uses execute_in_process with real enforcement
    {
        std::cout << "Test 6: Large memory allocation prevention (100MB limit, try 300MB)... ";
        SecurityLimits limits;
        limits.max_memory_bytes = 100 * 1024 * 1024;
        limits.timeout = std::chrono::milliseconds(10000);

        auto result = Sandbox::execute_in_process([]() -> int {
            try {
                // On Unix, setrlimit with overhead will make this fail via bad_alloc or SIGKILL
                // On Windows, monitoring will detect PrivateUsage > limit
                std::vector<char> large;
                large.reserve(300 * 1024 * 1024);
                large.resize(300 * 1024 * 1024);
                for (size_t i = 0; i < large.size(); i += 1024*1024) large[i] = 'x'; // touch each MB
                return 0; // 0 = allocation succeeded (limit NOT enforced)
            } catch (const std::bad_alloc&) {
                return 100; // 100 = bad_alloc - limit enforced
            } catch (...) {
                return 100;
            }
        }, limits);

        if (result.is_err()) {
            std::cout << "PASSED (prevented: " << result.error() << ")\n";
            tests_passed++;
        } else {
            std::cout << "FAILED (300MB succeeded despite 100MB limit)\n";
            tests_failed++;
        }
    }

    // Test 6b: Small allocation - should succeed
    {
        std::cout << "Test 6b: Small allocation within limit (150MB limit, 5MB alloc)... ";
        SecurityLimits limits = SecurityLimits::safe_defaults();
        limits.max_memory_bytes = 150 * 1024 * 1024;
        limits.timeout = std::chrono::milliseconds(10000);

        auto result = Sandbox::execute_in_process([]() -> int {
            try {
                std::vector<char> small(5 * 1024 * 1024, 'x');
                small[0] = 'y';
                return 0;
            } catch (...) { return 1; }
        }, limits);
        
        if (result.is_ok()) { std::cout << "PASSED\n"; tests_passed++; }
        else { std::cout << "FAILED: " << result.error() << "\n"; tests_failed++; }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Test Results: Passed: " << tests_passed << " Failed: " << tests_failed << "\n";
    std::cout << "========================================\n";
    return tests_failed == 0 ? 0 : 1;
}
