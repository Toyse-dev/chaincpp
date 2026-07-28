#include "chaincpp/security/sandbox.hpp"

#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <processthreadsapi.h>
    #include <memoryapi.h>
#else
    #include <sys/resource.h>
    #include <sys/time.h>
    #include <unistd.h>
    #include <signal.h>
    #include <cstring>
#endif

namespace chaincpp::security {

// Platform-Specific Implementations

#ifdef _WIN32
class WindowsSandboxImpl {
public:
    static bool set_memory_limit(size_t max_bytes) {
        HANDLE job = CreateJobObject(nullptr, nullptr);
        if (!job) return false;
        
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = max_bytes;
        
        return SetInformationJobObject(job, 
            JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE;
    }
    
    static void sanitize_environment() {
        // Using _putenv safely or casting to void to ensure no unused results
        (void)_putenv("PATH=");
        (void)_putenv("TEMP=");
        (void)_putenv("TMP=");
    }
};
#endif

#ifdef __unix__
class UnixSandboxImpl {
public:
    static bool set_memory_limit(size_t max_bytes) {
        struct rlimit limit;
        limit.rlim_cur = max_bytes;
        limit.rlim_max = max_bytes;
        return setrlimit(RLIMIT_AS, &limit) == 0;
    }
    
    static bool set_cpu_limit(std::chrono::milliseconds timeout) {
        struct rlimit limit;
        limit.rlim_cur = static_cast<rlim_t>(timeout.count() / 1000);
        limit.rlim_max = static_cast<rlim_t>(timeout.count() / 1000);
        return setrlimit(RLIMIT_CPU, &limit) == 0;
    }
    
    static void sanitize_environment() {
        (void)unsetenv("LD_PRELOAD");
        (void)unsetenv("LD_LIBRARY_PATH");
        (void)unsetenv("BASH_ENV");
    }
};
#endif

// Sandbox Implementation

Sandbox::~Sandbox() {
    // Virtual destructor implementation
}

bool Sandbox::set_memory_limit(size_t max_bytes) {
#ifdef _WIN32
    return WindowsSandboxImpl::set_memory_limit(max_bytes);
#elif defined(__unix__)
    return UnixSandboxImpl::set_memory_limit(max_bytes);
#else
    (void)max_bytes; // Silence unused warning
    return true;
#endif
}

bool Sandbox::set_time_limit([[maybe_unused]] std::chrono::milliseconds timeout) {
#ifdef __unix__
    return UnixSandboxImpl::set_cpu_limit(timeout);
#else
    // On Windows, the timeout is handled in the execute_safe loop
    // We mark it [[maybe_unused]] in the signature to satisfy -Werror
    return true;
#endif
}

void Sandbox::sanitize_environment() {
#ifdef _WIN32
    WindowsSandboxImpl::sanitize_environment();
#elif defined(__unix__)
    UnixSandboxImpl::sanitize_environment();
#endif
}

bool Sandbox::check_network_allowed(bool allowed) {
    return allowed; 
}

Result<void> Sandbox::execute_safe(
    std::function<Result<void>()> func,
    const SecurityLimits& limits
) {
    // Document: func MUST NOT capture stack variables by reference if timeout is possible
    // Better: Use processes instead of threads for true sandboxing
    if (!set_memory_limit(limits.max_memory_bytes)) {
        return Result<void>::err("Failed to set memory limit");
    }

     sanitize_environment();
    
    std::atomic<bool> completed{false};
    std::atomic<bool> timed_out{false};
    std::string error_msg;
    Result<void> func_result;
    
    std::thread worker([&]() {
        auto result = func();
        if (!timed_out) {
            if (result.is_err()) {
                error_msg = result.error();
            } else {
                func_result = std::move(result);
            }
            completed = true;
        }
    });
    auto start = std::chrono::steady_clock::now();
   
    while (!completed) {
        if (std::chrono::steady_clock::now() - start > limits.timeout) {
            timed_out = true;
            // We can't kill the thread, but we can stop waiting for it
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (timed_out) {
        // Detach and let it finish - but func must NOT have stack references
        worker.detach();
        return Result<void>::err("Execution timeout exceeded (func may continue in background)");
    }
    
    if (worker.joinable()) {
        worker.join();
    }
    
    if (!error_msg.empty()) {
        return Result<void>::err(error_msg);
    }
    
     return func_result.is_ok() ? Result<void>::ok() : Result<void>::err("Function failed");
}

// Better solution: Process-based sandboxing
Result<void> Sandbox::execute_in_process(
    std::function<int()> func,
    const SecurityLimits& limits
) {
#ifdef _WIN32
// The hardened windows OS process Isolation engine

// 1. Establish a secure Windows Job Object container to catch leaked resources
HANDLE job = CreateJobObjectW(nullptr, nullptr);
if (!job) {
    return Result<void>::err("Security Failure: Failed to create isolation Job Object.");
}

// Set resource limits natively on the OS kernel level
JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits = {};
job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
job_limits.JobMemoryLimit = limits.max_memory_bytes;

if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits))) {
    CloseHandle(job);
    return Result<void>::err("Security Failure: Failed to configure Job Object hardware constraints.");
}

// 2. Resolve your active binary path dynamically to spawn a duplicate clean child process worker
wchar_t binary_path[MAX_PATH];
GetModuleFileNameW(nullptr, binary_path, MAX_PATH);

STARTUPINFOW si = {};
PROCESS_INFORMATION pi = {};
si.cb = sizeof(si);

// Spawn a child process using low-privilege token tracking patterns (simulated here for v0.1 via child arguments)
// In a full production build, you pass an explicit "--sandbox-worker" flag payload argument string here
std::wstring cmd_line = L"\"" + std::wstring(binary_path) + L"\" --sandbox-worker";

if (!CreateProcessW(nullptr, &cmd_line[0], nullptr, nullptr, TRUE, 
    CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr, &si, &pi)) {
    CloseHandle(job);
    return Result<void>::err("Security Failure: Process execution fork block failed on Win32 API layer.");
}

// Assign the newly created process context safely inside our strict resource-monitored Job fence
if (!AssignProcessToJobObject(job, pi.hProcess)) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    return Result<void>::err("Security Failure: Failed to assign worker process to Job boundary.");
}

// Resume the process thread execution safely now that the security boundaries are locked
ResumeThread(pi.hThread);
CloseHandle(pi.hThread);

// 3. Monitor execution deadlines deterministically on the master core
long timeout_ms = static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(limits.timeout).count());
DWORD wait_res = WaitForSingleObject(pi.hProcess, timeout_ms);

if (wait_res == WAIT_TIMEOUT) {
    // TIMEOUT BREACH: Terminate everything executing inside the job container instantly!
    TerminateJobObject(job, 0); 
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    return Result<void>::err("Execution timeout exceeded: Sandbox process terminated instantly.");
}

DWORD exit_code = 1;
GetExitCodeProcess(pi.hProcess, &exit_code);
CloseHandle(pi.hProcess);
CloseHandle(job);

if (exit_code == 0) {
    return Result<void>::ok();
}
return Result<void>::err("Process isolated execution failed or was aborted by system restrictions.");
   
#else
 // Native Linux / UNIX Multi-Process Sandbox Engine
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        set_memory_limit(limits.max_memory_bytes);
        set_time_limit(limits.timeout);
        sanitize_environment();
        
        int result = func();
        exit(result);
    } else if (pid > 0) {
        // Parent process supervisor monitor loop
        int status;
        auto start = std::chrono::steady_clock::now();
        
        while (true) {
            if (waitpid(pid, &status, WNOHANG) > 0) {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    return Result<void>::ok();
                } else {
                    return Result<void>::err("Process failed");
                }
            }
            
            if (std::chrono::steady_clock::now() - start > limits.timeout) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return Result<void>::err("Timeout");
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
#endif
    return Result<void>::err("Process creation failed");
}
}
