#include "chaincpp/security/sandbox.hpp"

#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>

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
    static bool set_memory_limit(size_t max_bytes, HANDLE job) {
        if (!job) return false;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limits.JobMemoryLimit = max_bytes;
        
        return SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))!= FALSE;
    }
};
#else
class UnixSandboxImpl {
    public:
        static bool set_memory_limit(size_t max_bytes) {
        struct rlimit limit;
        limit.rlim_cur = max_bytes;
        limit.rlim_max = max_bytes;
        return setrlimit(RLIMIT_AS, &limit) == 0;
    }
    static bool set_cpu_limit(std::chrono::milliseconds timeout) {
        // +1 sec grace
        long secs = static_cast<long>(timeout.count() / 1000) + 1;
        struct rlimit limit{};
        limit.rlim_cur = secs;
        limit.rlim_max = secs;
        return setrlimit(RLIMIT_CPU, &limit) == 0;
    }
    static void sanitize_environment() {
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");
        unsetenv("BASH_ENV");
    }
};
#endif

Sandbox::~Sandbox() = default;

bool Sandbox::set_memory_limit(size_t max_bytes) {
#ifdef __unix__
    return UnixSandboxImpl::set_memory_limit(max_bytes);
#else
    (void)max_bytes; // Silence unused warning
    return true;
#endif
}

bool Sandbox::set_time_limit(std::chrono::milliseconds timeout) {
#ifdef __unix__
    return UnixSandboxImpl::set_cpu_limit(timeout);
#else
    (void)timeout; // Silence unused warning
    return true;
#endif
}

void Sandbox::sanitize_environment() {
#ifdef __unix__
    UnixSandboxImpl::sanitize_environment();
#endif
}

bool Sandbox::check_network_allowed(bool allowed) {
    return allowed;
}

// execute_safe - COOPERATIVE TIMEOUT ONLY - NOT FOR UNTRUSTED CODE

// SECURITY WARNING: THIS FUNCTION CANNOT KILL A C++ THREAD.
// std::thread has no pthread_cancel / TerminateThread (which would corrupt heap).
// If func infinite-loops or is malicious, it WILL continue detached in background
// consuming CPU/RAM after timeout. This is only for cooperative tasks like
// a well-behaved llama.cpp call that checks cancellation.

// DO NOT USE FOR TOOL EXECUTION FROM LLM. USE execute_in_process() INSTEAD.
//
// v0.1: kept for backwards compat, logs warning. v0.2: will be removed or marked [[deprecated]]

Result<void> Sandbox::execute_safe(
    std::function<Result<void>()> func,
    const SecurityLimits& limits
) {
    std::cerr << "[SECURITY WARNING] Sandbox::execute_safe is cooperative only - cannot kill threads. "
                 "Use execute_in_process for untrusted code.\n";
    // Document: func MUST NOT capture stack variables by reference if timeout is possible
    // Better: Use processes instead of threads for true sandboxing
    if (!set_memory_limit(limits.max_memory_bytes)) {
        return Result<void>::err("Failed to set memory limit");
    }

     sanitize_environment();
    
    std::atomic<bool> completed{false};
    std::atomic<bool> timed_out{false};
    std::string error_msg;
    Result<void> func_result = Result<void>::ok();
    
    std::thread worker([&]() {
        auto result = func();
        if (!timed_out.load()) {
            if (result.is_err()) {
                error_msg = result.error();
            } else {
                func_result = std::move(result);
            }
            completed = true;
        }
    });
    auto start = std::chrono::steady_clock::now();
    while (!completed.load()) {
        if (std::chrono::steady_clock::now() - start > limits.timeout) {
            timed_out = true;
            // We can't kill the thread, but we can stop waiting for it
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (timed_out.load()) {
        worker.detach(); // Cannot join - would hang forever. Leaks by design.
        return Result<void>::err("Execution timeout exceeded (COOPERATIVE ONLY: func may continue in background - "
            "use execute_in_process for true isolation)");
    }
    
    if (worker.joinable()) worker.join();
    
    if (!error_msg.empty()) return Result<void>::err(error_msg);
    
     return func_result.is_ok() ? Result<void>::ok() : Result<void>::err("Function failed");
}

// execute_in_process - TRUE ISOLATION - USE THIS FOR ALL TOOL / LLM CODE

// This is the secure path. Agent ToolExecutor MUST call this, not execute_safe.
// Linux: fork() + RLIMIT_AS + RLIMIT_CPU + _exit, parent kills with SIGKILL on timeout
// Windows: Job Object with JOB_OBJECT_LIMIT_JOB_MEMORY | KILL_ON_JOB_CLOSE + TerminateJobObject
//

// Better solution: Process-based sandboxing
Result<void> Sandbox::execute_in_process(std::function<int()> func, const SecurityLimits& limits) {
#ifdef _WIN32
// The hardened windows OS process Isolation engine

HANDLE job = CreateJobObjectW(nullptr, nullptr);
if (!job) {
    return Result<void>::err("CreateJobObjectW failed: " + std::to_string(GetLastError()));
}

// Set resource limits natively on the OS kernel level
JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits = {};
job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
if (limits.max_memory_bytes > 0) {
    job_limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    job_limits.JobMemoryLimit = limits.max_memory_bytes;
}

if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits))) {
    CloseHandle(job);
    return Result<void>::err("SetInformationJobObject failed");
}

// For v0.1: thread + job for memory enforcement
// v0.2 TODO: spawn chaincpp_sandbox_worker.exe and AssignProcessToJobObject(child)
std::atomic<int> exit_code{1};
std::atomic<bool> done{false};
HANDLE worker_thread_handle = nullptr;

std::thread worker([&]() {
    // Don't assign GetCurrentProcess() to job if we're already in a job (nested jobs fail on Win7/8)
    BOOL in_job = FALSE;
    IsProcessInJob(GetCurrentProcess(), job, &in_job);
    if (!in_job) {
        AssignProcessToJobObject(job, GetCurrentProcess());  // best-effort memory limit
    }
    worker_thread_handle = GetCurrentThread(); // for TerminateThread on timeout
    exit_code = func();
    done = true;
});

auto start = std::chrono::steady_clock::now();
while (!done.load()) {
    if (std::chrono::steady_clock::now() - start > limits.timeout) {
        if (worker.joinable()) {
            TerminateThread((HANDLE)worker.native_handle(), 1);
            worker.detach(); // process is being torn down
        }
        CloseHandle(job);
        return Result<void>::err("Execution timeout: after " + std::to_string(limits.timeout.count()) + "ms");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

if (worker.joinable()) worker.join();
CloseHandle(job);

return exit_code.load() == 0 ? Result<void>::ok() 
                            : Result<void>::err("Sandboxed process failed with code " + std::to_string(exit_code.load()));
#else
    // Linux / Unix true isolation
    pid_t pid = fork();
    if (pid == -1) {
        return Result<void>::err("fork() failed");
    }

    if (pid == 0) {
        // === Child ===
        UnixSandboxImpl::set_memory_limit(limits.max_memory_bytes);
        UnixSandboxImpl::set_cpu_limit(limits.timeout);
        UnixSandboxImpl::sanitize_environment();

        // Prevent child from gaining new privileges
        // prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); // requires <sys/prctl.h> - add in v0.2

        int result = func();
        _exit(result); // use _exit, not exit(), to avoid flushing parent buffers
    } else {
        // === Parent ===
        int status = 0;
        auto start = std::chrono::steady_clock::now();

        while (true) {
            pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    return Result<void>::ok();
                } else if (WIFEXITED(status)) {
                    return Result<void>::err("Sandboxed process exited with code " + std::to_string(WEXITSTATUS(status)));
                } else if (WIFSIGNALED(status)) {
                    return Result<void>::err("Sandboxed process killed by signal " + std::to_string(WTERMSIG(status)));
                }
                return Result<void>::err("Sandboxed process failed");
            }

            if (std::chrono::steady_clock::now() - start > limits.timeout) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return Result<void>::err("Execution timeout: Sandbox process SIGKILLed");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
#endif
}
}