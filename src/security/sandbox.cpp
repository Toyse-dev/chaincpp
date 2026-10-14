#include "chaincpp/security/sandbox.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <cstring>
#include <fstream>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/resource.h>
    #include <sys/time.h>
    #include <unistd.h>
    #include <signal.h>
    #ifdef __APPLE__
        #include <libproc.h>
        #include <sys/proc_info.h>
    #endif
#endif

namespace chaincpp::security {

#ifndef _WIN32
class UnixSandboxImpl {
public:
    static bool set_memory_limit(size_t max_bytes) {
        size_t overhead = 250 * 1024 * 1024;
        size_t new_limit = max_bytes + overhead;
        struct rlimit as_limit{new_limit, new_limit};
        struct rlimit data_limit{new_limit, new_limit};
        struct rlimit rss_limit{new_limit, new_limit};
        setrlimit(RLIMIT_AS, &as_limit);
        setrlimit(RLIMIT_DATA, &data_limit);
        setrlimit(RLIMIT_RSS, &rss_limit);
#ifdef RLIMIT_VMEM
        setrlimit(RLIMIT_VMEM, &as_limit);
#endif
        return true;
    }
    static bool set_cpu_limit(std::chrono::milliseconds timeout) {
        long secs = static_cast<long>(timeout.count() / 1000) + 2;
        struct rlimit limit{static_cast<rlim_t>(secs), static_cast<rlim_t>(secs)};
        setrlimit(RLIMIT_CPU, &limit);
        return true;
    }
    static void sanitize_environment() {
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");
        unsetenv("BASH_ENV");
    }
#ifdef __APPLE__
    static size_t get_child_rss(pid_t pid) {
        struct proc_taskinfo taskinfo;
        int ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
        if (ret == sizeof(taskinfo)) return taskinfo.pti_resident_size;
        return 0;
    }
#else
    static size_t get_child_rss(pid_t pid) {
        // Linux: read VmRSS from /proc/[pid]/status
        std::string path = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream file(path);
        std::string line;
        while (std::getline(file, line)) {
            if (line.rfind("VmRSS:", 0) == 0) {
                size_t kb = 0;
                // line like "VmRSS:  1234 kB"
                sscanf(line.c_str(), "VmRSS: %zu", &kb);
                return kb * 1024;
            }
        }
        // Fallback: VmHWM or statm
        path = "/proc/" + std::to_string(pid) + "/statm";
        std::ifstream file2(path);
        long rss_pages = 0;
        if (file2 >> rss_pages) {} // first is size, second is rss
        if (file2 >> rss_pages) {
            long page_size = sysconf(_SC_PAGESIZE);
            return (size_t)rss_pages * (size_t)page_size;
        }
        return 0;
    }
#endif
};
#endif

Sandbox::~Sandbox() = default;
bool Sandbox::set_memory_limit(size_t max_bytes) { (void)max_bytes;
#ifndef _WIN32
    return UnixSandboxImpl::set_memory_limit(max_bytes);
#else
    return true;
#endif
}
bool Sandbox::set_time_limit(std::chrono::milliseconds timeout) { (void)timeout;
#ifndef _WIN32
    return UnixSandboxImpl::set_cpu_limit(timeout);
#else
    return true;
#endif
}
void Sandbox::sanitize_environment() {
#ifndef _WIN32
    UnixSandboxImpl::sanitize_environment();
#endif
}
bool Sandbox::check_network_allowed(bool allowed) { return allowed; }

Result<void> Sandbox::execute_safe(std::function<Result<void>()> func, const SecurityLimits& limits) {
    std::cerr << "[SECURITY WARNING] Sandbox::execute_safe is cooperative only (timeout enforced, memory NOT enforced - use execute_in_process for memory)\n";
    std::atomic<bool> completed{false};
    std::atomic<bool> timed_out{false};
    std::string error_msg;
    Result<void> func_result = Result<void>::ok();
    std::thread worker([&]() {
        auto result = func();
        if (!timed_out.load()) {
            if (result.is_err()) error_msg = result.error();
            else func_result = std::move(result);
            completed = true;
        }
    });
    auto start = std::chrono::steady_clock::now();
    while (!completed.load()) {
        if (std::chrono::steady_clock::now() - start > limits.timeout) { timed_out = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (timed_out.load()) { worker.detach(); return Result<void>::err("Execution timeout exceeded (COOPERATIVE ONLY)"); }
    if (worker.joinable()) worker.join();
    if (!error_msg.empty()) return Result<void>::err(error_msg);
    return func_result.is_ok() ? Result<void>::ok() : Result<void>::err("Function failed");
}

Result<void> Sandbox::execute_in_process(std::function<int()> func, const SecurityLimits& limits) {
#ifdef _WIN32
    std::atomic<int> exit_code{0};
    std::atomic<bool> done{false};
    std::atomic<bool> mem_exceeded{false};
    std::atomic<size_t> peak_private{0};
    std::string mem_error;
    std::thread worker([&]() { 
        try { exit_code = func(); }
        catch (const std::bad_alloc&) { exit_code = 100; mem_error = "Memory limit exceeded - bad_alloc"; }
        catch (...) { exit_code = 100; mem_error = "Memory limit exceeded - exception"; }
        done = true; 
    });
    auto start = std::chrono::steady_clock::now();
    while (!done.load()) {
        if (std::chrono::steady_clock::now() - start > limits.timeout) { worker.detach(); return Result<void>::err("Timeout after " + std::to_string(limits.timeout.count()) + "ms"); }
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            size_t cur = pmc.PrivateUsage;
            if (cur > peak_private) peak_private = cur;
            if (cur > limits.max_memory_bytes) mem_exceeded = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (worker.joinable()) worker.join();
    if (exit_code == 100) return Result<void>::err(mem_error);
    if (mem_exceeded.load()) return Result<void>::err("Memory limit exceeded - PrivateUsage " + std::to_string(peak_private.load()/1024/1024) + "MB > " + std::to_string(limits.max_memory_bytes/1024/1024) + "MB");
    if (exit_code != 0) return Result<void>::err("Exited code " + std::to_string(exit_code.load()));
    return Result<void>::ok();
#else
    pid_t pid = fork();
    if (pid == -1) return Result<void>::err("fork() failed");
    if (pid == 0) {
        UnixSandboxImpl::set_memory_limit(limits.max_memory_bytes);
        UnixSandboxImpl::set_cpu_limit(limits.timeout);
        UnixSandboxImpl::sanitize_environment();
        int r = func();
        _exit(r);
    } else {
        int status = 0;
        auto start = std::chrono::steady_clock::now();
        const size_t overhead = 250 * 1024 * 1024;
        const size_t effective_limit = limits.max_memory_bytes + overhead;
        while (true) {
            pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    return Result<void>::ok();
                }
                if (WIFEXITED(status)) {
                    int code = WEXITSTATUS(status);
                    return Result<void>::err("Memory limit exceeded - child exited code " + std::to_string(code));
                }
                if (WIFSIGNALED(status)) {
                    return Result<void>::err("Memory limit exceeded - killed by signal " + std::to_string(WTERMSIG(status)));
                }
                return Result<void>::err("Sandboxed process failed");
            }
            // Active RSS monitoring for both macOS and Linux - for ALL limits
            size_t rss = UnixSandboxImpl::get_child_rss(pid);
            if (rss > 0 && rss > effective_limit) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return Result<void>::err("Memory limit exceeded - RSS " + std::to_string(rss/1024/1024) + "MB > " + std::to_string(effective_limit/1024/1024) + "MB limit (killed)");
            }
            if (std::chrono::steady_clock::now() - start > limits.timeout) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return Result<void>::err("Timeout after " + std::to_string(limits.timeout.count()) + "ms");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
#endif
}

} // namespace
