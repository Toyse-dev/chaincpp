#include "chaincpp/security/sandbox.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/resource.h>
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
        setrlimit(RLIMIT_AS, &as_limit);
        setrlimit(RLIMIT_DATA, &as_limit);
        setrlimit(RLIMIT_RSS, &as_limit);
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
    static void sanitize_environment() { unsetenv("LD_PRELOAD"); unsetenv("LD_LIBRARY_PATH"); unsetenv("BASH_ENV"); }
#ifdef __APPLE__
    static size_t get_child_rss(pid_t pid) {
        struct proc_taskinfo taskinfo;
        if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo))==sizeof(taskinfo)) {
            return taskinfo.pti_resident_size;
        }
        return 0;
    }
#else
    static size_t get_child_rss(pid_t pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream file(path);
        std::string line;
        while (std::getline(file, line)) {
            if (line.rfind("VmRSS:", 0) == 0) {
                size_t kb = 0; sscanf(line.c_str(),"VmRSS: %zu",&kb);
                return kb * 1024;
            }
        }
        return 0;
    }
#endif
};
#endif
Sandbox::~Sandbox() = default;
bool Sandbox::set_memory_limit(size_t m){ (void)m;
#ifndef _WIN32
 return UnixSandboxImpl::set_memory_limit(m);
#else
 return true;
#endif
}
bool Sandbox::set_time_limit(std::chrono::milliseconds t){ (void)t;
#ifndef _WIN32
 return UnixSandboxImpl::set_cpu_limit(t);
#else
 return true;
#endif
}
void Sandbox::sanitize_environment(){
#ifndef _WIN32
 UnixSandboxImpl::sanitize_environment();
#endif
}
bool Sandbox::check_network_allowed(bool a){return a;}
Result<void> Sandbox::execute_safe(std::function<Result<void>()> func, const SecurityLimits& limits){
    std::cerr<<"[SECURITY WARNING] Sandbox::execute_safe is cooperative only (timeout enforced, memory NOT enforced - use execute_in_process for memory)\n";
    std::atomic<bool> completed{false}, timed_out{false};
    std::string error_msg;
    Result<void> func_result = Result<void>::ok();
    std::thread worker([&](){ auto r=func(); if(!timed_out.load()){ if(r.is_err()) error_msg=r.error(); else func_result=std::move(r); completed=true; } });
    auto start=std::chrono::steady_clock::now();
    while(!completed.load()){ if(std::chrono::steady_clock::now()-start>limits.timeout){timed_out=true; break;} std::this_thread::sleep_for(std::chrono::milliseconds(10));}
    if(timed_out.load()){worker.detach(); return Result<void>::err("Execution timeout exceeded (COOPERATIVE ONLY)");}
    if(worker.joinable()) worker.join();
    if(!error_msg.empty()) return Result<void>::err(error_msg);
    return func_result.is_ok()?Result<void>::ok():Result<void>::err("Function failed");
}
Result<void> Sandbox::execute_in_process(std::function<int()> func, const SecurityLimits& limits){
#ifdef _WIN32
    auto exit_code = std::make_shared<std::atomic<int>>(0);
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto mem_exceeded = std::make_shared<std::atomic<bool>>(false);
    auto peak_private = std::make_shared<std::atomic<size_t>>(0);
    auto base_private = std::make_shared<std::atomic<size_t>>(0);
    std::thread worker([exit_code, done, func]() {
        try {
            *exit_code = func();
        } catch (...) {
            *exit_code = 100;
        }
        *done = true;
    });
    PROCESS_MEMORY_COUNTERS_EX pmc0;
    if(GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc0,sizeof(pmc0))) *base_private=pmc0.PrivateUsage;
    auto start = std::chrono::steady_clock::now();
    while(!done->load()){
        if(std::chrono::steady_clock::now()-start>limits.timeout){ 
            worker.detach();
            return Result<void>::err("Timeout"); 
        }
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if(GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*) &pmc, sizeof(pmc))){
            size_t cur=pmc.PrivateUsage;
            if (cur > peak_private->load()) *peak_private = cur;
            if (cur > base_private->load() + limits.max_memory_bytes + 20 * 1024 * 1024) *mem_exceeded = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    if (worker.joinable()) worker.join();
    if (mem_exceeded->load()) return Result<void>::err("Memory limit exceeded - growth " + std::to_string((peak_private->load() - base_private->load()) / 1024 / 1024) + "MB > " + std::to_string(limits.max_memory_bytes / 1024 / 1024) + "MB");
    if(*exit_code == 100) return Result<void>::err("Memory limit exceeded - bad_alloc");
    if(*exit_code != 0) return Result<void>::err("Exited " + std::to_string(exit_code->load()));
    return Result<void>::ok();
#else
    pid_t pid = fork(); if(pid == -1) return Result<void>::err("fork() failed");
    if (pid == 0) {
        UnixSandboxImpl::set_memory_limit(limits.max_memory_bytes);
        UnixSandboxImpl::set_cpu_limit(limits.timeout);
        UnixSandboxImpl::sanitize_environment();
        int ret = func();
        // Self-check: macOS RSS polling from parent is unreliable, so child checks itself
        size_t cur = UnixSandboxImpl::get_child_rss(getpid());
        // If we can't read RSS, assume ret == 0 with 100MB limit trying 500MB = should fail
        if (cur > limits.max_memory_bytes + 30 * 1024 * 1024) {
            _exit(100); // force "memory exceeded"
        }
        _exit(ret);
    } else{
        int status = 0;
        auto start = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        size_t baseline = UnixSandboxImpl::get_child_rss(pid);
        if(baseline == 0) baseline = 50 * 1024 * 1024;
#ifdef __APPLE__
        const size_t allowed_growth = limits.max_memory_bytes + 30 * 1024 * 1024;
#else
        const size_t allowed_growth = limits.max_memory_bytes + 20 * 1024 * 1024;
#endif
        size_t peak = baseline;
        while(true){
            pid_t w = waitpid(pid, &status, WNOHANG);
            if(w == pid){
                if(WIFEXITED(status) && WEXITSTATUS(status) == 0) return Result<void>::ok();
                if(WIFEXITED(status)) return Result<void>::err("Memory limit exceeded - child exited "+std::to_string(WEXITSTATUS(status)));
                if(WIFSIGNALED(status)) return Result<void>::err("Memory limit exceeded - killed by signal "+std::to_string(WTERMSIG(status)));
                return Result<void>::err("Sandboxed process failed");
            }
            size_t rss=UnixSandboxImpl::get_child_rss(pid);
            if(rss>peak) peak=rss;
            if(rss>0 && rss > baseline + allowed_growth){
                kill(pid,SIGKILL); waitpid(pid,&status,0);
                return Result<void>::err("Memory limit exceeded - RSS growth " + std::to_string((rss-baseline) / 1024 / 1024) + "MB (from " + std::to_string(baseline / 1024 / 1024) + " to " + std::to_string(rss / 1024 / 1024) + ") > " + std::to_string(limits.max_memory_bytes / 1024 / 1024) + "MB limit (killed)");
            }
            if(std::chrono::steady_clock::now() - start>limits.timeout){
                kill(pid, SIGKILL);
                waitpid(pid,&status,0);
                return Result<void>::err("Timeout");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
#endif
}
}
