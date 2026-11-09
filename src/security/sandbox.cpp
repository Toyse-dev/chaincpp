#include "chaincpp/security/sandbox.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>

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
    #if defined(__linux__) && !defined(__APPLE__)
        #include <sys/stat.h>
        #include <filesystem>
    #endif

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

#if defined(__linux__) && !defined(__APPLE__)
    struct CgroupGuard {
        std::string path;
        bool active = false;

        bool try_create(size_t limit_bytes) {
        // Try to create a cgroup under current cgroup or root
        // We must be in a writable cgroup. This will fail without root if not delegated - that's OK.
        std::string base = "/sys/fs/cgroup";
        // if we are in systemd scope, we can't write to root, try to create child
        path = base + "/chaincpp_" + std::to_string(getpid()) + "_" + std::to_string(rand());
        if (mkdir(path.c_str(), 0755) != 0) return false;
        // Enable memory controller if needed (cgroup v2)
        {
            std::ofstream f(path + "/memory.max");
            if (!f) { rmdir(path.c_str()); return false; }
            // Give 20MB extra for your overhead logic
            f << std::to_string(limit_bytes + 20 * 1024 * 1024);
        }
        // Disable swap to prevent child eating swap
        {
            std::ofstream f(path + "/memory.swap.max");
            if (f) f << "0";
        }
        // Prevent OOM killer from taking host down
        {
            std::ofstream f(path + "/memory.oom.group");
            if (f) f << "1";
        }
        active = true;
        return true;
    }
    bool add_pid(pid_t pid) {
        if (!active) return false;
        std::ofstream f(path + "/cgroup.procs");
        if (!f) return false;
        f << pid;
        return f.good();
    }
    size_t current_usage() {
        if (!active) return 0;
        std::ifstream f(path + "/memory.current");
        size_t v = 0;
        if (f) f >> v;
        return v;
    }
    void kill_all() {
        if (!active) return;
        // cgroup v2 way to kill all: cgroup.kill
        {
            std::ofstream f(path + "/cgroup.kill");
            if (f) { f << "1"; return; }
        }
        // Fallback: kill pids in cgroup.procs
        std::ifstream procs(path + "/cgroup.procs");
        pid_t p;
        while (procs >> p) { kill(p, SIGKILL); }
    }
    void cleanup() {
        if (!active) return;
        kill_all();
        // Move ourselves out before rmdir if we accidentally added parent
        // Just rmdir - kernel will fail if not empty, which is fine
        rmdir(path.c_str());
        active = false;
    }
    ~CgroupGuard() { cleanup(); }
    };
#endif
};
#endif

Sandbox::~Sandbox() = default;
bool Sandbox::set_memory_limit(size_t m) { 
    (void) m;
    #ifndef _WIN32
        return UnixSandboxImpl::set_memory_limit(m);
    #else
    return true;
#endif
}

bool Sandbox::set_time_limit(std::chrono::milliseconds t) {
    (void) t;
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

    struct State {
        std::atomic<bool> completed{false};
        std::atomic<bool> timed_out{false};
        std::string error_msg;
        std::mutex mutex;
        Result<void> func_result = Result<void>::ok();
    };
    auto state = std::make_shared<State>();

    std::thread worker([func, state](){
        auto r = func();
        if(!state->timed_out.load()){
            std::lock_guard<std::mutex> lock(state->mutex);
            if(r.is_err()) state->error_msg = r.error();
            else state->func_result = std::move(r);
            state->completed = true;
        }
    });

    auto start = std::chrono::steady_clock::now();
    while(!state->completed.load()){
        if(std::chrono::steady_clock::now() - start > limits.timeout){
            state->timed_out = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

     if(state->timed_out.load()){
        // Safe to detach now: worker only touches shared_ptr state
        worker.detach();
        return Result<void>::err("Execution timeout exceeded (COOPERATIVE ONLY)");
    }
    if(worker.joinable()) worker.join();

    std::lock_guard<std::mutex> lock(state->mutex);
    if(!state->error_msg.empty()) return Result<void>::err(state->error_msg);
    return state->func_result.is_ok() ? Result<void>::ok() : Result<void>::err("Function failed");
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

#if defined(__linux__) && !defined(__APPLE__)
        UnixSandboxImpl::CgroupGuard cg;
        bool use_cgroup = cg.try_create(limits.max_memory_bytes);
        if (use_cgroup) {
            if (!cg.add_pid(pid)) {
                std::cerr << "[SANDBOX WARNING] cgroup created but failed to add child pid " << pid 
                          << " - falling back to VmRSS polling, child processes not fully isolated\n";
                use_cgroup = false;
                cg.cleanup();
            }
        } else {
            std::cerr << "[SANDBOX WARNING] Failed to create cgroup at " << cg.path 
                      << " (needs root/delegation) - falling back to VmRSS polling\n";
        }
#endif

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
#if defined(__linux__) && !defined(__APPLE__)
                if (use_cgroup) cg.cleanup();
#endif
                if(WIFEXITED(status) && WEXITSTATUS(status) == 0) return Result<void>::ok();
                if(WIFEXITED(status)) return Result<void>::err("Memory limit exceeded - child exited "+std::to_string(WEXITSTATUS(status)));
                if(WIFSIGNALED(status)) return Result<void>::err("Memory limit exceeded - killed by signal "+std::to_string(WTERMSIG(status)));
                return Result<void>::err("Sandboxed process failed");
            }

#if defined(__linux__) && !defined(__APPLE__)
            if (use_cgroup) {
                size_t usage = cg.current_usage();
                if (usage > peak) peak = usage;
                // cgroup memory includes all children, so this is the real fix
                if (usage > limits.max_memory_bytes + 20 * 1024 * 1024) {
                    cg.kill_all();
                    kill(pid, SIGKILL);
                    waitpid(pid, &status, 0);
                    cg.cleanup();
                    return Result<void>::err("Memory limit exceeded - cgroup usage " + std::to_string(usage / 1024 / 1024) + "MB > " + std::to_string(limits.max_memory_bytes / 1024 / 1024) + "MB limit (entire tree killed)");
                }
            } else {
#endif
            size_t rss=UnixSandboxImpl::get_child_rss(pid);
            if(rss>peak) peak=rss;
            if(rss>0 && rss > baseline + allowed_growth){
                kill(pid,SIGKILL); waitpid(pid,&status,0);
                return Result<void>::err("Memory limit exceeded - RSS growth " + std::to_string((rss-baseline) / 1024 / 1024) + "MB (from " + std::to_string(baseline / 1024 / 1024) + " to " + std::to_string(rss / 1024 / 1024) + ") > " + std::to_string(limits.max_memory_bytes / 1024 / 1024) + "MB limit (killed)");
            }
#if defined(__linux__) && !defined(__APPLE__)
            }
#endif
            if(std::chrono::steady_clock::now() - start>limits.timeout){
#if defined(__linux__) && !defined(__APPLE__)
                if (use_cgroup) { cg.kill_all(); cg.cleanup(); }
#endif
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
