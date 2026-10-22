// cam_injector — ptrace-based dlopen injector for arm64 Android.
// Usage: cam_injector <process-name> <lib-path>
// Example (as root): cam_injector cameraserver /data/local/tmp/hal_inject/libcam_hook.so
//
// Technique:
//   1. Find target PID via /proc/*/cmdline
//   2. PTRACE_ATTACH
//   3. Locate dlopen in target process address space (via /proc/PID/maps + our own base)
//   4. Write library path string to target stack space via /proc/PID/mem
//   5. Redirect PC to dlopen, wait for SIGSEGV (return to NULL lr triggers it)
//   6. PTRACE_DETACH
//
// No Frida strings. No Frida runtime. Detection-clean.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <linux/elf.h>   // NT_PRSTATUS

// arm64 user_pt_regs layout (matches struct user_pt_regs in asm/ptrace.h)
struct arm64_regs {
    uint64_t regs[31]; // x0-x30 (x30 = link register)
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// ─── Helpers ──────────────────────────────────────────────────────────────

static pid_t find_pid(const char *proc_name) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    pid_t found = -1;
    while ((e = readdir(d)) && found == -1) {
        if (e->d_type != DT_DIR) continue;
        char *end;
        long n = strtol(e->d_name, &end, 10);
        if (*end) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", n);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[256] = {};
        read(fd, buf, sizeof(buf) - 1);
        close(fd);

        // cmdline is NUL-delimited; first token = process name or full path
        const char *bn = strrchr(buf, '/');
        bn = bn ? bn + 1 : buf;
        if (strcmp(bn,  proc_name) == 0 ||
            strcmp(buf, proc_name) == 0) found = (pid_t)n;
    }
    closedir(d);
    return found;
}

// First executable mapping of a library in the given PID's address space.
static uintptr_t get_lib_base(pid_t pid, const char *lib_substr) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f) && base == 0) {
        char perms[8], fname[256] = {};
        uint64_t start;
        if (sscanf(line, "%lx-%*lx %4s %*x %*x:%*x %*u %255s",
                   &start, perms, fname) >= 2) {
            const char *bn = strrchr(fname, '/');
            bn = bn ? bn + 1 : fname;
            if (strstr(bn, lib_substr) && perms[2] == 'x')
                base = (uintptr_t)start;
        }
    }
    fclose(f);
    return base;
}

static bool ptrace_get_regs(pid_t pid, arm64_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0;
}

static bool ptrace_set_regs(pid_t pid, const arm64_regs *r) {
    struct iovec iov = { (void *)r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0;
}

// Write bytes directly into target process via /proc/PID/mem.
static bool remote_write_mem(pid_t pid, uintptr_t addr,
                              const void *data, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR);
    if (fd < 0) { perror("open /proc/PID/mem"); return false; }
    ssize_t r = pwrite64(fd, data, len, (off64_t)addr);
    close(fd);
    return r == (ssize_t)len;
}

// Execute dlopen in target via ptrace: set up call frame, CONT, wait for fault.
// Returns the handle value (x0 on return), or 0 on failure.
static uintptr_t remote_dlopen(pid_t pid, uintptr_t dlopen_addr,
                                uintptr_t str_addr) {
    arm64_regs saved, call;
    if (!ptrace_get_regs(pid, &saved)) {
        perror("GETREGSET"); return 0;
    }
    call            = saved;
    call.regs[0]    = str_addr;      // arg0: path
    call.regs[1]    = 2;             // arg1: RTLD_NOW
    call.regs[30]   = 0;             // LR = NULL → SIGSEGV/SIGBUS on return
    call.pc         = dlopen_addr;

    if (!ptrace_set_regs(pid, &call)) { perror("SETREGSET"); return 0; }
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    int status;
    while (waitpid(pid, &status, 0) > 0) {
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        if (sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGTRAP)
            break;
        ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)sig);
    }

    arm64_regs ret;
    ptrace_get_regs(pid, &ret);
    uintptr_t retval = ret.regs[0];  // dlopen return value (handle or NULL)

    ptrace_set_regs(pid, &saved);    // restore process state
    return retval;
}

// ─── Main ─────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "Usage: cam_injector <process-name> <lib-path>\n"
                "  e.g. cam_injector cameraserver "
                "/data/local/tmp/hal_inject/libcam_hook.so\n");
        return 1;
    }

    const char *proc  = argv[1];
    const char *lib   = argv[2];
    size_t      libsz = strlen(lib) + 1;

    printf("[*] Looking for process: %s\n", proc);
    pid_t target = find_pid(proc);
    if (target < 0) { fprintf(stderr, "[-] Not found\n"); return 1; }
    printf("[+] PID: %d\n", target);

    // Find dlopen in our process, then calculate its address in the target.
    // Both processes use the same linker / libdl.so binary; only the load base differs.
    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen) {
        // Android 10+: dlopen may be an alias in linker64
        void *h = dlopen("libdl.so", RTLD_NOW | RTLD_NOLOAD);
        local_dlopen = h ? dlsym(h, "dlopen") : nullptr;
    }
    if (!local_dlopen) { fprintf(stderr, "[-] Cannot find dlopen\n"); return 1; }

    // Determine which lib provides dlopen in our process
    const char *dlopen_libs[] = { "libdl", "linker64", nullptr };
    uintptr_t local_base = 0, remote_base = 0;
    for (int i = 0; dlopen_libs[i] && !local_base; i++) {
        local_base  = get_lib_base(getpid(), dlopen_libs[i]);
        remote_base = get_lib_base(target,   dlopen_libs[i]);
    }
    if (!local_base || !remote_base) {
        fprintf(stderr, "[-] Cannot locate dlopen provider in maps\n");
        return 1;
    }

    uintptr_t remote_dlopen_addr =
        remote_base + ((uintptr_t)local_dlopen - local_base);
    printf("[+] dlopen remote: 0x%lx\n", (unsigned long)remote_dlopen_addr);

    // Attach
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) != 0) {
        perror("[-] PTRACE_ATTACH"); return 1;
    }
    int status;
    waitpid(target, &status, 0);
    printf("[+] Attached\n");

    // Read SP so we can write the library path just below it
    arm64_regs regs;
    if (!ptrace_get_regs(target, &regs)) {
        perror("[-] GETREGSET");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    // Place the path string 512 bytes below the current stack pointer (16-byte aligned).
    uintptr_t str_addr = (regs.sp - 512) & ~15ULL;
    printf("[*] Writing lib path to 0x%lx\n", (unsigned long)str_addr);

    if (!remote_write_mem(target, str_addr, lib, libsz)) {
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        fprintf(stderr, "[-] remote_write_mem failed\n");
        return 1;
    }

    // Execute dlopen in target
    printf("[*] Calling dlopen(\"%s\", RTLD_NOW) in target...\n", lib);
    uintptr_t handle = remote_dlopen(target, remote_dlopen_addr, str_addr);

    ptrace(PTRACE_DETACH, target, NULL, NULL);
    printf("[+] Detached\n");

    if (handle == 0) {
        fprintf(stderr, "[-] dlopen returned NULL — check logcat for details\n");
        return 1;
    }
    printf("[+] Library loaded, handle=0x%lx\n", (unsigned long)handle);
    return 0;
}
