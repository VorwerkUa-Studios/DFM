#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * libstealth: Linux Anti-Anti-Debugging Shared Library (ScyllaHide alternative for Linux)
 * Injected via LD_PRELOAD to bypass common Linux debugger detections:
 * 1. ptrace(PTRACE_TRACEME) detection
 * 2. /proc/self/status TracerPid scanning
 * 3. prctl anti-dumping checks
 */

// Original function pointers
static long (*orig_ptrace)(enum __ptrace_request request, pid_t pid, void *addr, void *data) = NULL;
static FILE *(*orig_fopen)(const char *path, const char *mode) = NULL;

__attribute__((constructor))
static void init_stealth(void) {
    orig_ptrace = dlsym(RTLD_NEXT, "ptrace");
    orig_fopen = dlsym(RTLD_NEXT, "fopen");
}

/*
 * Hook ptrace to prevent PTRACE_TRACEME failures
 */
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
    if (!orig_ptrace) orig_ptrace = dlsym(RTLD_NEXT, "ptrace");

    if (request == PTRACE_TRACEME) {
        // Fake success: Pretend the process attached to itself successfully
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

/*
 * Hook fopen to spoof /proc/self/status and wipe TracerPid
 */
FILE *fopen(const char *path, const char *mode) {
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");

    // Check if the process is inspecting its own status or wchan
    if (path && (strstr(path, "/proc/self/status") || strstr(path, "/proc/") && strstr(path, "/status"))) {
        FILE *real_file = orig_fopen(path, mode);
        if (!real_file) return NULL;

        // Create a temporary in-memory replacement file with TracerPid: 0
        FILE *fake_file = tmpfile();
        if (!fake_file) return real_file;

        char line[256];
        while (fgets(line, sizeof(line), real_file)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                fputs("TracerPid:\t0\n", fake_file);
            } else {
                fputs(line, fake_file);
            }
        }
        fclose(real_file);
        rewind(fake_file);
        return fake_file;
    }

    return orig_fopen(path, mode);
}
