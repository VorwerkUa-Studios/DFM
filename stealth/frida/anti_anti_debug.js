/**
 * Universal Frida Anti-Anti-Debugging Script (Windows & Linux)
 * Injected into target processes to neutralize active debugger detection checks.
 */

console.log("[+] Decod Stealth Engine active on platform: " + Process.platform);

if (Process.platform === "windows") {
    // 1. Hook IsDebuggerPresent
    const isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
    if (isDebuggerPresent) {
        Interceptor.attach(isDebuggerPresent, {
            onLeave: function (retval) {
                retval.replace(0);
            }
        });
        console.log("[+] Hooked kernel32!IsDebuggerPresent -> 0");
    }

    // 2. Hook CheckRemoteDebuggerPresent
    const checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
    if (checkRemoteDebugger) {
        Interceptor.attach(checkRemoteDebugger, {
            onEnter: function (args) {
                this.pbDebuggerPresent = args[1];
            },
            onLeave: function (retval) {
                if (!this.pbDebuggerPresent.isNull()) {
                    this.pbDebuggerPresent.writeU8(0);
                }
                retval.replace(1);
            }
        });
        console.log("[+] Hooked kernel32!CheckRemoteDebuggerPresent -> false");
    }

    // 3. Hook NtQueryInformationProcess
    const ntQueryInfoProcess = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
    if (ntQueryInfoProcess) {
        Interceptor.attach(ntQueryInfoProcess, {
            onEnter: function (args) {
                this.processInformationClass = args[1].toInt32();
                this.processInformation = args[2];
            },
            onLeave: function (retval) {
                // ProcessDebugPort (7)
                if (this.processInformationClass === 7 && !this.processInformation.isNull()) {
                    this.processInformation.writePointer(ptr(0));
                    retval.replace(0);
                }
                // ProcessDebugFlags (0x1f) -> Should be 1 (NoDebugInherit)
                if (this.processInformationClass === 0x1f && !this.processInformation.isNull()) {
                    this.processInformation.writeU32(1);
                    retval.replace(0);
                }
            }
        });
        console.log("[+] Hooked ntdll!NtQueryInformationProcess (DebugPort, DebugFlags)");
    }
} else if (Process.platform === "linux") {
    // Linux stealth hooks
    const ptrace = Module.findExportByName(null, "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function (args) {
                this.req = args[0].toInt32();
            },
            onLeave: function (retval) {
                // PTRACE_TRACEME = 0
                if (this.req === 0) {
                    retval.replace(0);
                }
            }
        });
        console.log("[+] Hooked libc!ptrace (PTRACE_TRACEME -> 0)");
    }
}
