"""
Decod Frida Runner:
Programmatic dynamic instrumentation engine for Windows & Linux.
Supports 32-bit (x86) and 64-bit (x64) process attachment, script injection, and stealth.
Provides RPC-based direct live memory reading, writing, and scanning.
"""

import os
import sys
import json
import psutil
from typing import Optional, Dict, Any, List

try:
    import frida
except ImportError:
    frida = None

STEALTH_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "..", "stealth", "frida", "anti_anti_debug.js")

def enable_debug_privilege():
    """Enable SeDebugPrivilege on Windows to allow attaching to elevated/game processes."""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            SE_PRIVILEGE_ENABLED = 0x00000002
            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008

            hToken = wintypes.HANDLE()
            if advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
                luid = wintypes.LUID()
                if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                    class TOKEN_PRIVILEGES(ctypes.Structure):
                        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                                    ("Privileges", wintypes.LUID * 1),
                                    ("Attributes", wintypes.DWORD)]
                    tp = TOKEN_PRIVILEGES(1, (luid * 1)(luid), SE_PRIVILEGE_ENABLED)
                    advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
                kernel32.CloseHandle(hToken)
        except Exception:
            pass

FRIDA_RPC_SCRIPT = """
rpc.exports = {
    readMemory: function(addressStr, size) {
        try {
            var p = ptr(addressStr);
            var buf = Memory.readByteArray(p, size);
            // Convert ArrayBuffer to hex string
            var u8 = new Uint8Array(buf);
            var hex = [];
            for (var i = 0; i < u8.length; i++) {
                hex.push((u8[i] < 16 ? '0' : '') + u8[i].toString(16));
            }
            return { "status": "success", "hex": hex.join(" ") };
        } catch (e) {
            return { "status": "error", "error": e.message };
        }
    },
    writeMemory: function(addressStr, hexBytesStr) {
        try {
            var p = ptr(addressStr);
            var clean = hexBytesStr.replace(/\\s+/g, '');
            var len = clean.length / 2;
            Memory.protect(p, len, 'rwx');
            var bytes = [];
            for (var i = 0; i < clean.length; i += 2) {
                bytes.push(parseInt(clean.substr(i, 2), 16));
            }
            Memory.writeByteArray(p, bytes);
            return { "status": "success", "bytes_written": len };
        } catch (e) {
            return { "status": "error", "error": e.message };
        }
    },
    scanMemory: function(patternStr) {
        try {
            var ranges = Process.enumerateRanges('r-x');
            var results = [];
            for (var i = 0; i < ranges.length; i++) {
                var range = ranges[i];
                var matches = Memory.scanSync(range.base, range.size, patternStr);
                for (var j = 0; j < matches.length; j++) {
                    results.push({
                        "address": matches[j].address.toString(),
                        "size": matches[j].size
                    });
                    if (results.length >= 20) break;
                }
                if (results.length >= 20) break;
            }
            return { "status": "success", "matches": results };
        } catch (e) {
            return { "status": "error", "error": e.message };
        }
    }
};
"""

class FridaRunner:
    def __init__(self):
        if frida is None:
            raise RuntimeError("Frida is not installed. Install via: pip install frida frida-tools")
        enable_debug_privilege()
        self.device = frida.get_local_device()
        self.session = None
        self.rpc_script = None

    def find_pid(self, target: str | int) -> Optional[int]:
        if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
            return int(target)
        target_name = target.lower()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name']
                if name and target_name in name.lower():
                    return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def attach(self, target: str | int, enable_stealth: bool = True) -> int:
        pid = self.find_pid(target)
        if not pid:
            raise ProcessLookupError(f"Target process '{target}' not found.")

        self.session = self.device.attach(pid)

        # Inject stealth hooks first
        if enable_stealth and os.path.exists(STEALTH_SCRIPT_PATH):
            with open(STEALTH_SCRIPT_PATH, "r", encoding="utf-8") as f:
                stealth_code = f.read()
            stealth_script = self.session.create_script(stealth_code)
            stealth_script.load()

        # Inject RPC handler for direct memory operations
        self.rpc_script = self.session.create_script(FRIDA_RPC_SCRIPT)
        self.rpc_script.load()

        return pid

    def read_mem(self, address: str, size: int) -> dict:
        if not self.rpc_script:
            raise RuntimeError("Must attach to process first.")
        return self.rpc_script.exports_sync.read_memory(address, size)

    def write_mem(self, address: str, hex_bytes: str) -> dict:
        if not self.rpc_script:
            raise RuntimeError("Must attach to process first.")
        return self.rpc_script.exports_sync.write_memory(address, hex_bytes)

    def scan_mem(self, pattern: str) -> dict:
        if not self.rpc_script:
            raise RuntimeError("Must attach to process first.")
        return self.rpc_script.exports_sync.scan_memory(pattern)

    def detach(self):
        if self.session:
            self.session.detach()
            self.session = None

if __name__ == "__main__":
    runner = FridaRunner()
    print("[+] FridaRunner ready with SeDebugPrivilege and RPC memory controllers.")
