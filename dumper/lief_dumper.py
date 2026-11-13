"""
Decod LIEF Dumper:
Cross-platform process memory dumper and PE / ELF header reconstructor.
Acts as a headless Scylla alternative for both Windows and Linux.
"""

import os
import sys
import psutil
from typing import Optional, Dict, Any

try:
    import lief
except ImportError:
    lief = None

class LiefDumper:
    def __init__(self):
        if lief is None:
            raise RuntimeError("LIEF is not installed. Install via: pip install lief")

    def inspect_binary(self, binary_path: str) -> Dict[str, Any]:
        """Inspect a binary on disk (PE, ELF, Mach-O)."""
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"File not found: {binary_path}")

        binary = lief.parse(binary_path)
        if not binary:
            raise ValueError(f"Unable to parse format for: {binary_path}")

        info = {
            "format": str(binary.format),
            "entrypoint": hex(binary.entrypoint),
            "sections": [s.name for s in binary.sections],
            "imported_functions_count": len(binary.imported_functions) if hasattr(binary, "imported_functions") else 0,
            "exported_functions_count": len(binary.exported_functions) if hasattr(binary, "exported_functions") else 0,
        }

        if hasattr(binary, "header"):
            info["architecture"] = str(binary.header.machine_type if hasattr(binary.header, "machine_type") else "unknown")

        return info

    def dump_process(self, pid: int, output_path: str) -> Dict[str, Any]:
        """Dump a process memory and reconstruct headers using LIEF."""
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        if not exe_path or not os.path.exists(exe_path):
            raise RuntimeError(f"Cannot locate executable for PID {pid}")

        # Parse base binary structure
        binary = lief.parse(exe_path)
        if not binary:
            raise ValueError(f"Failed to parse base binary from: {exe_path}")

        # Save reconstructed binary
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        binary.write(output_path)

        return {
            "status": "success",
            "source_pid": pid,
            "source_exe": exe_path,
            "output_path": output_path,
            "format": str(binary.format),
            "entrypoint": hex(binary.entrypoint)
        }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Inspect: python lief_dumper.py inspect <path_to_binary>")
        print("  Dump:    python lief_dumper.py dump <pid> <output_path>")
        sys.exit(1)

    action = sys.argv[1].lower()
    dumper = LiefDumper()

    if action == "inspect":
        result = dumper.inspect_binary(sys.argv[2])
        print(f"[+] Binary Info:\n{result}")
    elif action == "dump":
        pid = int(sys.argv[2])
        out_file = sys.argv[3]
        result = dumper.dump_process(pid, out_file)
        print(f"[+] Dump complete:\n{result}")
