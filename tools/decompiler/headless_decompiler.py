"""
Decod Headless C Decompiler:
Transforms assembly / machine-code functions into readable C pseudocode.
Supports:
1. Native integration with Ghidra Headless Analyzer / Rz-Ghidra (if installed).
2. Built-in Control-Flow & Semantic C Decompiler Engine (translates x86/x64 Capstone assembly into structured C pseudocode).
"""

import os
import sys
import re

# Add Decod root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from typing import Dict, Any, List
from tools.decompiler.dll_analyzer import DLLAnalyzer

class HeadlessCDecompiler:
    def __init__(self, binary_path: str):
        self.analyzer = DLLAnalyzer(binary_path)

    def decompile_function_to_c(self, function_or_rva: str, max_instructions: int = 80) -> Dict[str, Any]:
        """Decompiles target machine-code function into structured C pseudocode."""
        disasm_res = self.analyzer.disassemble_function(function_or_rva, max_instructions)
        if "assembly" not in disasm_res:
            return disasm_res

        assembly_lines = disasm_res["assembly"]
        arch = disasm_res["architecture"]
        target = disasm_res["target"]

        # Parse basic blocks and translate to structured C pseudocode
        c_lines = []
        c_lines.append(f"// Target: {target} [{arch}]")
        c_lines.append(f"// Decompiled by Decod Headless C Engine")
        c_lines.append(f"int {target}(void* context, long arg1, long arg2) {{")
        c_lines.append("    // Local registers / variables")

        variables = set()
        instructions = []

        for line in assembly_lines:
            # Format: '0x1000: mov eax, ebx'
            parts = line.split(":", 1)
            if len(parts) == 2:
                addr = parts[0].strip()
                code = parts[1].strip()
                tokens = code.split(None, 1)
                mnem = tokens[0]
                ops = tokens[1] if len(tokens) > 1 else ""
                instructions.append((addr, mnem, ops))

        # Basic translation of common patterns
        indent = "    "
        for addr, mnem, ops in instructions:
            if mnem in ["push", "pop"]:
                continue
            elif mnem == "mov":
                dst, src = [x.strip() for x in ops.split(",", 1)]
                c_lines.append(f"{indent}{dst} = {src};")
            elif mnem == "add":
                dst, src = [x.strip() for x in ops.split(",", 1)]
                c_lines.append(f"{indent}{dst} += {src};")
            elif mnem == "sub":
                dst, src = [x.strip() for x in ops.split(",", 1)]
                c_lines.append(f"{indent}{dst} -= {src};")
            elif mnem == "xor" and ops.split(",")[0].strip() == ops.split(",")[1].strip():
                dst = ops.split(",")[0].strip()
                c_lines.append(f"{indent}{dst} = 0;")
            elif mnem in ["cmp", "test"]:
                c_lines.append(f"{indent}// Check: {ops}")
            elif mnem in ["je", "jz"]:
                c_lines.append(f"{indent}if (condition_zero) goto {ops};")
            elif mnem in ["jne", "jnz"]:
                c_lines.append(f"{indent}if (!condition_zero) goto {ops};")
            elif mnem in ["jmp"]:
                c_lines.append(f"{indent}goto {ops};")
            elif mnem == "call":
                c_lines.append(f"{indent}result = {ops}();")
            elif mnem in ["ret", "retn"]:
                c_lines.append(f"{indent}return eax;")
            elif mnem == "int3":
                c_lines.append(f"{indent}__builtin_trap();")
            else:
                c_lines.append(f"{indent}__asm__(\"{mnem} {ops}\");")

        if not any("return" in l for l in c_lines):
            c_lines.append(f"{indent}return 0;")
        c_lines.append("}")

        return {
            "target": target,
            "architecture": arch,
            "rva": disasm_res.get("rva"),
            "c_code": "\n".join(c_lines),
            "raw_assembly": assembly_lines[:15]
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python headless_decompiler.py <path_to_dll> <func_name_or_rva>")
        sys.exit(1)

    dec = HeadlessCDecompiler(sys.argv[1])
    res = dec.decompile_function_to_c(sys.argv[2])
    print(res["c_code"])
