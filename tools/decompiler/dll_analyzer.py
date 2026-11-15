"""
Decod DLL & Binary Disassembler / Analyzer:
Deep inspection and disassembly of DLL files (.dll, .so, .dylib, .exe).
Supports Native x86/x64, .NET Managed CLR detection, Export/Import resolution,
and function machine-code disassembly via Capstone.
"""

import os
import sys
from typing import Dict, Any, List, Optional
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

class DLLAnalyzer:
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        self.file_path = os.path.abspath(file_path)
        self.binary = lief.parse(self.file_path)
        if not self.binary:
            raise ValueError(f"Could not parse binary format for: {file_path}")

        self.is_pe = self.binary.format == lief.Binary.FORMATS.PE
        self.is_elf = self.binary.format == lief.Binary.FORMATS.ELF
        self.is_64bit = False
        self.is_dotnet = False

        if self.is_pe:
            self.is_64bit = self.binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
            if hasattr(self.binary, "data_directories"):
                self.is_dotnet = any(
                    d.type == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER and d.size > 0 
                    for d in self.binary.data_directories
                )
        elif self.is_elf:
            self.is_64bit = self.binary.header.identity_class == lief.ELF.Header.CLASS.ELF64

    def get_summary(self) -> Dict[str, Any]:
        """Returns structured metadata about the DLL / shared library."""
        exports = []
        if self.is_pe and hasattr(self.binary, "get_export"):
            try:
                exp_table = self.binary.get_export()
                if exp_table and hasattr(exp_table, "entries"):
                    for exp in exp_table.entries:
                        exports.append({
                            "name": getattr(exp, "name", "") or f"Ordinal_{getattr(exp, 'ordinal', 0)}",
                            "address": hex(getattr(exp, "address", 0)),
                            "ordinal": getattr(exp, "ordinal", None)
                        })
            except Exception:
                pass
        if not exports and hasattr(self.binary, "exported_functions"):
            for exp in self.binary.exported_functions:
                exports.append({
                    "name": getattr(exp, "name", "") or "unnamed",
                    "address": hex(getattr(exp, "address", 0)),
                    "ordinal": getattr(exp, "ordinal", None)
                })
        elif self.is_elf and hasattr(self.binary, "exported_symbols"):
            for sym in self.binary.exported_symbols:
                exports.append({
                    "name": sym.name,
                    "address": hex(sym.value)
                })

        imports = {}
        if self.is_pe and hasattr(self.binary, "imports"):
            for imp in self.binary.imports:
                imports[imp.name] = [getattr(entry, "name", "") or f"Ordinal_{getattr(entry, 'data', 0)}" for entry in list(imp.entries)[:20]]
        elif self.is_elf and hasattr(self.binary, "imported_symbols"):
            imports["dynamic_symbols"] = [getattr(s, "name", "") for s in list(self.binary.imported_symbols)[:50]]

        sections = []
        for s in self.binary.sections:
            sections.append({
                "name": s.name,
                "virtual_address": hex(s.virtual_address),
                "size": s.size,
                "entropy": round(s.entropy, 2)
            })

        return {
            "path": self.file_path,
            "format": str(self.binary.format),
            "architecture": "x64 (64-bit)" if self.is_64bit else "x86 (32-bit)",
            "is_dotnet_managed": self.is_dotnet,
            "entrypoint": hex(self.binary.entrypoint),
            "exports_count": len(exports),
            "exports": exports[:50],  # first 50
            "imports_libraries": list(imports.keys()),
            "sections": sections
        }

    def disassemble_function(self, target_address_or_name: str, max_instructions: int = 50) -> Dict[str, Any]:
        """Disassembles machine code at an export or virtual address using Capstone."""
        if self.is_dotnet:
            return {
                "status": "managed_code",
                "message": "This is a .NET CIL assembly. Use ilspycmd or dnSpy for C# source code decompile."
            }

        target_rva = None
        func_name = None

        # Check if target is an exported function name
        if self.is_pe and hasattr(self.binary, "exported_functions"):
            for exp in self.binary.exported_functions:
                if exp.name and exp.name.lower() == target_address_or_name.lower():
                    target_rva = exp.address
                    func_name = exp.name
                    break

        if target_rva is None:
            try:
                val = int(target_address_or_name, 16) if target_address_or_name.startswith("0x") else int(target_address_or_name)
                if hasattr(self.binary, "imagebase") and val >= self.binary.imagebase:
                    target_rva = val - self.binary.imagebase
                else:
                    target_rva = val
            except ValueError:
                raise ValueError(f"Could not resolve function name or address: {target_address_or_name}")

        file_offset = self.binary.rva_to_offset(target_rva)

        with open(self.file_path, "rb") as f:
            f.seek(file_offset, os.SEEK_SET)
            raw_bytes = f.read(max_instructions * 15)

        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)

        instructions = []
        for i, insn in enumerate(md.disasm(raw_bytes, target_rva)):
            if i >= max_instructions:
                break
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex()
            })
            if insn.mnemonic in ["ret", "retn", "retf"]:
                break

        return {
            "target": func_name or hex(target_rva),
            "rva": hex(target_rva),
            "file_offset": hex(file_offset),
            "architecture": "x64" if self.is_64bit else "x86",
            "instruction_count": len(instructions),
            "assembly": [f"{ins['address']}: {ins['mnemonic']} {ins['op_str']}".strip() for ins in instructions]
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dll_analyzer.py <path_to_dll> [function_name_or_rva]")
        sys.exit(1)

    analyzer = DLLAnalyzer(sys.argv[1])
    if len(sys.argv) == 2:
        import json
        print(json.dumps(analyzer.get_summary(), indent=2))
    else:
        import json
        disasm = analyzer.disassemble_function(sys.argv[2])
        print(json.dumps(disasm, indent=2))
