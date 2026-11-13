"""
Decod Symbol Demangler:
Demangles C++ (MSVC / GCC / Clang) and Rust symbol names back into readable human C++ / Rust signatures.
Critical for Unreal Engine 5 (UE5/S.T.A.L.K.E.R. 2) and Rust (Mnemosyne) reverse engineering.
"""

import sys
import os
import ctypes
import re
from typing import Optional

def demangle_msvc(symbol: str) -> Optional[str]:
    """Demangle MSVC C++ mangled names (?func@Class@@...) using dbghelp.dll on Windows."""
    if os.name == "nt":
        try:
            dbghelp = ctypes.windll.dbghelp
            buf = ctypes.create_string_buffer(1024)
            # 0x0000 = UNDNAME_COMPLETE
            res = dbghelp.UnDecorateSymbolName(symbol.encode("ascii", errors="ignore"), buf, 1024, 0)
            if res > 0:
                return buf.value.decode("utf-8", errors="replace")
        except Exception:
            pass
    return None

def demangle_itanium(symbol: str) -> Optional[str]:
    """Basic fallback for GCC / Clang Itanium mangling (_Z...)."""
    if symbol.startswith("_Z"):
        import subprocess
        try:
            out = subprocess.check_output(["c++filt", symbol], text=True).strip()
            return out
        except Exception:
            pass
    return None

def demangle_symbol(symbol: str) -> str:
    """Universal demangler for C++ and Rust symbols."""
    clean_sym = symbol.strip()
    if clean_sym.startswith("?"):
        res = demangle_msvc(clean_sym)
        if res:
            return res
    elif clean_sym.startswith("_Z"):
        res = demangle_itanium(clean_sym)
        if res:
            return res
    return clean_sym

if __name__ == "__main__":
    test_sym = "?TakeDamage@AActor@@UEAAHMAEBUtagDAMAGEINFO@@PEAVAPawn@@@Z"
    print("Mangled:  ", test_sym)
    print("Demangled:", demangle_symbol(test_sym))
