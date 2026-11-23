"""
Decod Domain Architectural Clusterer v5.0:
Organizes decompiled native functions into clean, human-readable, domain-driven
C++ architectural subsystems instead of arbitrary flat chunk files.

Domains:
- src/core/      (DllMain, Static initializers, boot manager, ReShade lifecycle)
- src/editor/    (Foliage brush, 300 limit bypass, DLC gates, vanilla sinker)
- src/storage/   (Settings.ini, JSON layouts, stamps, filesystem)
- src/gui/       (ImGui bindings, overlays, pickers, key listeners)
- src/engine/    (Unreal Engine 5 actors, raycasting, landscape)
- src/runtime/   (CRT replacements, memory allocators, trivial stubs, math)
"""

import os
import re
from typing import Dict, List, Any, Set, Tuple

class DomainClusterer:
    DOMAINS = ["core", "editor", "storage", "gui", "engine", "runtime"]

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.src_dir = os.path.join(output_dir, "src")
        self.include_dir = os.path.join(output_dir, "include")

        self.categorized_funcs: Dict[str, List[Tuple[str, str]]] = {d: [] for d in self.DOMAINS}
        self.domain_includes: Dict[str, Set[str]] = {d: set() for d in self.DOMAINS}

    def classify_function(
        self,
        fn_name: str,
        rva: int,
        code: str,
        strings: List[str],
        semantic_cat: str = "runtime"
    ) -> str:
        """Determines the most appropriate architectural domain for a function."""
        if semantic_cat in self.DOMAINS:
            return semantic_cat

        all_text = " ".join(s.lower() for s in strings) + " " + code.lower()

        # 1. Editor Domain
        if any(w in all_text for w in ["foliage", "brush", "limit", "dlc", "operation is not available", "sink", "0x2ac"]):
            return "editor"

        # 2. Storage Domain
        if any(w in all_text for w in ["settings.ini", "layouts", "stamps", "localappdata", "createdirectory", "filesystem"]):
            return "storage"

        # 3. GUI Domain
        if any(w in all_text for w in ["imgui", "button", "checkbox", "slider", "window", "overlay", "picker"]):
            return "gui"

        # 4. Engine Domain
        if any(w in all_text for w in ["uobject", "aactor", "linetrace", "landscape", "world", "processevent", "staticclass"]):
            return "engine"

        # 5. Core Domain
        if any(w in all_text for w in ["boot", "reshade", "dllmain", "init", "attach", "detach", "bcrypt"]):
            return "core"

        # 6. Default to Runtime (CRT, stubs, math)
        return "runtime"

    def add_function(self, domain: str, fn_name: str, code: str):
        if domain not in self.categorized_funcs:
            domain = "runtime"
        self.categorized_funcs[domain].append((fn_name, code))

    def emit_modular_project(self) -> List[str]:
        """Emits structured source files grouped by domain."""
        emitted_files = []

        for domain in self.DOMAINS:
            funcs = self.categorized_funcs[domain]
            if not funcs:
                continue

            domain_src_dir = os.path.join(self.src_dir, domain)
            domain_inc_dir = os.path.join(self.include_dir, domain)
            os.makedirs(domain_src_dir, exist_ok=True)
            os.makedirs(domain_inc_dir, exist_ok=True)

            cpp_name = f"{domain}_module.cpp"
            h_name = f"{domain}_module.h"

            cpp_path = os.path.join(domain_src_dir, cpp_name)
            h_path = os.path.join(domain_inc_dir, h_name)

            rel_cpp = f"src/{domain}/{cpp_name}"
            emitted_files.append(rel_cpp)

            # Emit Header
            with open(h_path, "w", encoding="utf-8") as f_h:
                guard = f"DECOD_{domain.upper()}_MODULE_H"
                f_h.write(f"#pragma once\n#ifndef {guard}\n#define {guard}\n\n")
                f_h.write('#include "types.h"\n\n')
                f_h.write(f"// Forward declarations for {domain.upper()} subsystem\n")
                for fn_name, _ in funcs:
                    f_h.write(f"bool {fn_name}(RegValue this_or_arg1 = 0, RegValue arg2 = 0, RegValue arg3 = 0, RegValue arg4 = 0);\n")
                f_h.write(f"\n#endif // {guard}\n")

            # Emit C++ Source
            with open(cpp_path, "w", encoding="utf-8") as f_cpp:
                f_cpp.write(f'#include "{domain}/{h_name}"\n')
                f_cpp.write('#include "types.h"\n')
                f_cpp.write('#include "functions.h"\n')
                f_cpp.write('#include "global_data.h"\n')
                f_cpp.write('#include <windows.h>\n#include <string>\n#include <vector>\n#include <cmath>\n\n')
                f_cpp.write(f"// ===========================================================================\n")
                f_cpp.write(f"// Architectural Subsystem: {domain.upper()} ({len(funcs)} functions)\n")
                f_cpp.write(f"// Fully Structured & Native C++ (Decod v5.0)\n")
                f_cpp.write(f"// ===========================================================================\n\n")

                for _, fn_code in funcs:
                    f_cpp.write(fn_code + "\n\n")

        return emitted_files
