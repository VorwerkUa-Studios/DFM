"""
Decod Dynamic Skill Router:
Selectively activates skills, rules, and MCP tools based on user prompt intent.
Designed to minimize context window bloat and output tokens on FreeLLMAPI / OpenRouter Free.
"""

import os
import re
from typing import Dict, List, Any

# Profiles with their required toolset and rules
PROFILES = {
    "reversing": {
        "keywords": [
            "reverse", "decompile", "disassemble", "ghidra", "x64dbg", "frida", "hook",
            "dump", "lief", "memory", "ptrace", "spore", "package", "dbpf", "offset",
            "stalker", "ue5", "pak", "dumper", "iostore", "stealth", "unity", "godot",
            "pck", "vpk", "source", "il2cpp", "mono", "assembly-csharp", "detect_engine"
        ],
        "mcp_tools": [
            "detect_game_engine",
            "inspect_binary",
            "dump_process",
            "inject_frida_stealth",
            "unpack_dbpf_package",
            "unpack_godot_pck",
            "unpack_source_vpk",
            "inspect_unity_game"
        ],
        "rules": [
            "Always detect the game engine first before attempting to unpack or decompile.",
            "Operate in headless mode.",
            "Decompile only specific targeted functions; do not dump entire binary text.",
            "Check for 32-bit (x86) vs 64-bit (x64) differences when calculating offsets."
        ]
    },
    "coding": {
        "keywords": [
            "code", "rust", "python", "refactor", "bug", "implement", "feature", "test",
            "git", "commit", "review", "algorithm", "cargo", "function"
        ],
        "mcp_tools": ["lsp_goto_definition", "lsp_find_references"],
        "rules": [
            "Follow Karpathy & Ponytail principles: minimal dependencies, standard libraries, YAGNI.",
            "Do not over-engineer solutions.",
            "Write robust error handling."
        ]
    },
    "frontend": {
        "keywords": [
            "ui", "css", "tailwind", "html", "react", "component", "frontend", "design", "layout"
        ],
        "mcp_tools": ["magic_components", "playwright_browser"],
        "rules": [
            "Apply Impeccable UI principles: clean typography, accessible contrast, responsive layout.",
            "Prefer standard Tailwind utility classes."
        ]
    }
}

CAVEMAN_PROMPT = """
[CAVEMAN MODE ACTIVE]
- Be concise. Zero conversational filler, greetings, or recaps.
- Keep exact code, commands, paths, and technical parameters verbatim.
- State actions and results immediately.
"""

class SkillRouter:
    def __init__(self, use_caveman: bool = True):
        self.use_caveman = use_caveman

    def route(self, prompt: str) -> Dict[str, Any]:
        prompt_lower = prompt.lower()
        matched_profiles = []

        for profile_name, data in PROFILES.items():
            for kw in data["keywords"]:
                if re.search(rf"\b{re.escape(kw)}\b", prompt_lower):
                    matched_profiles.append(profile_name)
                    break

        # Default to 'coding' if nothing matched
        if not matched_profiles:
            matched_profiles = ["coding"]

        active_tools = set()
        active_rules = []

        for p in matched_profiles:
            cfg = PROFILES[p]
            active_tools.update(cfg["mcp_tools"])
            active_rules.extend(cfg["rules"])

        system_prompt = ""
        if self.use_caveman:
            system_prompt += CAVEMAN_PROMPT.strip() + "\n\n"

        system_prompt += "### Active Rules:\n" + "\n".join(f"- {r}" for r in active_rules)

        return {
            "matched_profiles": matched_profiles,
            "active_tools": list(active_tools),
            "system_prompt": system_prompt
        }

if __name__ == "__main__":
    router = SkillRouter(use_caveman=True)
    sample_queries = [
        "Визнач рушій у цій папці гри та розпакуй ресурси",
        "Розпакуй Godot pck архів і дістань скрипти",
        "Як розібрати Unity гру на IL2CPP?"
    ]

    for q in sample_queries:
        res = router.route(q)
        print(f"\nQuery: '{q}'")
        print(f"Profiles: {res['matched_profiles']}")
        print(f"Active Tools: {res['active_tools']}")
