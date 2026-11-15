"""
Decod Headless MCP Server v2:
Standard JSON-RPC 2.0 Model Context Protocol Server for Claude Code & Mnemosyne.
Exposes cross-platform reverse engineering, memory dumping, DLL analysis, C decompilation,
signature scanning, binary patching, 3D model tools, MIDI music composition,
FFmpeg audio/video conversion, game localization, multi-format game extraction,
AI memory scanner (Cheat Engine), Offset Vault (SQLite), and UE4SS Lua modding tools.
"""

import sys
import os
import json
import traceback

# Ensure Decod root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engines.detector import detect_engine
from engines.classic.dbpf_unpacker import DBPFPackage
from engines.godot.godot_helper import GodotPCK
from engines.source.vpk_helper import VPKPackage
from engines.unity.unity_helper import UnityHelper
from engines.ue5.ue_helper import UEHelper
from engines.jvm.java_helper import JavaHelper
from engines.electron.asar_helper import AsarUnpacker
from engines.assets.model_helper import Model3DHelper
from engines.assets.audio_helper import compose_midi
from engines.assets.localization_helper import LocalizationHelper
from engines.assets.media_converter import MediaConverter
from tools.decompiler.dll_analyzer import DLLAnalyzer
from tools.decompiler.headless_decompiler import HeadlessCDecompiler
from tools.decompiler.demangler import demangle_symbol
from tools.scanner.sig_scanner import SigScanner
from tools.patcher.binary_patcher import BinaryPatcher
from tools.scanner.memory_scanner import snapshot, diff_snapshot, read_memory_value, write_memory_value, quick_scan
from tools.vault.offset_vault import add_offset, list_offsets, get_offset, delete_offset, rescan_offsets, import_offsets, export_vault
from engines.ue5.ue4ss_helper import check_ue4ss, scaffold_mod, scaffold_map_editor, list_mods, enable_mod
from engines.assets.audio_helper import compose_midi
from tools.code.code_analyzer import inspect_code_structure, extract_function_definition, check_code_diagnostics, run_git_summary
from tools.security.strix_pentester import run_situational_security_audit, check_strix_status

ue_helper = UEHelper()
media_converter = MediaConverter()

TOOLS = [
    {
        "name": "convert_media_file",
        "description": "Convert audio or video files between formats (MP3, OGG, WAV, FLAC, MP4, WebM, GIF) using FFmpeg.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {"type": "string", "description": "Source file path."},
                "output_path": {"type": "string", "description": "Destination file path with new extension."}
            },
            "required": ["input_path", "output_path"]
        }
    },
    {
        "name": "extract_audio_from_video",
        "description": "Extract audio track from video files or game cutscenes via FFmpeg.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "video_path": {"type": "string", "description": "Path to input video/cutscene."},
                "output_audio_path": {"type": "string", "description": "Path to save extracted audio (e.g. sound.ogg or sound.wav)."}
            },
            "required": ["video_path", "output_audio_path"]
        }
    },
    {
        "name": "inspect_media_file",
        "description": "Inspect audio/video codecs, sample rates, channels, bitrate, and duration via ffprobe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to media file."}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "compose_midi_music",
        "description": "Compose and export standard playable MIDI (.mid) music and melodies with instruments, BPM, and note sequences.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bpm": {"type": "integer", "description": "Tempo in Beats Per Minute (e.g. 120)."},
                "instrument": {"type": "integer", "description": "General MIDI instrument (0=Grand Piano, 25=Steel Guitar, 80=Lead Synth)."},
                "notes": {
                    "type": "array",
                    "description": "List of notes: [{'note': 'C4', 'duration': 1.0, 'velocity': 90}]",
                    "items": {"type": "object"}
                },
                "output_path": {"type": "string", "description": "Path to write the .mid file."}
            },
            "required": ["bpm", "notes", "output_path"]
        }
    },
    {
        "name": "inspect_3d_model",
        "description": "Parse and inspect 3D models (.obj), analyzing vertex counts, faces, materials, and bounding box dimensions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model_path": {"type": "string", "description": "Path to .obj file."}
            },
            "required": ["model_path"]
        }
    },
    {
        "name": "create_minecraft_block_model",
        "description": "Generate a valid Minecraft JSON block model structure for modding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Block name."},
                "texture": {"type": "string", "description": "Texture identifier (e.g. 'block/my_block')."}
            },
            "required": ["name", "texture"]
        }
    },
    {
        "name": "extract_game_strings",
        "description": "Extract text strings from game localization files (JSON, CSV) for AI translation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to language file (e.g. en_us.json)."}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "save_game_translation",
        "description": "Save translated strings into game localization format (e.g. uk_ua.json).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "translated_dict": {"type": "object", "description": "Key-value dictionary of translated strings."},
                "output_path": {"type": "string", "description": "Output path."}
            },
            "required": ["translated_dict", "output_path"]
        }
    },
    {
        "name": "search_binary_strings",
        "description": "Extract and search ASCII & Unicode UTF-16 strings inside any binary, DLL, or EXE, returning file offsets and memory RVAs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file."},
                "query": {"type": "string", "description": "Substring to search for (e.g. 'Stalker', 'Health', 'Key')."},
                "max_results": {"type": "integer", "description": "Limit results (default 50)."}
            },
            "required": ["binary_path"]
        }
    },
    {
        "name": "scan_aob_pattern",
        "description": "Scan a binary for an Array of Bytes (AOB) signature pattern with wildcards (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file."},
                "pattern": {"type": "string", "description": "Hex pattern with ?? wildcards."},
                "max_results": {"type": "integer", "description": "Max matches (default 20)."}
            },
            "required": ["binary_path", "pattern"]
        }
    },
    {
        "name": "demangle_cpp_symbol",
        "description": "Demangle MSVC C++ or GCC/Clang/Rust mangled symbol names back into readable C++ function signatures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "Mangled symbol (e.g. '?TakeDamage@AActor@@...')."}
            },
            "required": ["symbol"]
        }
    },
    {
        "name": "patch_binary_bytes",
        "description": "Safely patch specific hex bytes at a file offset in an EXE or DLL with automatic .bak backup creation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to binary file."},
                "offset": {"type": "string", "description": "File offset in hex (e.g. '0x1F40') or decimal."},
                "hex_bytes": {"type": "string", "description": "New bytes in hex (e.g. '90 90' or 'EB 05')."},
                "backup": {"type": "boolean", "description": "Create .bak backup (default true)."}
            },
            "required": ["file_path", "offset", "hex_bytes"]
        }
    },
    {
        "name": "decompile_function_to_c",
        "description": "Decompile machine-code function inside a DLL or EXE into structured C pseudocode for AI analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file (.dll, .exe, .so)."},
                "function_or_address": {"type": "string", "description": "Function name or RVA/virtual address."},
                "max_instructions": {"type": "integer", "description": "Instruction depth limit (default 80)."}
            },
            "required": ["binary_path", "function_or_address"]
        }
    },
    {
        "name": "inspect_dll",
        "description": "Deep inspection of a DLL, SO, or EXE: checks architecture (x86 vs x64), detects .NET CLR vs Native, lists exported and imported functions, and analyzes section entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dll_path": {"type": "string", "description": "Absolute path to the .dll, .so, or .exe file."}
            },
            "required": ["dll_path"]
        }
    },
    {
        "name": "disassemble_dll_function",
        "description": "Disassemble machine code at an exported function name or RVA/virtual address inside a DLL or EXE via Capstone (x86/x64).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dll_path": {"type": "string", "description": "Path to the binary file."},
                "function_or_address": {"type": "string", "description": "Exported function name or hex address."},
                "max_instructions": {"type": "integer", "description": "Maximum instructions to disassemble (default 50)."}
            },
            "required": ["dll_path", "function_or_address"]
        }
    },
    {
        "name": "unpack_jar_package",
        "description": "Unpack a Java archive (.jar, .war, .apk) such as Minecraft or Android packages, extracting .class bytecode and game assets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jar_path": {"type": "string", "description": "Path to the .jar file."},
                "output_dir": {"type": "string", "description": "Output directory."}
            },
            "required": ["jar_path", "output_dir"]
        }
    },
    {
        "name": "read_minecraft_nbt",
        "description": "Read and parse Minecraft binary NBT format files (level.dat, player .dat, chunk data) into structured JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "nbt_path": {"type": "string", "description": "Path to the .dat or NBT file."}
            },
            "required": ["nbt_path"]
        }
    },
    {
        "name": "unpack_electron_asar",
        "description": "Extract full source code (JavaScript, HTML, CSS, configs) from an Electron desktop app archive (app.asar) like Discord, VS Code, or Obsidian.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asar_path": {"type": "string", "description": "Path to the app.asar file."},
                "output_dir": {"type": "string", "description": "Output directory."}
            },
            "required": ["asar_path", "output_dir"]
        }
    },
    {
        "name": "detect_game_engine",
        "description": "Scan a game directory to automatically detect its engine (Unreal Engine 4/5, Unity Mono/IL2CPP, Godot, Valve Source, EA Maxis DBPF).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string", "description": "Path to the target game directory."}
            },
            "required": ["game_dir"]
        }
    },
    {
        "name": "unpack_ue_pak",
        "description": "Unpack Unreal Engine 4/5 (.pak, IoStore) archives (e.g. S.T.A.L.K.E.R. 2) using repak.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pak_path": {"type": "string", "description": "Path to the .pak file."},
                "output_dir": {"type": "string", "description": "Output directory."},
                "aes_key": {"type": "string", "description": "Optional 256-bit AES encryption key (0x...)."}
            },
            "required": ["pak_path", "output_dir"]
        }
    },
    {
        "name": "list_ue_pak",
        "description": "List files inside a UE4/UE5 .pak archive without extracting them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pak_path": {"type": "string", "description": "Path to the .pak file."},
                "aes_key": {"type": "string", "description": "Optional AES key."}
            },
            "required": ["pak_path"]
        }
    },
    {
        "name": "convert_ue_save_to_json",
        "description": "Convert an Unreal Engine save file (.sav, GVAS) to JSON format via uesave.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sav_path": {"type": "string", "description": "Path to .sav file."},
                "json_out_path": {"type": "string", "description": "Path to write output JSON."}
            },
            "required": ["sav_path", "json_out_path"]
        }
    },
    {
        "name": "convert_json_to_ue_save",
        "description": "Convert a modified JSON file back into an Unreal Engine binary save file (.sav).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "json_in_path": {"type": "string", "description": "Path to input JSON."},
                "sav_out_path": {"type": "string", "description": "Path to output .sav."}
            },
            "required": ["json_in_path", "sav_out_path"]
        }
    },
    {
        "name": "list_processes",
        "description": "List running processes with PID and executable paths on the host system (Windows/Linux).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter_name": {"type": "string", "description": "Optional substring to filter process names."}
            }
        }
    },
    {
        "name": "dump_process",
        "description": "Dump process memory and reconstruct binary headers using LIEF (headless Scylla equivalent).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target process ID."},
                "output_path": {"type": "string", "description": "Path to write the dumped executable."}
            },
            "required": ["pid", "output_path"]
        }
    },
    {
        "name": "unpack_dbpf_package",
        "description": "Extract assets from an EA DBPF package file (.package) used in Spore, The Sims 2/3/4, or SimCity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_path": {"type": "string", "description": "Path to the .package file."},
                "output_dir": {"type": "string", "description": "Directory to save extracted assets."}
            },
            "required": ["package_path", "output_dir"]
        }
    },
    {
        "name": "unpack_godot_pck",
        "description": "Extract GDScript scenes, scripts, and assets from a Godot Engine .pck package archive.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pck_path": {"type": "string", "description": "Path to the .pck file."},
                "output_dir": {"type": "string", "description": "Directory to save extracted assets."}
            },
            "required": ["pck_path", "output_dir"]
        }
    },
    {
        "name": "unpack_source_vpk",
        "description": "Extract maps, models, textures, and sounds from a Valve Source Engine .vpk package.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vpk_path": {"type": "string", "description": "Path to the .vpk file."},
                "output_dir": {"type": "string", "description": "Directory to save extracted assets."}
            },
            "required": ["vpk_path", "output_dir"]
        }
    },
    {
        "name": "inspect_unity_game",
        "description": "Inspect a Unity game folder to detect whether it is Mono (.NET) or IL2CPP (native), and locate main assemblies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string", "description": "Path to the Unity game root directory."}
            },
            "required": ["game_dir"]
        }
    },
    {
        "name": "inject_frida_stealth",
        "description": "Attach Frida to a target process and inject anti-anti-debugging hooks (neutralizes IsDebuggerPresent, ptrace, PEB checks).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID."}
            },
            "required": ["target"]
        }
    },
    # ── Memory Scanner (AI Cheat Engine) ──────────────────────────────────────
    {
        "name": "memory_snapshot",
        "description": "Take a snapshot of a process's readable memory regions. First step of two-pass memory diff scanning (like Cheat Engine). Use to find health, ammo, coordinates etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target process ID."},
                "value_type": {"type": "string", "description": "Data type to scan: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 (default: u32)."}
            },
            "required": ["pid"]
        }
    },
    {
        "name": "memory_diff",
        "description": "Compare a saved memory snapshot vs current live process memory to find addresses that changed to a specific value. Second step of two-pass memory scanning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string", "description": "Snapshot ID returned by memory_snapshot."},
                "new_value": {"description": "Value the address should now contain (e.g. current health after taking damage)."},
                "max_results": {"type": "integer", "description": "Max addresses to return (default 500)."}
            },
            "required": ["snapshot_id", "new_value"]
        }
    },
    {
        "name": "memory_read",
        "description": "Read a single value from a process memory address (requires Frida attach).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "address": {"type": "string", "description": "Hex address string (e.g. '0x7FF4A3B00')."},
                "value_type": {"type": "string", "description": "u8/u16/u32/u64/f32/f64 etc."}
            },
            "required": ["pid", "address"]
        }
    },
    {
        "name": "memory_write",
        "description": "Write a value to a process memory address (requires Frida attach). Use for game value manipulation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "address": {"type": "string", "description": "Hex address string."},
                "value": {"description": "Value to write."},
                "value_type": {"type": "string", "description": "u8/u16/u32/u64/f32/f64 etc."}
            },
            "required": ["pid", "address", "value"]
        }
    },
    {
        "name": "memory_quick_scan",
        "description": "One-shot Frida memory scan for a known value. No snapshot needed. Use when you already know the exact current value (e.g. health=100).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "value": {"description": "Value to find."},
                "value_type": {"type": "string", "description": "u8/u16/u32/u64/f32/f64 (default: u32)."},
                "max_results": {"type": "integer"}
            },
            "required": ["pid", "value"]
        }
    },
    # ── Offset Vault ─────────────────────────────────────────────────────────
    {
        "name": "vault_add",
        "description": "Save a function offset or AOB pattern to the persistent Offset Vault SQLite database. Offsets survive game patches via AOB re-scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game": {"type": "string", "description": "Game name (e.g. 'stalker2')."},
                "name": {"type": "string", "description": "Offset name (e.g. 'TakeDamage', 'PlayerHealth')."},
                "address_hex": {"type": "string", "description": "Current hex address (e.g. '0x14A2B3C00')."},
                "aob_pattern": {"type": "string", "description": "AOB byte pattern for auto-rescan (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0')."},
                "module": {"type": "string", "description": "Module/DLL name."},
                "version": {"type": "string", "description": "Game version string."},
                "notes": {"type": "string"}
            },
            "required": ["game", "name"]
        }
    },
    {
        "name": "vault_list",
        "description": "List all offsets in the Vault, optionally filtered by game name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game": {"type": "string", "description": "Filter by game name (optional)."}
            }
        }
    },
    {
        "name": "vault_rescan",
        "description": "Re-scan a game binary for all stored AOB patterns and auto-update addresses after a game patch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game": {"type": "string"},
                "binary_path": {"type": "string", "description": "Path to game .exe or .dll to scan."}
            },
            "required": ["game", "binary_path"]
        }
    },
    # ── UE4SS ────────────────────────────────────────────────────────────────
    {
        "name": "ue4ss_check",
        "description": "Check if UE4SS is installed in a game directory and locate the Mods/ folder.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string", "description": "Path to game root or Binaries/Win64 directory."}
            },
            "required": ["game_dir"]
        }
    },
    {
        "name": "ue4ss_scaffold_mod",
        "description": "Generate a UE4SS Lua mod scaffold (main.lua + enabled.txt) ready to drop into Mods/ folder.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "description": "Directory to create the mod folder in."},
                "mod_name": {"type": "string", "description": "Mod folder/display name."},
                "description": {"type": "string"},
                "version": {"type": "string"}
            },
            "required": ["output_dir", "mod_name"]
        }
    },
    {
        "name": "ue4ss_map_editor",
        "description": "Generate and optionally deploy the STALKER 2 Map & Object Editor UE4SS Lua mod with ImGui overlay, actor list, transform gizmo, crosshair teleport, and JSON persistence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "description": "Directory to output the mod files."},
                "game_dir": {"type": "string", "description": "Game directory to auto-deploy into (optional)."},
                "save_path": {"type": "string", "description": "JSON file to save object placements (optional)."}
            },
            "required": ["output_dir"]
        }
    },
    {
        "name": "ue4ss_list_mods",
        "description": "List all UE4SS mods installed in a game directory, with enabled/disabled status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string"}
            },
            "required": ["game_dir"]
        }
    },
    # ── Code Intelligence & Diagnostics (Token Saver) ─────────────────────────
    {
        "name": "inspect_code_structure",
        "description": "Fast AST outline of a code file (Rust, Python, C/C++, C#, Lua). Returns list of functions, classes, structs, and line numbers without reading thousands of lines.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to source file."}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "extract_function_definition",
        "description": "Extract ONLY the implementation body of a specific function or class by name from a file. Saves 90%+ tokens.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to source file."},
                "symbol_name": {"type": "string", "description": "Name of function or class to extract."}
            },
            "required": ["file_path", "symbol_name"]
        }
    },
    {
        "name": "check_code_diagnostics",
        "description": "Run compiler checks or linters (cargo check for Rust, py_compile for Python) to verify syntax without full builds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to project directory, Cargo.toml, or source file."}
            },
            "required": ["path"]
        }
    },
    {
        "name": "run_git_summary",
        "description": "Get a token-compact git summary: branch, modified/untracked files, and diff stat.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to git repository root."}
            },
            "required": ["repo_path"]
        }
    },
    # ── Security & Web Pentesting (Strix AI) ──────────────────────────
    {
        "name": "run_security_audit",
        "description": "Situational web & backend security audit using usestrix/strix autonomous pentesting agent (if installed) or high-speed built-in SAST static analyzer. Scans for hardcoded API keys, JWT, private keys, SQL injection, RCE, CORS, and XSS.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Local project path, source file, or URL to audit."},
                "scan_mode": {"type": "string", "description": "Scan intensity: 'quick' (default) or 'deep'.", "default": "quick"},
                "max_budget": {"type": "integer", "description": "Max budget in USD if using Strix LLM (default 5).", "default": 5}
            },
            "required": ["target"]
        }
    },
    {
        "name": "check_security_tools_status",
        "description": "Check if Strix AI pentester CLI, Docker runtime, and SAST analyzers are installed and ready.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

def handle_tool_call(name: str, args: dict) -> dict:
    try:
        if name == "convert_media_file":
            return media_converter.convert_media(args["input_path"], args["output_path"])

        elif name == "extract_audio_from_video":
            return media_converter.extract_audio(args["video_path"], args["output_audio_path"])

        elif name == "inspect_media_file":
            return media_converter.inspect_media(args["file_path"])

        elif name == "compose_midi_music":
            return compose_midi(
                output_path=args["output_path"],
                bpm=args.get("bpm", 120),
                tracks=args.get("tracks"),
                preset=args.get("preset"),
                seed=args.get("seed", 42),
            )

        elif name == "inspect_3d_model":
            return Model3DHelper.inspect_obj(args["model_path"])

        elif name == "create_minecraft_block_model":
            return Model3DHelper.create_minecraft_block_model(args["name"], args["texture"])

        elif name == "extract_game_strings":
            data = LocalizationHelper.extract_strings_from_json(args["file_path"])
            return {"status": "success", "total_strings": len(data), "sample": dict(list(data.items())[:10])}

        elif name == "save_game_translation":
            out = LocalizationHelper.save_translated_json(args["translated_dict"], args["output_path"])
            return {"status": "success", "saved_file": out}

        elif name == "search_binary_strings":
            scanner = SigScanner(args["binary_path"])
            query = args.get("query", "")
            limit = args.get("max_results", 50)
            return {"status": "success", "results": scanner.search_strings(query=query, max_results=limit)}

        elif name == "scan_aob_pattern":
            scanner = SigScanner(args["binary_path"])
            limit = args.get("max_results", 20)
            matches = scanner.scan_aob(args["pattern"], max_results=limit)
            return {"status": "success", "matches": matches}

        elif name == "demangle_cpp_symbol":
            return {"original": args["symbol"], "demangled": demangle_symbol(args["symbol"])}

        elif name == "patch_binary_bytes":
            patcher = BinaryPatcher(args["file_path"])
            backup = args.get("backup", True)
            return patcher.patch_bytes(args["offset"], args["hex_bytes"], backup=backup)

        elif name == "decompile_function_to_c":
            dec = HeadlessCDecompiler(args["binary_path"])
            max_insn = args.get("max_instructions", 80)
            return dec.decompile_function_to_c(args["function_or_address"], max_insn)

        elif name == "inspect_dll":
            analyzer = DLLAnalyzer(args["dll_path"])
            return analyzer.get_summary()

        elif name == "disassemble_dll_function":
            analyzer = DLLAnalyzer(args["dll_path"])
            max_insn = args.get("max_instructions", 50)
            return analyzer.disassemble_function(args["function_or_address"], max_insn)

        elif name == "unpack_jar_package":
            return JavaHelper.unpack_jar(args["jar_path"], args["output_dir"])

        elif name == "read_minecraft_nbt":
            return JavaHelper.parse_minecraft_nbt(args["nbt_path"])

        elif name == "unpack_electron_asar":
            unpacker = AsarUnpacker(args["asar_path"])
            count = unpacker.extract_all(args["output_dir"])
            return {"status": "success", "extracted_files": count, "output_dir": args["output_dir"]}

        elif name == "detect_game_engine":
            return detect_engine(args["game_dir"])

        elif name == "unpack_ue_pak":
            return ue_helper.unpack_pak(args["pak_path"], args["output_dir"], args.get("aes_key"))

        elif name == "list_ue_pak":
            return ue_helper.list_pak(args["pak_path"], args.get("aes_key"))

        elif name == "convert_ue_save_to_json":
            return ue_helper.convert_save_to_json(args["sav_path"], args["json_out_path"])

        elif name == "convert_json_to_ue_save":
            return ue_helper.convert_json_to_save(args["json_in_path"], args["sav_out_path"])

        elif name == "list_processes":
            import psutil
            filter_name = args.get("filter_name", "").lower()
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pname = p.info['name'] or ""
                    if not filter_name or filter_name in pname.lower():
                        procs.append({
                            "pid": p.info['pid'],
                            "name": pname,
                            "exe": p.info['exe'] or ""
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return {"status": "success", "count": len(procs), "processes": procs[:100]}

        elif name == "dump_process":
            from dumper.lief_dumper import LiefDumper
            dumper = LiefDumper()
            res = dumper.dump_process(args["pid"], args["output_path"])
            return res

        elif name == "unpack_dbpf_package":
            pkg = DBPFPackage(args["package_path"])
            count = pkg.extract_all(args["output_dir"])
            return {
                "status": "success",
                "extracted_count": count,
                "version": f"{pkg.version_major}.{pkg.version_minor}",
                "output_dir": args["output_dir"]
            }

        elif name == "unpack_godot_pck":
            pck = GodotPCK(args["pck_path"])
            count = pck.extract_all(args["output_dir"])
            return {
                "status": "success",
                "extracted_count": count,
                "godot_version": f"{pck.godot_version[0]}.{pck.godot_version[1]}.{pck.godot_version[2]}",
                "output_dir": args["output_dir"]
            }

        elif name == "unpack_source_vpk":
            vpk = VPKPackage(args["vpk_path"])
            count = vpk.extract_all(args["output_dir"])
            return {
                "status": "success",
                "extracted_count": count,
                "version": vpk.version,
                "output_dir": args["output_dir"]
            }

        elif name == "inspect_unity_game":
            helper = UnityHelper(args["game_dir"])
            return helper.get_info()

        elif name == "inject_frida_stealth":
            from core.frida_runner import FridaRunner
            runner = FridaRunner()
            pid = runner.attach(args["target"], enable_stealth=True)
            return {"status": "success", "pid": pid, "stealth": True}

        # ── Memory Scanner ────────────────────────────────────────────────────
        elif name == "memory_snapshot":
            return snapshot(args["pid"], args.get("value_type", "u32"))

        elif name == "memory_diff":
            return diff_snapshot(args["snapshot_id"], args["new_value"], args.get("max_results", 500))

        elif name == "memory_read":
            return read_memory_value(args["pid"], args["address"], args.get("value_type", "u32"))

        elif name == "memory_write":
            return write_memory_value(args["pid"], args["address"], args["value"], args.get("value_type", "u32"))

        elif name == "memory_quick_scan":
            return quick_scan(args["pid"], args["value"], args.get("value_type", "u32"), args.get("max_results", 200))

        # ── Offset Vault ──────────────────────────────────────────────────────
        elif name == "vault_add":
            return add_offset(
                game=args["game"], name=args["name"],
                address_hex=args.get("address_hex"), aob_pattern=args.get("aob_pattern"),
                module=args.get("module"), version=args.get("version", "any"),
                notes=args.get("notes"),
            )

        elif name == "vault_list":
            return list_offsets(args.get("game"))

        elif name == "vault_rescan":
            return rescan_offsets(args["game"], args["binary_path"])

        # ── UE4SS ─────────────────────────────────────────────────────────────
        elif name == "ue4ss_check":
            return check_ue4ss(args["game_dir"])

        elif name == "ue4ss_scaffold_mod":
            return scaffold_mod(args["output_dir"], args["mod_name"],
                                args.get("description", "Custom mod"), args.get("version", "1.0.0"))

        elif name == "ue4ss_map_editor":
            return scaffold_map_editor(args["output_dir"], args.get("game_dir"), args.get("save_path"))

        elif name == "ue4ss_list_mods":
            return list_mods(args["game_dir"])

        # ── Code Intelligence & Diagnostics ──────────────────────────────────
        elif name == "inspect_code_structure":
            return inspect_code_structure(args["file_path"])

        elif name == "extract_function_definition":
            return extract_function_definition(args["file_path"], args["symbol_name"])

        elif name == "check_code_diagnostics":
            return check_code_diagnostics(args["path"])

        elif name == "run_git_summary":
            return run_git_summary(args["repo_path"])

        # ── Security & Web Pentesting (Strix AI) ──────────────────────
        elif name == "run_security_audit":
            return run_situational_security_audit(
                args["target"],
                scan_mode=args.get("scan_mode", "quick"),
                max_budget=args.get("max_budget", 5)
            )

        elif name == "check_security_tools_status":
            return check_strix_status()

        else:
            return {"status": "error", "message": f"Unknown tool: {name}"}

    except Exception as e:
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}

def main():
    """Main JSON-RPC stdio loop for Model Context Protocol."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": "decod-re-engine",
                            "version": "1.0.0"
                        },
                        "capabilities": {
                            "tools": {}
                        }
                    }
                }
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": TOOLS
                    }
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                res = handle_tool_call(tool_name, tool_args)
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(res, indent=2)
                            }
                        ]
                    }
                }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }

            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
