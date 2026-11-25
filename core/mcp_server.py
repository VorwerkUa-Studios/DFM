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
from tools.decompiler.crypto_detector import CryptoDetector
from tools.decompiler.project_decompiler import ProjectDecompiler
from tools.decompiler.decompile_full_binary import deconstruct_entire_binary
from tools.decompiler.demangler import demangle_symbol
from tools.scanner.sig_scanner import SigScanner
from tools.patcher.binary_patcher import BinaryPatcher
from tools.scanner.memory_scanner import snapshot, diff_snapshot, read_memory_value, write_memory_value, quick_scan
from tools.vault.offset_vault import add_offset, list_offsets, get_offset, delete_offset, rescan_offsets, import_offsets, export_vault
from engines.ue5.ue4ss_helper import check_ue4ss, scaffold_mod, scaffold_map_editor, list_mods, enable_mod
from engines.ue5.world_converter import WorldConverter
from engines.ue5.cue4parse_helper import scan_ue_iostore_assets
from engines.redengine.cp2077_helper import (
    detect_cp2077,
    inventory_cp2077_mods,
    inspect_cp2077_archive,
    run_wolvenkit_cli,
    scaffold_cp2077_mod,
    patch_cp2077_text_file,
    get_cp2077_ecosystem,
    inspect_cp2077_project,
    get_cp2077_platform_status,
    check_cp2077_mod_compatibility,
    analyze_cp2077_logs,
)
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
        "name": "analyze_binary_crypto",
        "description": "Scan any binary (.dll, .exe, .addon64, .so, assets) to detect all cryptographic algorithms (AES, DES, RC4, TEA/XTEA, Blowfish, MD5, SHA-1, SHA-256, SHA-512, CRC32, Adler32, Base64), Windows Crypto APIs (BCrypt, CryptoAPI), compression (Oodle, Zlib, LZ4, ZSTD), and anti-tamper protections.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to binary file (.dll, .exe, .addon64)."}
            },
            "required": ["binary_path"]
        }
    },
    {
        "name": "deconstruct_binary_project",
        "description": "Deconstruct any native binary into a complete, structured C/C++ project with decompiled feature logic, class headers, anti-tamper neutralization, and CMake/build templates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file (.dll, .exe, .addon64)."},
                "output_dir": {"type": "string", "description": "Output project directory."},
                "max_decompiled_functions": {"type": "integer", "description": "Max functions to decompile (default 50)."}
            },
            "required": ["binary_path", "output_dir"]
        }
    },
    {
        "name": "decompile_entire_binary",
        "description": "Exhaustively decompile 100% of instructions and all registered functions in any native binary (.dll, .exe, .addon64) into full C++ modules, extracted string tables, universal types.h, and a ready-to-build CMake project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file (.dll, .exe, .addon64)."},
                "output_dir": {"type": "string", "description": "Destination directory for the complete C++ project."},
                "chunk_size": {"type": "integer", "description": "Number of functions per translation unit module (default 500)."},
                "domain_cluster": {"type": "boolean", "description": "Cluster decompiled functions into architectural domain modules (core, editor, storage, gui, engine, runtime)."}
            },
            "required": ["binary_path", "output_dir"]
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
        "description": "Scan a game directory to automatically detect its engine (Cyberpunk 2077 REDengine, Unreal Engine 4/5, Unity Mono/IL2CPP, Godot, Valve Source, EA Maxis DBPF).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string", "description": "Path to the target game directory."}
            },
            "required": ["game_dir"]
        }
    },
    {
        "name": "detect_cp2077_install",
        "description": "Inspect a Cyberpunk 2077 installation, archive layout, executable, mod folders, CET, and RED4ext status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string", "description": "Cyberpunk 2077 game root or executable path."}
            },
            "required": ["game_dir"]
        }
    },
    {
        "name": "list_cp2077_mods",
        "description": "Inventory archive, CET, RED4ext, redscript, and TweakXL mods in a Cyberpunk 2077 installation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_dir": {"type": "string", "description": "Cyberpunk 2077 game root."}
            },
            "required": ["game_dir"]
        }
    },
    {
        "name": "inspect_cp2077_archive",
        "description": "Inspect a Cyberpunk 2077 .archive file and report size/header plus available WolvenKit CLI.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "archive_path": {"type": "string", "description": "Path to a .archive file."}
            },
            "required": ["archive_path"]
        }
    },
    {
        "name": "run_wolvenkit_cli",
        "description": "Run WolvenKit.CLI.exe with explicit arguments for archive, CR2W, or asset operations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "arguments": {"type": "array", "items": {"type": "string"}, "description": "CLI arguments (for example: --help)."},
                "wolvenkit_cli": {"type": "string", "description": "Optional explicit WolvenKit.CLI.exe path."}
            },
            "required": ["arguments"]
        }
    },
    {
        "name": "scaffold_cp2077_mod",
        "description": "Create a Cyberpunk 2077 mod scaffold for CET Lua, redscript, TweakXL, or archive mods.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "description": "Parent directory for generated mod."},
                "mod_name": {"type": "string", "description": "Mod name."},
                "mod_type": {"type": "string", "enum": ["cet", "redscript", "tweakxl", "archive"], "description": "Mod format."},
                "description": {"type": "string", "description": "Optional mod description."}
            },
            "required": ["output_dir", "mod_name", "mod_type"]
        }
    },
    {
        "name": "patch_cp2077_text_file",
        "description": "Apply exact text replacements to a Cyberpunk 2077 mod file, with an optional timestamped backup.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Lua, redscript, YAML, JSON, or text mod file."},
                "replacements": {"type": "object", "description": "Exact old-text to new-text mapping.", "additionalProperties": {"type": "string"}},
                "backup": {"type": "boolean", "description": "Create a .bak copy before writing.", "default": True}
            },
            "required": ["file_path", "replacements"]
        }
    },
    {
        "name": "get_cp2077_ecosystem",
        "description": "List supported Cyberpunk 2077 mod libraries and tools, optionally filtered by category or text query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Optional category such as archive_asset_tool, lua_runtime, native_extender, script_compiler, audio_pipeline, model_asset_pipeline."},
                "query": {"type": "string", "description": "Optional substring matched against library metadata."}
            }
        }
    },
    {
        "name": "inspect_cp2077_project",
        "description": "Scan a Cyberpunk 2077 mod project directory and detect WolvenKit, CET, RED4ext, redscript, TweakXL, ArchiveXL, Codeware, Wwise, Blender, and media dependencies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {"type": "string", "description": "Mod project or extracted mod directory."}
            },
            "required": ["project_dir"]
        }
    },
    {
        "name": "get_cp2077_platform_status",
        "description": "Report cross-platform Cyberpunk 2077 tooling availability for Windows, Linux native, .NET, Wine, Blender, FFmpeg, and vgmstream.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "check_cp2077_mod_compatibility",
        "description": "Scan a Cyberpunk 2077 mod project for declared dependencies, framework evidence, missing runtimes, and duplicate deploy paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {"type": "string", "description": "Mod project or extracted mod directory."}
            },
            "required": ["project_dir"]
        }
    },
    {
        "name": "analyze_cp2077_logs",
        "description": "Analyze Cyberpunk 2077, redscript, CET, RED4ext, TweakXL, ArchiveXL, and DLL logs for actionable compatibility findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_path": {"type": "string", "description": "Path to a game or mod log text file."}
            },
            "required": ["log_path"]
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
        "description": "List files inside a UE4/UE5 .pak archive without extracting them. Supports substring filtering and pagination to avoid blowing up context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pak_path": {"type": "string", "description": "Path to the .pak file."},
                "aes_key": {"type": "string", "description": "Optional AES key."},
                "filter_query": {"type": "string", "description": "Optional substring to filter paths (case-insensitive, e.g. '.uasset', 'ZoneTerra', 'Maps')."},
                "limit": {"type": "integer", "description": "Max entries to return (default 100, max 500)."},
                "offset": {"type": "integer", "description": "Starting index for pagination (default 0)."}
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
    # ── World Transfer ───────────────────────────────────────────────────────
    {
        "name": "scan_ue_world_assets",
        "description": "Scan an extracted UE5 directory or a PAK/IoStore archive name for maps, WorldPartition data, landscape, mesh, and material assets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "Directory or archive path to scan."},
                "filter_query": {"type": "string", "description": "Optional location or asset name filter."}
            },
            "required": ["source"]
        }
    },
    {
        "name": "create_stalker_world_export_job",
        "description": "Create a STALKER 2 world-export job manifest from the local game installation. It inventories PAK/IoStore files and checks headless CUE4Parse/UE4SS availability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_root": {"type": "string", "description": "STALKER 2 installation root."},
                "output_dir": {"type": "string", "description": "Directory for the job manifest and exports."}
            },
            "required": ["game_root", "output_dir"]
        }
    },
    {
        "name": "scan_ue_iostore_assets",
        "description": "Index Unreal Engine PAK/IoStore package paths without a GUI using CUE4Parse. Optionally parse one package and list its exports; AES key and .usmap mappings can be supplied through DECOD_CUE4PARSE_AES_KEY and DECOD_CUE4PARSE_USMAP environment variables.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "game_root": {"type": "string", "description": "Game root or its Content/Paks directory."},
                "output_path": {"type": "string", "description": "JSON output path for the package index."},
                "filter_query": {"type": "string", "description": "Optional case-insensitive package-path filter.", "default": ""},
                "max_results": {"type": "integer", "description": "Maximum package paths written to the index.", "default": 2000},
                "game_version": {"type": "string", "description": "CUE4Parse EGame enum name.", "default": "GAME_UE5_5"},
                "probe_asset": {"type": "string", "description": "Optional package path to parse and list exports."},
                "package_type": {"type": "string", "enum": ["all", "maps", "assets"], "description": "Restrict results to .umap maps or .uasset assets.", "default": "all"},
                "extract_dir": {"type": "string", "description": "Optional output directory for the raw package and available .uexp/.ubulk companions."}
            },
            "required": ["game_root", "output_path"]
        }
    },
    {
        "name": "export_heightmap_minecraft",
        "description": "Convert a JSON or CSV height grid into an executable Minecraft mcfunction file. Useful for reproducing an extracted STALKER or Unreal terrain footprint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "heightmap_path": {"type": "string", "description": "JSON or CSV numeric height grid."},
                "output_path": {"type": "string", "description": "Output .mcfunction path."},
                "base_block": {"type": "string", "description": "Block below the surface.", "default": "minecraft:stone"},
                "surface_block": {"type": "string", "description": "Top-surface block.", "default": "minecraft:grass_block"},
                "z_scale": {"type": "integer", "description": "Minecraft Z spacing per source row.", "default": 1},
                "x_origin": {"type": "integer", "default": 0},
                "y_origin": {"type": "integer", "default": 64},
                "z_origin": {"type": "integer", "default": 0},
                "vertical_offset": {"type": "integer", "default": 0},
                "png_height_scale": {"type": "number", "description": "Scale applied only to PNG grayscale heights.", "default": 0.25}
            },
            "required": ["heightmap_path", "output_path"]
        }
    },
    {
        "name": "export_landscape_heightmap_from_probe",
        "description": "Reconstruct a raw UE Landscape uint16 height grid from a CUE4Parse probe report and extracted .ubulk payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "probe_report_path": {"type": "string", "description": "CUE4Parse probe JSON created with --probe and --extract-dir."},
                "output_path": {"type": "string", "description": "Output JSON path for the reconstructed height grid."},
                "bulk_path": {"type": "string", "description": "Optional .ubulk path if it is not listed in the probe report.", "default": ""}
            },
            "required": ["probe_report_path", "output_path"]
        }
    },
    {
        "name": "export_voxel_manifest_minecraft",
        "description": "Convert a JSON voxel manifest with x/y/z and block fields into a Minecraft mcfunction. Supports palette color-to-block mapping.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_path": {"type": "string", "description": "JSON file containing voxels or a voxels array."},
                "output_path": {"type": "string", "description": "Output .mcfunction path."},
                "x_origin": {"type": "integer", "default": 0},
                "y_origin": {"type": "integer", "default": 64},
                "z_origin": {"type": "integer", "default": 0}
            },
            "required": ["manifest_path", "output_path"]
        }
    },
    {
        "name": "export_ue_actor_dump_minecraft",
        "description": "Convert a UE4SS MapEditor world dump into a Minecraft voxel manifest and optional mcfunction. Tree-like actors become approximate vanilla log-and-leaf trees, and other vegetation uses vanilla plant blocks; building geometry still requires mesh export.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dump_path": {"type": "string", "description": "Decod UE4SS stalker_world_dump.json file."},
                "output_path": {"type": "string", "description": "Output .mcfunction path."},
                "x_origin": {"type": "integer", "default": 0},
                "y_origin": {"type": "integer", "default": 64},
                "z_origin": {"type": "integer", "default": 0},
                "uu_per_meter": {"type": "number", "default": 100.0},
                "blocks_per_meter": {"type": "number", "default": 1.0},
                "manifest_only": {"type": "boolean", "default": False}
            },
            "required": ["dump_path", "output_path"]
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

        elif name == "analyze_binary_crypto":
            return CryptoDetector.scan_file(args["binary_path"])

        elif name == "deconstruct_binary_project":
            dec = ProjectDecompiler(args["binary_path"])
            max_fn = args.get("max_decompiled_functions", 50)
            return dec.deconstruct_to_project(args["output_dir"], max_fn)

        elif name == "decompile_entire_binary":
            chunk_size = args.get("chunk_size", 500)
            domain_cluster = args.get("domain_cluster", False)
            return deconstruct_entire_binary(args["binary_path"], args["output_dir"], chunk_size=chunk_size, domain_cluster=domain_cluster)

        elif name == "unpack_jar_package":
            return JavaHelper.unpack_jar(args["jar_path"], args["output_dir"])

        elif name == "read_minecraft_nbt":
            return JavaHelper.parse_minecraft_nbt(args["nbt_path"])

        elif name == "scan_ue_world_assets":
            return WorldConverter.scan_level_assets(
                args["source"],
                args.get("filter_query", ""),
            )

        elif name == "create_stalker_world_export_job":
            return WorldConverter.create_stalker_world_export_job(
                args["game_root"],
                args["output_dir"],
            )

        elif name == "scan_ue_iostore_assets":
            return scan_ue_iostore_assets(
                args["game_root"],
                args["output_path"],
                filter_query=args.get("filter_query", ""),
                max_results=int(args.get("max_results", 2000)),
                game_version=args.get("game_version", "GAME_UE5_5"),
                probe_asset=args.get("probe_asset", ""),
                package_type=args.get("package_type", "all"),
                extract_dir=args.get("extract_dir", ""),
            )

        elif name == "export_heightmap_minecraft":
            return WorldConverter.export_heightmap_mcfunction(
                args["heightmap_path"],
                args["output_path"],
                base_block=args.get("base_block", "minecraft:stone"),
                surface_block=args.get("surface_block", "minecraft:grass_block"),
                z_scale=int(args.get("z_scale", 1)),
                x_origin=int(args.get("x_origin", 0)),
                y_origin=int(args.get("y_origin", 64)),
                z_origin=int(args.get("z_origin", 0)),
                vertical_offset=int(args.get("vertical_offset", 0)),
                png_height_scale=float(args.get("png_height_scale", 0.25)),
            )

        elif name == "export_landscape_heightmap_from_probe":
            return WorldConverter.export_landscape_heightmap_from_probe(
                args["probe_report_path"],
                args["output_path"],
                bulk_path=args.get("bulk_path", ""),
            )

        elif name == "export_voxel_manifest_minecraft":
            return WorldConverter.export_voxel_manifest_mcfunction(
                args["manifest_path"],
                args["output_path"],
                x_origin=int(args.get("x_origin", 0)),
                y_origin=int(args.get("y_origin", 64)),
                z_origin=int(args.get("z_origin", 0)),
            )

        elif name == "export_ue_actor_dump_minecraft":
            return WorldConverter.export_ue_actor_dump_minecraft(
                args["dump_path"],
                args["output_path"],
                x_origin=int(args.get("x_origin", 0)),
                y_origin=int(args.get("y_origin", 64)),
                z_origin=int(args.get("z_origin", 0)),
                uu_per_meter=float(args.get("uu_per_meter", 100.0)),
                blocks_per_meter=float(args.get("blocks_per_meter", 1.0)),
                manifest_only=bool(args.get("manifest_only", False)),
            )

        elif name == "unpack_electron_asar":
            unpacker = AsarUnpacker(args["asar_path"])
            count = unpacker.extract_all(args["output_dir"])
            return {"status": "success", "extracted_files": count, "output_dir": args["output_dir"]}

        elif name == "detect_game_engine":
            return detect_engine(args["game_dir"])

        elif name == "detect_cp2077_install":
            return detect_cp2077(args["game_dir"])

        elif name == "list_cp2077_mods":
            return inventory_cp2077_mods(args["game_dir"])

        elif name == "inspect_cp2077_archive":
            return inspect_cp2077_archive(args["archive_path"])

        elif name == "run_wolvenkit_cli":
            return run_wolvenkit_cli(
                args["arguments"],
                wolvenkit_cli=args.get("wolvenkit_cli", ""),
            )

        elif name == "scaffold_cp2077_mod":
            return scaffold_cp2077_mod(
                args["output_dir"],
                args["mod_name"],
                args["mod_type"],
                args.get("description", ""),
            )

        elif name == "patch_cp2077_text_file":
            return patch_cp2077_text_file(
                args["file_path"],
                args["replacements"],
                backup=bool(args.get("backup", True)),
            )

        elif name == "get_cp2077_ecosystem":
            return get_cp2077_ecosystem(
                category=args.get("category", ""),
                query=args.get("query", ""),
            )

        elif name == "inspect_cp2077_project":
            return inspect_cp2077_project(args["project_dir"])

        elif name == "get_cp2077_platform_status":
            return get_cp2077_platform_status()

        elif name == "check_cp2077_mod_compatibility":
            return check_cp2077_mod_compatibility(args["project_dir"])

        elif name == "analyze_cp2077_logs":
            return analyze_cp2077_logs(args["log_path"])

        elif name == "unpack_ue_pak":
            return ue_helper.unpack_pak(args["pak_path"], args["output_dir"], args.get("aes_key"))

        elif name == "list_ue_pak":
            return ue_helper.list_pak(
                args["pak_path"],
                aes_key=args.get("aes_key"),
                filter_query=args.get("filter_query"),
                limit=min(int(args.get("limit", 100)), 500),
                offset=int(args.get("offset", 0))
            )

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

MAX_TOOL_OUTPUT_CHARS = 16000

def truncate_tool_output(output_str: str, max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Truncate tool output if it exceeds max_chars to prevent context window explosion."""
    if len(output_str) <= max_chars:
        return output_str
    omitted = len(output_str) - max_chars
    return (
        output_str[:max_chars]
        + f"\n\n... [OUTPUT TRUNCATED: {omitted} characters (~{omitted // 4} tokens) omitted by Decod MCP to prevent context overflow. Refine query, add filters, or paginate to view more.] ..."
    )

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
                                "text": truncate_tool_output(json.dumps(res, indent=2))
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
