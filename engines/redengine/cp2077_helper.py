import json
import os
import shutil
import subprocess
import sys
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional


ECOSYSTEM_PATH = Path(__file__).with_name("ecosystem.json")


def get_cp2077_ecosystem(category: str = "", query: str = "") -> Dict:
    data = json.loads(ECOSYSTEM_PATH.read_text(encoding="utf-8"))
    libraries = data["libraries"]
    category = category.strip().lower()
    query = query.strip().lower()
    if category:
        libraries = [item for item in libraries if item["category"].lower() == category]
    if query:
        libraries = [
            item for item in libraries
            if query in json.dumps(item, ensure_ascii=False).lower()
        ]
    return {
        "status": "ok",
        "count": len(libraries),
        "category": category or None,
        "query": query or None,
        "libraries": libraries,
    }


def inspect_cp2077_project(project_dir: str) -> Dict:
    root = Path(project_dir).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Mod project not found: {root}")

    catalog = json.loads(ECOSYSTEM_PATH.read_text(encoding="utf-8"))["libraries"]
    files = [path for path in root.rglob("*") if path.is_file()]
    detected = []
    evidence = {}

    checks = {
        "wolvenkit": [".archive", ".cr2w", ".cpmodproj", ".xl", ".inkatlas", ".inkwidget", ".mesh", ".xbm"],
        "cyber-engine-tweaks": [".lua"],
        "red4ext": [".dll", "CMakeLists.txt", "RED4ext"],
        "redscript": [".reds", "r6/scripts"],
        "tweakxl": [".yaml", ".yml", "r6/tweaks"],
        "archivexl": [".xl", ".archive", "ArchiveXL"],
        "codeware": [".reds", "Codeware"],
        "mod-settings": ["ModSettings", "mod_settings"],
        "cyberpunk-blender": [".blend", ".fbx", ".gltf", ".glb"],
        "wwise": [".wem", ".bnk", ".pck"],
        "ffmpeg": [".mp4", ".webm", ".mkv", ".mp3", ".flac"],
        "audioweaver": [".wem", ".bnk", ".wem.xml", "audioweaver", "Audio Weaver"],
        "ink": [".inkatlas", ".inkwidget", ".inkanim"],
        "cet-kit": [".lua", "CET Kit", "cet-kit"],
        "equipment-ex": ["equipment-ex", "equipment ex", "equipmentex"],
        "redmod": ["mod/info.json", "r6/scripts", "archive/pc/mod"],
    }

    for library_id, needles in checks.items():
        matches = []
        for path in files:
            lower_path = str(path).lower()
            lower_name = path.name.lower()
            for needle in needles:
                needle_lower = needle.lower()
                if (needle_lower.startswith(".") and lower_name.endswith(needle_lower)) or (
                    not needle_lower.startswith(".") and needle_lower in lower_path
                ):
                    matches.append(str(path.resolve()))
                    break
        if matches:
            evidence[library_id] = sorted(set(matches))[:100]

    for item in catalog:
        item_id = item["id"]
        if item_id in evidence:
            detected.append(item)

    if evidence:
        key_text = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")[:10000]
            for path in files
            if path.suffix.lower() in {".lua", ".reds", ".yaml", ".yml", ".json", ".xml", ".txt", ".toml", ".cpp", ".h"}
        ).lower()
        for item in catalog:
            item_id = item["id"]
            if item_id not in evidence:
                if item_id == "codeware" and "codeware" in key_text:
                    evidence[item_id] = []
                    detected.append(item)
                elif item_id == "mod-settings" and ("mod_settings" in key_text or "modsettings" in key_text):
                    evidence[item_id] = []
                    detected.append(item)

    return {
        "status": "ok",
        "project": str(root),
        "file_count": len(files),
        "detected_count": len(detected),
        "detected": detected,
        "evidence": evidence,
        "missing_tool_warning": "Install only the libraries and runtimes required by the detected project format.",
    }


def check_cp2077_mod_compatibility(project_dir: str) -> Dict:
    root = Path(project_dir).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Mod project not found: {root}")

    inspection = inspect_cp2077_project(str(root))
    detected_ids = {item["id"] for item in inspection["detected"]}
    issues = []
    warnings = []

    dependency_names = {
        "cyber-engine-tweaks": re.compile(r"(?i)\b(?:CET|Cyber Engine Tweaks)\b"),
        "red4ext": re.compile(r"(?i)\b(?:RED4ext|RED4ext\.SDK)\b"),
        "redscript": re.compile(r"(?i)\bredscript\b"),
        "tweakxl": re.compile(r"(?i)\bTweakXL\b"),
        "archivexl": re.compile(r"(?i)\bArchiveXL\b"),
        "codeware": re.compile(r"(?i)\bCodeware\b"),
        "equipment-ex": re.compile(r"(?i)\bEquipment[- ]EX\b"),
        "mod-settings": re.compile(r"(?i)\b(?:Mod Settings|ModSettings|mod_settings)\b"),
        "cet-kit": re.compile(r"(?i)\bCET Kit\b"),
    }

    manifests = [
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".json", ".toml", ".yaml", ".yml", ".txt"}
    ]
    manifest_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")[:20000]
        for path in manifests
    )

    declared_dependencies = set()
    for library_id, pattern in dependency_names.items():
        if pattern.search(manifest_text):
            declared_dependencies.add(library_id)

    missing = sorted(declared_dependencies - detected_ids)
    for library_id in missing:
        issues.append({
            "severity": "error",
            "code": "missing_dependency",
            "dependency": library_id,
            "message": f"The project declares or references {library_id}, but no matching installed framework project evidence was found.",
        })

    conflicts = []
    path_groups = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix().lower()
        path_groups.setdefault(rel, []).append(str(path.resolve()))
    for rel, paths in path_groups.items():
        if len(paths) > 1:
            conflicts.append({"path": rel, "sources": paths})

    return {
        "status": "ok",
        "project": str(root),
        "detected": sorted(detected_ids),
        "declared_dependencies": sorted(declared_dependencies),
        "missing_dependencies": sorted(missing),
        "issues": issues,
        "warnings": warnings,
        "duplicate_relative_paths": conflicts,
        "safe_to_deploy": not issues,
    }


def analyze_cp2077_logs(log_path: str) -> Dict:
    path = Path(log_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    text = path.read_text(encoding="utf-8", errors="ignore")
    rules = [
        ("redscript_compile_failed", r"(?i)redscript.{0,80}(?:compile|failed)|compilation failed", "REDscript compilation failed; inspect syntax, game patch compatibility, and stale script cache."),
        ("cet_missing", r"(?i)(?:cyber_engine_tweaks|cyber engine tweaks).{0,80}(?:missing|not found|load failed)", "CET runtime or one of its modules could not be loaded."),
        ("red4ext_missing", r"(?i)(?:red4ext|version\.dll).{0,80}(?:missing|not found|load failed)", "RED4ext runtime or version.dll is missing or incompatible."),
        ("tweakxl_error", r"(?i)tweakxl.{0,120}(?:error|failed|invalid)", "TweakXL encountered a YAML/TweakDB or dependency error."),
        ("archivexl_error", r"(?i)archivexl.{0,120}(?:error|failed|invalid|conflict)", "ArchiveXL encountered an asset/resource conflict or invalid definition."),
        ("codeware_error", r"(?i)codeware.{0,120}(?:error|failed|missing)", "Codeware is missing or one of its APIs is incompatible."),
        ("dll_load_error", r"(?i)(?:0x[c]?000007b|bad image|dll.{0,40}load|load.{0,40}dll)", "A native DLL could not load; check architecture, dependencies, and Wine/Windows runtime."),
        ("archive_error", r"(?i)(?:archivexl|archive).{0,120}(?:missing|invalid|failed|corrupt)", "Archive/resource loading failed; verify archive placement and WolvenKit build compatibility."),
    ]

    findings = []
    lower_text = text.lower()
    for code, pattern, recommendation in rules:
        matches = re.findall(pattern, text)
        if matches:
            snippet = text[max(0, lower_text.find(matches[0].lower()) - 120):lower_text.find(matches[0].lower()) + 300] if isinstance(matches[0], str) else ""
            findings.append({
                "code": code,
                "severity": "error",
                "count": len(matches),
                "recommendation": recommendation,
                "snippet": snippet.replace("\r", "")[:420],
            })

    return {
        "status": "ok",
        "log": str(path),
        "size_bytes": path.stat().st_size,
        "finding_count": len(findings),
        "findings": findings,
    }


def _resolve_game_root(path: str) -> Path:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Cyberpunk 2077 path not found: {root}")
    if root.is_file():
        root = root.parent
        if root.name.lower() == "x64" and root.parent.name.lower() == "bin":
            root = root.parent.parent
    return root


def find_wolvenkit_cli(explicit_path: str = "") -> Optional[Path]:
    candidates = []
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())
    env_path = os.environ.get("DECOD_WOLVENKIT_CLI", "")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    base = Path(__file__).resolve().parents[2]
    candidates.extend([
        base / "bin" / "WolvenKit.CLI.exe",
        base / "bin" / "WolvenKit.CLI",
        base / "bin" / "WolvenKit.CLI.dll",
        base / "components" / "WolvenKit" / "WolvenKit.CLI.exe",
        base / "components" / "WolvenKit" / "WolvenKit.CLI",
        base / "components" / "WolvenKit" / "WolvenKit.CLI.dll",
        base / "components" / "WolvenKitCLI" / "WolvenKit.CLI.exe",
        base / "components" / "WolvenKitCLI" / "WolvenKit.CLI",
        base / "components" / "WolvenKitCLI" / "WolvenKit.CLI.dll",
    ])

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
        found = shutil.which(str(candidate))
        if found:
            return Path(found).resolve()
    return None


def get_cp2077_platform_status() -> Dict:
    wolvenkit = find_wolvenkit_cli()
    dotnet = shutil.which("dotnet")
    wine = shutil.which("wine")
    blender = shutil.which("blender")
    ffmpeg = shutil.which("ffmpeg")
    ffprobe = shutil.which("ffprobe")
    vgmstream = shutil.which("vgmstream-cli") or shutil.which("vgmstream")

    return {
        "status": "ok",
        "host": os.getenv("WINEARCH") if wine and os.name != "nt" else None,
        "platform": "windows" if os.name == "nt" else "linux",
        "python": sys.version.split()[0],
        "tools": {
            "wolvenkit_cli": str(wolvenkit) if wolvenkit else None,
            "wolvenkit_cli_ready": bool(wolvenkit),
            "dotnet": dotnet,
            "wine": wine,
            "blender": blender,
            "ffmpeg": ffmpeg,
            "ffprobe": ffprobe,
            "vgmstream": vgmstream,
        },
        "profiles": {
            "native_text": ["redscript source", "TweakXL YAML", "ArchiveXL YAML", "CET Lua", "JSON", "XML"],
            "native_media": ["FFmpeg", "ffprobe", "vgmstream-cli"],
            "native_archive": ["WolvenKit CLI under .NET", "WolvenKit CLI under Wine"] ,
            "native_model": ["Blender CLI/add-on"],
            "wine_required": ["Cyber Engine Tweaks", "RED4ext", "game runtime", "Windows Wwise authoring"],
        },
    }


def detect_cp2077(game_dir: str) -> Dict:
    root = _resolve_game_root(game_dir)
    archives = sorted(root.glob("archive/**/*.archive"))
    executable = root / "bin" / "x64" / "Cyberpunk2077.exe"
    if not executable.exists():
        executable = next(root.glob("**/Cyberpunk2077.exe"), None)

    mod_dirs = []
    for relative in ("archive/pc/mod", "archive/pc/hotfix", "r6/scripts", "r6/tweaks", "engine/config"):
        candidate = root / relative
        if candidate.exists():
            mod_dirs.append(str(candidate.resolve()))

    cet_dir = root / "bin" / "x64" / "plugins" / "cyber_engine_tweaks"
    red4ext_dir = root / "bin" / "x64" / "plugins"
    return {
        "status": "ok",
        "engine": "redengine",
        "game": "Cyberpunk 2077",
        "game_root": str(root),
        "executable": str(executable.resolve()) if executable and executable.exists() else None,
        "archive_count": len(archives),
        "archives": [str(path.resolve()) for path in archives[:100]],
        "mod_dirs": mod_dirs,
        "cyber_engine_tweaks": {
            "installed": (root / "bin" / "x64" / "cyber_engine_tweaks.dll").exists(),
            "mods_dir": str(cet_dir / "mods"),
        },
        "red4ext": {
            "installed": (root / "bin" / "x64" / "version.dll").exists(),
            "plugins_dir": str(red4ext_dir),
        },
    }


def inventory_cp2077_mods(game_dir: str) -> Dict:
    root = _resolve_game_root(game_dir)
    inventory = []
    locations = [
        ("archive", root / "archive" / "pc" / "mod"),
        ("cet", root / "bin" / "x64" / "plugins" / "cyber_engine_tweaks" / "mods"),
        ("red4ext", root / "bin" / "x64" / "plugins"),
        ("redscript", root / "r6" / "scripts"),
        ("tweakxl", root / "r6" / "tweaks"),
    ]
    for kind, directory in locations:
        if not directory.exists():
            continue
        for path in sorted(directory.iterdir()):
            if kind == "red4ext" and path.name.lower() in {"cyber_engine_tweaks"}:
                continue
            inventory.append({
                "type": kind,
                "name": path.name,
                "path": str(path.resolve()),
                "directory": path.is_dir(),
            })
    return {"status": "ok", "game_root": str(root), "count": len(inventory), "mods": inventory}


def inspect_cp2077_archive(archive_path: str) -> Dict:
    path = Path(archive_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Archive not found: {path}")
    if path.suffix.lower() != ".archive":
        raise ValueError("cp2077_inspect_archive expects a .archive file")
    cli = find_wolvenkit_cli()
    return {
        "status": "ok",
        "archive": str(path),
        "size_bytes": path.stat().st_size,
        "header_hex": path.read_bytes()[:32].hex(" "),
        "wolvenkit_cli": str(cli) if cli else None,
        "note": "Use run_wolvenkit_cli for listing/extraction; Decod performs no blind archive parsing.",
    }


def run_wolvenkit_cli(arguments: Iterable[str], wolvenkit_cli: str = "") -> Dict:
    cli = find_wolvenkit_cli(wolvenkit_cli)
    if not cli:
        return {
            "status": "error",
            "error": "WolvenKit CLI not found",
            "hint": "Set DECOD_WOLVENKIT_CLI or pass wolvenkit_cli.",
        }
    dotnet = shutil.which("dotnet")
    wine = shutil.which("wine")
    suffix = cli.suffix.lower()

    if suffix == ".dll" and dotnet:
        command = [dotnet, str(cli), *[str(arg) for arg in arguments]]
    elif suffix == ".dll" and not dotnet:
        return {
            "status": "error",
            "error": "WolvenKit CLI is a .NET assembly, but dotnet is not available",
            "hint": "Install .NET 8 or newer and ensure 'dotnet' is on PATH.",
        }
    elif os.name != "nt" and suffix == ".exe" and wine:
        command = [wine, str(cli), *[str(arg) for arg in arguments]]
    elif os.name != "nt" and suffix == ".exe" and not wine:
        return {
            "status": "error",
            "error": "WolvenKit CLI is a Windows executable, but Wine is not available",
            "hint": "Install Wine/Proton-compatible runtime or place a cross-platform WolvenKit.CLI.dll and configure DECOD_WOLVENKIT_CLI.",
        }
    else:
        command = [str(cli), *[str(arg) for arg in arguments]]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": command}
    return {
        "status": "success" if completed.returncode == 0 else "error",
        "exit_code": completed.returncode,
        "command": command,
        "stdout": completed.stdout[-16000:],
        "stderr": completed.stderr[-16000:],
    }


def scaffold_cp2077_mod(output_dir: str, mod_name: str, mod_type: str, description: str = "") -> Dict:
    if not mod_name.strip():
        raise ValueError("mod_name must not be empty")
    safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in mod_name.strip())
    output = Path(output_dir).expanduser().resolve() / safe_name
    output.mkdir(parents=True, exist_ok=True)
    mod_type = mod_type.lower()
    created = []

    if mod_type == "cet":
        init_lua = output / "init.lua"
        init_lua.write_text(
            "-- Decod CET mod scaffold\n"
            "registerForEvent(\"onInit\", function()\n"
            f"    print(\"[{mod_name}] initialized\")\n"
            "end)\n",
            encoding="utf-8",
        )
        created.append(str(init_lua))
    elif mod_type == "redscript":
        scripts_dir = output / "r6" / "scripts" / safe_name
        scripts_dir.mkdir(parents=True, exist_ok=True)
        script = scripts_dir / "Main.reds"
        script.write_text(
            "// Decod redscript scaffold\n"
            "public class DecodMod {\n"
            "    public static func Init() -> Void {}\n"
            "}\n",
            encoding="utf-8",
        )
        created.append(str(script))
    elif mod_type == "tweakxl":
        yaml_dir = output / "r6" / "tweaks"
        yaml_dir.mkdir(parents=True, exist_ok=True)
        yaml = yaml_dir / f"{safe_name}.yaml"
        yaml.write_text(f"# Decod TweakXL scaffold: {mod_name}\n# Add TweakDB record overrides here.\n", encoding="utf-8")
        created.append(str(yaml))
    elif mod_type == "archive":
        content_dir = output / "archive" / "pc" / "mod"
        content_dir.mkdir(parents=True, exist_ok=True)
        created.append(str(content_dir))
    else:
        raise ValueError("mod_type must be one of: cet, redscript, tweakxl, archive")

    manifest = {
        "name": mod_name,
        "type": mod_type,
        "description": description,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_files": created,
    }
    manifest_path = output / "decod_mod.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    created.append(str(manifest_path))
    return {"status": "ok", "output_dir": str(output), "type": mod_type, "created": created}


def patch_cp2077_text_file(file_path: str, replacements: Dict[str, str], backup: bool = True) -> Dict:
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Mod file not found: {path}")
    original = path.read_text(encoding="utf-8")
    updated = original
    changes = []
    for old_text, new_text in replacements.items():
        count = updated.count(old_text)
        if count:
            updated = updated.replace(old_text, new_text)
            changes.append({"old": old_text[:200], "new": new_text[:200], "replacements": count})
    backup_path = None
    if updated != original:
        if backup:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_path = Path(f"{path}.decod-{timestamp}.bak")
            shutil.copy2(path, backup_path)
        path.write_text(updated, encoding="utf-8")
    return {
        "status": "ok",
        "file": str(path),
        "changed": updated != original,
        "backup": str(backup_path) if backup_path else None,
        "changes": changes,
    }
