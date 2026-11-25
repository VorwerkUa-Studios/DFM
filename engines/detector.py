"""
Universal Game Engine Detector:
Scans a game directory and identifies the engine, architecture, runtime type, and key asset paths.
"""

import os
import glob
from typing import Dict, Any

def detect_engine(game_dir: str) -> Dict[str, Any]:
    if not os.path.exists(game_dir):
        raise FileNotFoundError(f"Directory not found: {game_dir}")

    result = {
        "engine": "unknown",
        "flavor": None,
        "executable": None,
        "main_assets": [],
        "architecture": "unknown",
        "description": "Unrecognized or custom engine"
    }

    # Find executables in root or first subfolder
    exes = glob.glob(os.path.join(game_dir, "*.exe")) + glob.glob(os.path.join(game_dir, "*", "*.exe"))
    if exes:
        result["executable"] = os.path.abspath(exes[0])

    # Cyberpunk 2077 / REDengine 4
    cyberpunk_exe = (
        glob.glob(os.path.join(game_dir, "Cyberpunk2077.exe"))
        + glob.glob(os.path.join(game_dir, "bin", "x64", "Cyberpunk2077.exe"))
        + glob.glob(os.path.join(game_dir, "bin", "x64", "*Cyberpunk*2077*.exe"))
    )
    red_archive_dirs = glob.glob(os.path.join(game_dir, "**", "*.archive"), recursive=True)
    red_archive_root = glob.glob(os.path.join(game_dir, "archive", "pc", "content", "*.archive"))
    if cyberpunk_exe or red_archive_root or (
        red_archive_dirs
        and (
            os.path.isdir(os.path.join(game_dir, "r6"))
            or os.path.isdir(os.path.join(game_dir, "engine"))
            or os.path.isdir(os.path.join(game_dir, "bin"))
        )
    ):
        result["engine"] = "redengine"
        result["flavor"] = "REDengine 4 (Cyberpunk 2077)"
        result["executable"] = os.path.abspath(cyberpunk_exe[0]) if cyberpunk_exe else None
        result["main_assets"] = red_archive_dirs[:20]
        result["description"] = "Cyberpunk 2077 REDengine 4 archive/modding installation."
        return result

    # 1. Check for Unreal Engine (UE4 / UE5)
    pak_files = glob.glob(os.path.join(game_dir, "**", "*.pak"), recursive=True)
    utoc_files = glob.glob(os.path.join(game_dir, "**", "*.utoc"), recursive=True)
    if utoc_files:
        result["engine"] = "unreal_engine"
        result["flavor"] = "UE5 (IoStore)"
        result["main_assets"] = utoc_files[:10]
        result["description"] = "Unreal Engine 5 with IoStore container (.utoc/.ucas) format."
        return result
    elif pak_files:
        result["engine"] = "unreal_engine"
        result["flavor"] = "UE4/UE5 (Standard Pak)"
        result["main_assets"] = pak_files[:10]
        result["description"] = "Unreal Engine using standard .pak container files."
        return result

    # 2. Check for Unity Engine
    unity_player = glob.glob(os.path.join(game_dir, "UnityPlayer.dll")) or glob.glob(os.path.join(game_dir, "UnityCrashHandler*.exe"))
    managed_dir = glob.glob(os.path.join(game_dir, "*_Data", "Managed"))
    il2cpp_metadata = glob.glob(os.path.join(game_dir, "*_Data", "il2cpp_data", "Metadata", "global-metadata.dat"))

    if unity_player or managed_dir or il2cpp_metadata:
        result["engine"] = "unity"
        if il2cpp_metadata or glob.glob(os.path.join(game_dir, "GameAssembly.dll")):
            result["flavor"] = "Unity IL2CPP"
            result["description"] = "Unity compiled to native C++ machine code (IL2CPP). Needs Il2CppDumper."
            if il2cpp_metadata:
                result["main_assets"] = [il2cpp_metadata[0]]
        else:
            result["flavor"] = "Unity Mono (.NET)"
            result["description"] = "Classic Unity with C# bytecode in Assembly-CSharp.dll. Full decompile possible!"
            csharp_dll = glob.glob(os.path.join(game_dir, "*_Data", "Managed", "Assembly-CSharp.dll"))
            if csharp_dll:
                result["main_assets"] = [csharp_dll[0]]
        return result

    # 3. Check for Godot Engine
    pck_files = glob.glob(os.path.join(game_dir, "*.pck")) + glob.glob(os.path.join(game_dir, "*", "*.pck"))
    if pck_files:
        result["engine"] = "godot"
        result["flavor"] = "Godot PCK"
        result["main_assets"] = pck_files
        result["description"] = "Godot Engine package archive (.pck) containing GDScript and game scenes."
        return result

    # 4. Check for Valve Source / GoldSrc
    vpk_files = glob.glob(os.path.join(game_dir, "**", "*.vpk"), recursive=True)
    if vpk_files or glob.glob(os.path.join(game_dir, "hl2.exe")):
        result["engine"] = "valve_source"
        result["flavor"] = "Source Engine"
        result["main_assets"] = vpk_files[:10]
        result["description"] = "Valve Source Engine with .vpk (Valve Pak) archives."
        return result

    # 5. Check for Maxis / DBPF (Spore, The Sims)
    package_files = glob.glob(os.path.join(game_dir, "**", "*.package"), recursive=True)
    if package_files or glob.glob(os.path.join(game_dir, "**", "SporeApp.exe"), recursive=True):
        result["engine"] = "ea_maxis"
        result["flavor"] = "DBPF (Spore / The Sims)"
        result["main_assets"] = package_files[:10]
        result["description"] = "EA Maxis DBPF archive format (Spore, The Sims 2/3/4)."
        return result

    return result

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(detect_engine(path))
