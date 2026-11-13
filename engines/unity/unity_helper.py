"""
Unity Engine Inspector & Tool Helper:
Analyzes Unity games, detects runtime backend (Mono C# vs. IL2CPP native C++),
locates game assemblies, and prepares decompiler pipelines.
"""

import os
import glob
import json
from typing import Dict, Any, List

class UnityHelper:
    def __init__(self, game_dir: str):
        self.game_dir = os.path.abspath(game_dir)
        self.backend = "unknown"
        self.metadata_path = None
        self.assembly_path = None
        self.analyze()

    def analyze(self):
        # Look for IL2CPP metadata
        il2cpp_meta = glob.glob(os.path.join(self.game_dir, "**", "global-metadata.dat"), recursive=True)
        game_assembly = glob.glob(os.path.join(self.game_dir, "**", "GameAssembly.dll"), recursive=True) or \
                        glob.glob(os.path.join(self.game_dir, "**", "libil2cpp.so"), recursive=True)

        if il2cpp_meta and game_assembly:
            self.backend = "IL2CPP"
            self.metadata_path = il2cpp_meta[0]
            self.assembly_path = game_assembly[0]
            return

        # Look for Mono Managed assemblies
        mono_csharp = glob.glob(os.path.join(self.game_dir, "**", "Assembly-CSharp.dll"), recursive=True)
        if mono_csharp:
            self.backend = "Mono"
            self.assembly_path = mono_csharp[0]
            return

        # Fallback check
        if glob.glob(os.path.join(self.game_dir, "**", "UnityPlayer.dll"), recursive=True):
            self.backend = "Unity (Unconfirmed backend)"

    def get_info(self) -> Dict[str, Any]:
        info = {
            "game_dir": self.game_dir,
            "backend": self.backend,
            "can_decompile_full_source": self.backend == "Mono",
            "assembly_path": self.assembly_path,
            "metadata_path": self.metadata_path
        }
        if self.backend == "Mono":
            info["recommended_action"] = "Use ilspycmd or dnSpy on Assembly-CSharp.dll to recover full C# source code."
        elif self.backend == "IL2CPP":
            info["recommended_action"] = "Use Il2CppDumper with GameAssembly and global-metadata.dat to restore symbol names."
        else:
            info["recommended_action"] = "Scan for Unity asset files or investigate root binaries."

        return info

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    helper = UnityHelper(target)
    print(json.dumps(helper.get_info(), indent=2))
