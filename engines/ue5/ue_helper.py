"""
Decod UE5 Helper:
Unreal Engine 4/5 & S.T.A.L.K.E.R. 2 archive manager and tool runner.
Automates repak (Rust), uesave (Rust), and asset inspection.
"""

import os
import subprocess
import json
from typing import Dict, Any, List

BIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bin")
DEFAULT_REPAK = os.path.join(BIN_DIR, "repak.exe") if os.name == "nt" else os.path.join(BIN_DIR, "repak")
DEFAULT_UESAVE = os.path.join(BIN_DIR, "uesave.exe") if os.name == "nt" else os.path.join(BIN_DIR, "uesave")

class UEHelper:
    def __init__(self, repak_bin: str = None, uesave_bin: str = None):
        self.repak_bin = repak_bin or (DEFAULT_REPAK if os.path.exists(DEFAULT_REPAK) else "repak")
        self.uesave_bin = uesave_bin or (DEFAULT_UESAVE if os.path.exists(DEFAULT_UESAVE) else "uesave")

    def unpack_pak(self, pak_path: str, output_dir: str, aes_key: str = None) -> Dict[str, Any]:
        """Unpack UE .pak or IoStore archive via repak."""
        if not os.path.exists(pak_path):
            raise FileNotFoundError(f"PAK archive not found: {pak_path}")

        cmd = [self.repak_bin, "unpack", pak_path, "-O", output_dir]
        if aes_key:
            cmd.extend(["--aes-key", aes_key])

        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_dir": output_dir
        }

    def pack_pak(self, input_dir: str, output_pak: str, version: str = "V11") -> Dict[str, Any]:
        """Pack directory into a .pak archive."""
        if not os.path.exists(input_dir):
            raise FileNotFoundError(f"Input directory not found: {input_dir}")

        cmd = [self.repak_bin, "pack", input_dir, output_pak, "--version", version]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_pak": output_pak
        }

    def list_pak(self, pak_path: str, aes_key: str = None) -> Dict[str, Any]:
        """List files inside a UE .pak archive without unpacking."""
        if not os.path.exists(pak_path):
            raise FileNotFoundError(f"PAK archive not found: {pak_path}")

        cmd = [self.repak_bin, "list", pak_path]
        if aes_key:
            cmd.extend(["--aes-key", aes_key])

        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    def convert_save_to_json(self, sav_path: str, json_out_path: str) -> Dict[str, Any]:
        """Convert Unreal .sav file to JSON via uesave."""
        if not os.path.exists(sav_path):
            raise FileNotFoundError(f"Save file not found: {sav_path}")

        cmd = [self.uesave_bin, "to-json", "-i", sav_path, "-o", json_out_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_json": json_out_path
        }

    def convert_json_to_save(self, json_in_path: str, sav_out_path: str) -> Dict[str, Any]:
        """Convert modified JSON back to Unreal .sav file via uesave."""
        if not os.path.exists(json_in_path):
            raise FileNotFoundError(f"JSON file not found: {json_in_path}")

        cmd = [self.uesave_bin, "from-json", "-i", json_in_path, "-o", sav_out_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_sav": sav_out_path
        }

if __name__ == "__main__":
    helper = UEHelper()
    print(f"[*] Repak binary: {helper.repak_bin} (exists: {os.path.exists(helper.repak_bin)})")
    print(f"[*] UESave binary: {helper.uesave_bin} (exists: {os.path.exists(helper.uesave_bin)})")
