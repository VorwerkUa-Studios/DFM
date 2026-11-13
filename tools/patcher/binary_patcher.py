"""
Decod Binary Patcher & Hex Modifier:
Safely patches binary files (EXE, DLL, SO) with byte sequences, NOPs, and jumps.
Includes automatic backup (.bak) creation, validation, and restore capabilities.
"""

import os
import sys
import shutil
from typing import Dict, Any, List

class BinaryPatcher:
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        self.file_path = os.path.abspath(file_path)

    def create_backup(self) -> str:
        bak_path = self.file_path + ".bak"
        if not os.path.exists(bak_path):
            shutil.copy2(self.file_path, bak_path)
        return bak_path

    def patch_bytes(self, offset: int | str, new_bytes_hex: str, backup: bool = True) -> Dict[str, Any]:
        """Patch binary at a specific file offset with hex bytes (e.g. '90 90 90' or 'EB 10')."""
        if isinstance(offset, str):
            offset = int(offset, 16) if offset.startswith("0x") else int(offset)

        clean_hex = new_bytes_hex.replace(" ", "").replace("-", "")
        patch_data = bytes.fromhex(clean_hex)

        file_size = os.path.getsize(self.file_path)
        if offset + len(patch_data) > file_size:
            raise ValueError(f"Patch overflow: offset {hex(offset)} + {len(patch_data)} exceeds file size {hex(file_size)}")

        bak_file = None
        if backup:
            bak_file = self.create_backup()

        # Read original bytes before patching
        with open(self.file_path, "r+b") as f:
            f.seek(offset, os.SEEK_SET)
            original_bytes = f.read(len(patch_data))

            f.seek(offset, os.SEEK_SET)
            f.write(patch_data)

        return {
            "status": "success",
            "file": self.file_path,
            "offset": hex(offset),
            "original_bytes": original_bytes.hex(" ").upper(),
            "patched_bytes": patch_data.hex(" ").upper(),
            "bytes_modified": len(patch_data),
            "backup_file": bak_file
        }

    def restore_backup(self) -> Dict[str, Any]:
        """Restore file from .bak backup."""
        bak_path = self.file_path + ".bak"
        if not os.path.exists(bak_path):
            raise FileNotFoundError(f"No backup file found at: {bak_path}")

        shutil.copy2(bak_path, self.file_path)
        return {"status": "restored", "file": self.file_path}

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python binary_patcher.py <file> <offset_hex> '<new_hex_bytes>'")
        sys.exit(1)

    patcher = BinaryPatcher(sys.argv[1])
    res = patcher.patch_bytes(sys.argv[2], sys.argv[3])
    import json
    print(json.dumps(res, indent=2))
