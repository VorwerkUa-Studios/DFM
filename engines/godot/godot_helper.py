"""
Godot Engine PCK Archive Reader & Unpacker:
Extracts scenes, GDScript files, textures, and assets from Godot .pck packages (Godot 3.x & 4.x).
Pure Python implementation with no external binaries required.
"""

import os
import struct
import json
from typing import List, Dict, Any

GDPC_MAGIC = b"GDPC"

class GodotPCKEntry:
    def __init__(self, path: str, offset: int, size: int):
        self.path = path.replace("res://", "")
        self.offset = offset
        self.size = size

class GodotPCK:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.entries: List[GodotPCKEntry] = []
        self.version = 0
        self.godot_version = (0, 0, 0)
        self.parse()

    def parse(self):
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCK file not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            magic = f.read(4)
            if magic != GDPC_MAGIC:
                # Some Godot executables have PCK embedded at the end
                f.seek(-4, os.SEEK_END)
                end_magic = f.read(4)
                if end_magic == GDPC_MAGIC:
                    f.seek(-12, os.SEEK_END)
                    pck_offset = struct.unpack("<Q", f.read(8))[0]
                    f.seek(pck_offset, os.SEEK_SET)
                    magic = f.read(4)
                else:
                    raise ValueError(f"Invalid Godot PCK magic: {magic}. Expected b'GDPC'.")

            self.version = struct.unpack("<I", f.read(4))[0]
            major, minor, patch = struct.unpack("<III", f.read(12))
            self.godot_version = (major, minor, patch)

            # Skip reserved / flags depending on PCK version
            if self.version >= 2:
                # Godot 4.x PCK format
                flags = struct.unpack("<I", f.read(4))[0]
                file_base = struct.unpack("<Q", f.read(8))[0]
                f.seek(64, os.SEEK_CUR)  # reserved
            else:
                # Godot 3.x PCK format
                file_base = 0
                f.seek(64, os.SEEK_CUR)  # 16 ints reserved

            file_count = struct.unpack("<I", f.read(4))[0]

            for _ in range(file_count):
                path_len = struct.unpack("<I", f.read(4))[0]
                # Pad to multiple of 4
                raw_path = f.read(path_len)
                pad = (4 - (path_len % 4)) % 4
                f.seek(pad, os.SEEK_CUR)

                path_str = raw_path.decode("utf-8", errors="replace").rstrip("\x00")
                offset, size = struct.unpack("<QQ", f.read(16))
                f.seek(16, os.SEEK_CUR)  # skip 16 bytes md5

                if self.version >= 2:
                    f.seek(4, os.SEEK_CUR)  # skip flags

                self.entries.append(GodotPCKEntry(
                    path=path_str,
                    offset=offset + file_base,
                    size=size
                ))

    def list_files(self) -> List[Dict[str, Any]]:
        return [{"path": e.path, "offset": e.offset, "size": e.size} for e in self.entries]

    def extract_all(self, output_dir: str) -> int:
        os.makedirs(output_dir, exist_ok=True)
        with open(self.filepath, "rb") as f:
            for entry in self.entries:
                out_path = os.path.join(output_dir, entry.path.lstrip("/\\"))
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                f.seek(entry.offset, os.SEEK_SET)
                data = f.read(entry.size)
                with open(out_path, "wb") as out_f:
                    out_f.write(data)

        return len(self.entries)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python godot_helper.py <game.pck> [output_dir]")
        sys.exit(1)

    pck = GodotPCK(sys.argv[1])
    print(f"[*] Godot Version: {pck.godot_version[0]}.{pck.godot_version[1]}.{pck.godot_version[2]}")
    print(f"[*] Found {len(pck.entries)} files in PCK.")

    if len(sys.argv) >= 3:
        out_dir = sys.argv[2]
        extracted = pck.extract_all(out_dir)
        print(f"[+] Extracted {extracted} files into '{out_dir}'.")
    else:
        print(json.dumps(pck.list_files()[:5], indent=2))
