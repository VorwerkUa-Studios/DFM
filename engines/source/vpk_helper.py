"""
Valve Source Engine VPK (Valve Pak) Archive Unpacker:
Extracts models, maps, textures, scripts, and sounds from .vpk archives (Half-Life 2, Portal, L4D, TF2).
Pure Python implementation with no external dependencies.
"""

import os
import struct
import json
from typing import List, Dict, Any

VPK_SIGNATURE = 0x55AA1234

def read_cstring(f) -> str:
    chars = []
    while True:
        c = f.read(1)
        if not c or c == b"\x00":
            break
        chars.append(c)
    return b"".join(chars).decode("utf-8", errors="replace")

class VPKEntry:
    def __init__(self, full_path: str, archive_index: int, offset: int, length: int, preload_data: bytes):
        self.full_path = full_path
        self.archive_index = archive_index
        self.offset = offset
        self.length = length
        self.preload_data = preload_data

class VPKPackage:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.entries: List[VPKEntry] = []
        self.version = 0
        self.tree_size = 0
        self.header_size = 0
        self.parse()

    def parse(self):
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"VPK not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            sig, version, tree_size = struct.unpack("<III", f.read(12))
            if sig != VPK_SIGNATURE:
                raise ValueError(f"Invalid VPK signature: 0x{sig:08X}. Expected 0x55AA1234.")

            self.version = version
            self.tree_size = tree_size
            self.header_size = 12

            if version == 2:
                # VPK v2 has 16 additional header bytes
                f.seek(16, os.SEEK_CUR)
                self.header_size += 16

            # Parse directory tree
            while True:
                ext = read_cstring(f)
                if not ext:
                    break

                while True:
                    path = read_cstring(f)
                    if not path:
                        break

                    while True:
                        filename = read_cstring(f)
                        if not filename:
                            break

                        entry_raw = f.read(18)
                        crc, preload_bytes, archive_index, entry_offset, entry_length, term = struct.unpack("<IHHIIH", entry_raw)
                        preload_data = f.read(preload_bytes) if preload_bytes > 0 else b""

                        full_path = f"{path}/{filename}.{ext}" if path != " " else f"{filename}.{ext}"

                        self.entries.append(VPKEntry(
                            full_path=full_path,
                            archive_index=archive_index,
                            offset=entry_offset,
                            length=entry_length,
                            preload_data=preload_data
                        ))

    def list_files(self) -> List[Dict[str, Any]]:
        return [{"path": e.full_path, "size": e.length + len(e.preload_data)} for e in self.entries]

    def extract_all(self, output_dir: str) -> int:
        os.makedirs(output_dir, exist_ok=True)
        data_start = self.header_size + self.tree_size

        with open(self.filepath, "rb") as f:
            for entry in self.entries:
                out_path = os.path.join(output_dir, entry.full_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                with open(out_path, "wb") as out_f:
                    if entry.preload_data:
                        out_f.write(entry.preload_data)

                    if entry.length > 0:
                        # 0x7FFF means embedded data inside this single VPK
                        if entry.archive_index == 0x7FFF:
                            f.seek(data_start + entry.offset, os.SEEK_SET)
                            out_f.write(f.read(entry.length))
                        else:
                            # Multi-part VPK: _dir.vpk references _000.vpk, _001.vpk, etc.
                            base = self.filepath.rsplit("_dir.vpk", 1)[0]
                            part_path = f"{base}_{entry.archive_index:03d}.vpk"
                            if os.path.exists(part_path):
                                with open(part_path, "rb") as pf:
                                    pf.seek(entry.offset, os.SEEK_SET)
                                    out_f.write(pf.read(entry.length))

        return len(self.entries)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python vpk_helper.py <file.vpk> [output_dir]")
        sys.exit(1)

    vpk = VPKPackage(sys.argv[1])
    print(f"[*] VPK Version: {vpk.version}")
    print(f"[*] Total entries: {len(vpk.entries)}")

    if len(sys.argv) >= 3:
        out_dir = sys.argv[2]
        extracted = vpk.extract_all(out_dir)
        print(f"[+] Extracted {extracted} files into '{out_dir}'.")
    else:
        print(json.dumps(vpk.list_files()[:5], indent=2))
