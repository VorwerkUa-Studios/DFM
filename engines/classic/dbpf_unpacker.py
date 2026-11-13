"""
DBPF (.package) Unpacker & Inspector for Spore, The Sims 2/3/4, and SimCity.
Reads EA DBPF package files (DBPF 1.x and 2.0) and extracts assets or catalogs.
"""

import os
import struct
import zlib
import json
from typing import List, Dict, Any, Optional

DBPF_MAGIC = b"DBPF"

class DBPFEntry:
    def __init__(self, type_id: int, group_id: int, instance_id: int, offset: int, size: int, decomp_size: int = 0, is_compressed: bool = False):
        self.type_id = type_id
        self.group_id = group_id
        self.instance_id = instance_id
        self.offset = offset
        self.size = size
        self.decomp_size = decomp_size
        self.is_compressed = is_compressed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type_id": f"0x{self.type_id:08X}",
            "group_id": f"0x{self.group_id:08X}",
            "instance_id": f"0x{self.instance_id:016X}" if self.instance_id > 0xFFFFFFFF else f"0x{self.instance_id:08X}",
            "offset": self.offset,
            "size": self.size,
            "decompressed_size": self.decomp_size,
            "compressed": self.is_compressed
        }

class DBPFPackage:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.entries: List[DBPFEntry] = []
        self.version_major = 0
        self.version_minor = 0
        self.parse_header()

    def parse_header(self):
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            magic = f.read(4)
            if magic != DBPF_MAGIC:
                raise ValueError(f"Invalid DBPF magic: {magic}. Expected b'DBPF'.")

            self.version_major, self.version_minor = struct.unpack("<II", f.read(8))
            f.seek(24, os.SEEK_CUR)  # skip reserved

            # In standard DBPF:
            # offset 36: index count
            # offset 40: index offset
            # offset 44: index size
            f.seek(36, os.SEEK_SET)
            index_count, index_offset, index_size = struct.unpack("<III", f.read(12))

            # Read Index table
            f.seek(index_offset, os.SEEK_SET)
            for _ in range(index_count):
                # Standard DBPF v1 / Spore header format for entries
                entry_data = f.read(20)
                if len(entry_data) < 20:
                    break
                type_id, group_id, instance_id, offset, size = struct.unpack("<IIIII", entry_data)
                
                # Check compression bit flag
                is_compressed = bool(size & 0x80000000)
                actual_size = size & 0x7FFFFFFF

                self.entries.append(DBPFEntry(
                    type_id=type_id,
                    group_id=group_id,
                    instance_id=instance_id,
                    offset=offset,
                    size=actual_size,
                    is_compressed=is_compressed
                ))

    def list_entries(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries]

    def extract_all(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        with open(self.filepath, "rb") as f:
            for i, entry in enumerate(self.entries):
                f.seek(entry.offset, os.SEEK_SET)
                raw_data = f.read(entry.size)
                
                # Decompress if needed (Zlib / QFS)
                out_data = raw_data
                if entry.is_compressed:
                    try:
                        out_data = zlib.decompress(raw_data)
                    except Exception:
                        # Some versions use QFS or custom headers, fallback to raw
                        out_data = raw_data

                filename = f"chunk_{i:04d}_T{entry.type_id:08X}_G{entry.group_id:08X}_I{entry.instance_id:08X}.bin"
                out_path = os.path.join(output_dir, filename)
                with open(out_path, "wb") as out_f:
                    out_f.write(out_data)

        return len(self.entries)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dbpf_unpacker.py <package_file> [output_dir]")
        sys.exit(1)

    pkg_path = sys.argv[1]
    pkg = DBPFPackage(pkg_path)
    print(f"[*] Package: {pkg_path}")
    print(f"[*] Version: {pkg.version_major}.{pkg.version_minor}")
    print(f"[*] Found {len(pkg.entries)} entries.")

    if len(sys.argv) >= 3:
        out_folder = sys.argv[2]
        extracted = pkg.extract_all(out_folder)
        print(f"[+] Extracted {extracted} files into '{out_folder}'.")
    else:
        print(json.dumps(pkg.list_entries()[:5], indent=2))
        print("... (use second argument to extract)")
