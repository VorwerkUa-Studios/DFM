"""
Electron ASAR Archive Unpacker (Pure Python):
Extracts source code (JS, TS, HTML, CSS, configs) from Electron app archives (app.asar).
Used by Discord, VS Code, Slack, Obsidian, Spotify, Teams, and desktop game launchers.
"""

import os
import struct
import json
from typing import Dict, Any

class AsarUnpacker:
    def __init__(self, asar_path: str):
        if not os.path.exists(asar_path):
            raise FileNotFoundError(f"ASAR file not found: {asar_path}")
        self.asar_path = os.path.abspath(asar_path)
        self.header = None
        self.base_offset = 0
        self.parse_header()

    def parse_header(self):
        with open(self.asar_path, "rb") as f:
            # First 16 bytes:
            # 4 bytes: 0x00000004 (magic/prefix)
            # 4 bytes: total header size (including JSON size)
            # 4 bytes: header JSON size + 4
            # 4 bytes: header JSON string size
            f.seek(4, os.SEEK_SET)
            total_size = struct.unpack("<I", f.read(4))[0]
            f.seek(4, os.SEEK_CUR)
            json_len = struct.unpack("<I", f.read(4))[0]

            json_bytes = f.read(json_len)
            self.header = json.loads(json_bytes.decode("utf-8"))
            self.base_offset = 16 + json_len

    def extract_all(self, output_dir: str) -> int:
        os.makedirs(output_dir, exist_ok=True)
        extracted_count = [0]

        with open(self.asar_path, "rb") as f:
            def extract_node(node: dict, current_path: str):
                files = node.get("files", {})
                for name, item in files.items():
                    target_path = os.path.join(current_path, name)
                    if "files" in item:
                        # Directory
                        os.makedirs(target_path, exist_ok=True)
                        extract_node(item, target_path)
                    elif "size" in item and "offset" in item:
                        # File
                        offset = self.base_offset + int(item["offset"])
                        size = int(item["size"])
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)

                        f.seek(offset, os.SEEK_SET)
                        data = f.read(size)
                        with open(target_path, "wb") as out_f:
                            out_f.write(data)
                        extracted_count[0] += 1

            extract_node(self.header, output_dir)
        return extracted_count[0]

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python asar_helper.py <app.asar> <output_dir>")
        sys.exit(1)

    unpacker = AsarUnpacker(sys.argv[1])
    count = unpacker.extract_all(sys.argv[2])
    print(f"[+] Extracted {count} files from ASAR into '{sys.argv[2]}'.")
