"""
Java & Minecraft (JVM) Inspector & Extractor:
1. Unpacks and inspects Java .jar / .war / .apk archives.
2. Inspects compiled Java .class bytecode headers (detects Java 8-21 compiler targets).
3. Parses Minecraft NBT (Named Binary Tag) format files (level.dat, player data, chunk data).
"""

import os
import io
import gzip
import zlib
import zipfile
import struct
import json
from typing import Dict, Any, List, Tuple

JAVA_CLASS_MAGIC = 0xCAFEBABE

JAVA_VERSIONS = {
    45: "Java 1.1", 46: "Java 1.2", 47: "Java 1.3", 48: "Java 1.4",
    49: "Java 5",   50: "Java 6",   51: "Java 7",   52: "Java 8",
    53: "Java 9",   54: "Java 10",  55: "Java 11",  56: "Java 12",
    57: "Java 13",  58: "Java 14",  59: "Java 15",  60: "Java 16",
    61: "Java 17",  62: "Java 18",  63: "Java 19",  64: "Java 20",
    65: "Java 21",  66: "Java 22",  67: "Java 23"
}

# --- NBT Tag Types (Minecraft) ---
TAG_END = 0
TAG_BYTE = 1
TAG_SHORT = 2
TAG_INT = 3
TAG_LONG = 4
TAG_FLOAT = 5
TAG_DOUBLE = 6
TAG_BYTE_ARRAY = 7
TAG_STRING = 8
TAG_LIST = 9
TAG_COMPOUND = 10
TAG_INT_ARRAY = 11
TAG_LONG_ARRAY = 12

class NBTParser:
    """Parses Minecraft binary NBT format (level.dat, player files, chunks)."""
    def __init__(self, data: bytes):
        # Auto-detect GZIP or ZLIB compression
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        elif data[:2] == b"\x78\x9c" or data[:2] == b"\x78\x01":
            try:
                data = zlib.decompress(data)
            except Exception:
                pass
        self.stream = io.BytesIO(data)

    def read_string(self) -> str:
        length = struct.unpack(">H", self.stream.read(2))[0]
        return self.stream.read(length).decode("utf-8", errors="replace")

    def parse_payload(self, tag_type: int) -> Any:
        if tag_type == TAG_BYTE:
            return struct.unpack(">b", self.stream.read(1))[0]
        elif tag_type == TAG_SHORT:
            return struct.unpack(">h", self.stream.read(2))[0]
        elif tag_type == TAG_INT:
            return struct.unpack(">i", self.stream.read(4))[0]
        elif tag_type == TAG_LONG:
            return struct.unpack(">q", self.stream.read(8))[0]
        elif tag_type == TAG_FLOAT:
            return round(struct.unpack(">f", self.stream.read(4))[0], 4)
        elif tag_type == TAG_DOUBLE:
            return round(struct.unpack(">d", self.stream.read(8))[0], 6)
        elif tag_type == TAG_BYTE_ARRAY:
            length = struct.unpack(">i", self.stream.read(4))[0]
            return f"<Byte Array: {length} bytes>"
        elif tag_type == TAG_STRING:
            return self.read_string()
        elif tag_type == TAG_LIST:
            elem_type = struct.unpack(">b", self.stream.read(1))[0]
            count = struct.unpack(">i", self.stream.read(4))[0]
            return [self.parse_payload(elem_type) for _ in range(min(count, 100))]
        elif tag_type == TAG_COMPOUND:
            compound = {}
            while True:
                sub_type_bytes = self.stream.read(1)
                if not sub_type_bytes:
                    break
                sub_type = sub_type_bytes[0]
                if sub_type == TAG_END:
                    break
                sub_name = self.read_string()
                compound[sub_name] = self.parse_payload(sub_type)
            return compound
        elif tag_type == TAG_INT_ARRAY:
            count = struct.unpack(">i", self.stream.read(4))[0]
            return f"<Int Array: {count} ints>"
        elif tag_type == TAG_LONG_ARRAY:
            count = struct.unpack(">i", self.stream.read(4))[0]
            return f"<Long Array: {count} longs>"
        return None

    def parse(self) -> Dict[str, Any]:
        root_type_bytes = self.stream.read(1)
        if not root_type_bytes or root_type_bytes[0] == TAG_END:
            return {}
        root_type = root_type_bytes[0]
        root_name = self.read_string()
        return {root_name: self.parse_payload(root_type)}

class JavaHelper:
    @staticmethod
    def inspect_class_file(file_path: str) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            magic = struct.unpack(">I", f.read(4))[0]
            if magic != JAVA_CLASS_MAGIC:
                raise ValueError("Not a valid Java .class file (magic != 0xCAFEBABE)")
            minor, major = struct.unpack(">HH", f.read(4))
            return {
                "file": file_path,
                "major_version": major,
                "minor_version": minor,
                "target_platform": JAVA_VERSIONS.get(major, f"Java Major {major}")
            }

    @staticmethod
    def unpack_jar(jar_path: str, output_dir: str) -> Dict[str, Any]:
        if not os.path.exists(jar_path):
            raise FileNotFoundError(f"JAR file not found: {jar_path}")

        os.makedirs(output_dir, exist_ok=True)
        class_count = 0
        asset_count = 0

        with zipfile.ZipFile(jar_path, "r") as z:
            for item in z.namelist():
                if item.endswith(".class"):
                    class_count += 1
                else:
                    asset_count += 1
            z.extractall(output_dir)

        return {
            "status": "success",
            "jar_path": jar_path,
            "output_dir": output_dir,
            "classes_count": class_count,
            "assets_count": asset_count,
            "total_files": class_count + asset_count
        }

    @staticmethod
    def parse_minecraft_nbt(nbt_path: str) -> Dict[str, Any]:
        if not os.path.exists(nbt_path):
            raise FileNotFoundError(f"NBT file not found: {nbt_path}")
        with open(nbt_path, "rb") as f:
            raw = f.read()
        parser = NBTParser(raw)
        return parser.parse()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python java_helper.py unpack_jar <path.jar> <output_dir>")
        print("  python java_helper.py read_nbt <level.dat>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "unpack_jar":
        res = JavaHelper.unpack_jar(sys.argv[2], sys.argv[3])
        print(json.dumps(res, indent=2))
    elif cmd == "read_nbt":
        res = JavaHelper.parse_minecraft_nbt(sys.argv[2])
        print(json.dumps(res, indent=2))
