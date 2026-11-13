"""
Decod Binary Signature & String Scanner:
1. Fast ASCII & UTF-16 (Unicode wide) string extraction and filtering.
2. AOB (Array of Bytes) pattern scanner with wildcards (?? or *) across binary sections.
3. Maps matching file offsets to virtual addresses (RVA).
"""

import os
import sys
import re
from typing import List, Dict, Any, Optional
import lief

class SigScanner:
    def __init__(self, binary_path: str):
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        self.binary_path = os.path.abspath(binary_path)
        self.binary = lief.parse(self.binary_path)
        with open(self.binary_path, "rb") as f:
            self.raw_data = f.read()

    def search_strings(self, query: str = "", min_length: int = 4, max_results: int = 100) -> List[Dict[str, Any]]:
        """Search ASCII and UTF-16 wide strings in binary."""
        results = []
        q_lower = query.lower()

        # 1. ASCII strings
        ascii_regex = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
        for match in ascii_regex.finditer(self.raw_data):
            val = match.group().decode("ascii", errors="ignore")
            if not query or q_lower in val.lower():
                offset = match.start()
                rva = None
                if self.binary and hasattr(self.binary, "offset_to_virtual_address"):
                    try:
                        rva = hex(self.binary.offset_to_virtual_address(offset))
                    except Exception:
                        rva = None
                results.append({
                    "string": val,
                    "encoding": "ASCII",
                    "file_offset": hex(offset),
                    "rva": rva
                })
                if len(results) >= max_results:
                    return results

        # 2. UTF-16LE Unicode strings
        wide_regex = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}")
        for match in wide_regex.finditer(self.raw_data):
            try:
                val = match.group().decode("utf-16le", errors="ignore")
            except Exception:
                continue
            if not query or q_lower in val.lower():
                offset = match.start()
                rva = None
                if self.binary and hasattr(self.binary, "offset_to_virtual_address"):
                    try:
                        rva = hex(self.binary.offset_to_virtual_address(offset))
                    except Exception:
                        rva = None
                results.append({
                    "string": val,
                    "encoding": "UTF-16LE",
                    "file_offset": hex(offset),
                    "rva": rva
                })
                if len(results) >= max_results:
                    return results

        return results

    def scan_aob(self, pattern: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Scan for Array of Bytes (AOB) pattern with wildcards (?? or *).
        Example: '48 8B 05 ?? ?? ?? ?? 48 85 C0'
        """
        clean_tokens = pattern.strip().split()
        regex_parts = []

        for token in clean_tokens:
            if token in ["??", "?", "*"]:
                regex_parts.append(b".")
            else:
                try:
                    byte_val = int(token, 16)
                    regex_parts.append(re.escape(bytes([byte_val])))
                except ValueError:
                    raise ValueError(f"Invalid byte token in AOB pattern: {token}")

        compiled_pattern = re.compile(b"".join(regex_parts), re.DOTALL)
        matches = []

        for match in compiled_pattern.finditer(self.raw_data):
            offset = match.start()
            rva = None
            if self.binary and hasattr(self.binary, "offset_to_virtual_address"):
                try:
                    rva = hex(self.binary.offset_to_virtual_address(offset))
                except Exception:
                    rva = None

            matched_bytes = match.group().hex(" ").upper()
            matches.append({
                "file_offset": hex(offset),
                "rva": rva,
                "matched_bytes": matched_bytes
            })
            if len(matches) >= max_results:
                break

        return matches

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python sig_scanner.py strings <file> <search_query>")
        print("  python sig_scanner.py aob <file> '<hex pattern>'")
        sys.exit(1)

    cmd = sys.argv[1]
    scanner = SigScanner(sys.argv[2])
    import json

    if cmd == "strings":
        query = sys.argv[3] if len(sys.argv) > 3 else ""
        print(json.dumps(scanner.search_strings(query=query, max_results=10), indent=2))
    elif cmd == "aob":
        pattern = sys.argv[3]
        print(json.dumps(scanner.scan_aob(pattern=pattern), indent=2))
