"""
Decod Advanced Crypto & Protection Detector:
Detects, analyzes, and identifies all cryptographic algorithms, constants,
obfuscation schemes, packers, and integrity checks in binaries and game files.
"""

import os
import struct
import math
from typing import Dict, Any, List

class CryptoDetector:
    # ── Cryptographic Constants & Signatures ──────────────────────
    SIGNATURES = {
        # Block Ciphers
        "TEA / XTEA (Delta 0x9E3779B9)": {
            "bytes": struct.pack("<I", 0x9E3779B9),
            "type": "block_cipher",
            "desc": "Tiny Encryption Algorithm (TEA/XTEA) key schedule constant"
        },
        "TEA / XTEA (Delta 0x61C88647)": {
            "bytes": struct.pack("<I", 0x61C88647),
            "type": "block_cipher",
            "desc": "Tiny Encryption Algorithm (TEA/XTEA) reverse delta constant"
        },
        "AES S-Box (Rijndael)": {
            "bytes": bytes([
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0
            ]),
            "type": "block_cipher",
            "desc": "Advanced Encryption Standard (AES) forward substitution box"
        },
        "AES Inverse S-Box": {
            "bytes": bytes([
                0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB
            ]),
            "type": "block_cipher",
            "desc": "Advanced Encryption Standard (AES) inverse substitution box"
        },
        "Blowfish P-Box Init": {
            "bytes": struct.pack("<IIII", 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344),
            "type": "block_cipher",
            "desc": "Blowfish initial permutation array (derived from Pi)"
        },
        "DES Initial Permutation": {
            "bytes": bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]),
            "type": "block_cipher",
            "desc": "Data Encryption Standard (DES) Initial Permutation (IP) table"
        },

        # Hash Functions
        "MD5 Init Constants": {
            "bytes": struct.pack("<IIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
            "type": "hash",
            "desc": "MD5 Initial State Constants (A, B, C, D)"
        },
        "SHA-1 Init Constants": {
            "bytes": struct.pack("<IIIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
            "type": "hash",
            "desc": "SHA-1 Initial Hash State (H0-H4)"
        },
        "SHA-256 Init Constants": {
            "bytes": struct.pack("<IIII", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A),
            "type": "hash",
            "desc": "SHA-256 Initial Hash State (H0-H3)"
        },
        "SHA-256 Round Constants (K)": {
            "bytes": struct.pack("<IIII", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5),
            "type": "hash",
            "desc": "SHA-256 Round Constants K[0..3]"
        },
        "SHA-512 Init Constants": {
            "bytes": struct.pack("<QQ", 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B),
            "type": "hash",
            "desc": "SHA-512 Initial Hash State (H0-H1)"
        },

        # Checksums & Cyclic Codes
        "CRC32 Standard Polynomial (0xEDB88320)": {
            "bytes": struct.pack("<I", 0xEDB88320),
            "type": "checksum",
            "desc": "CRC32 standard polynomial representation (ISO 3309)"
        },
        "CRC32 Castagnoli (0x82F63B78)": {
            "bytes": struct.pack("<I", 0x82F63B78),
            "type": "checksum",
            "desc": "CRC32-C (Castagnoli) polynomial used in hardware SSE4.2 CRC"
        },
        "Adler-32 Modulo (65521)": {
            "bytes": struct.pack("<I", 65521),
            "type": "checksum",
            "desc": "Adler-32 Prime Modulo constant (ZLIB checksum)"
        },

        # Compression Formats
        "ZLIB Compression Header": {
            "bytes": b"\x78\x9c",
            "type": "compression",
            "desc": "Deflate / ZLIB default compression stream header"
        },
        "Zstandard (ZSTD) Magic": {
            "bytes": b"\x28\xb5\x2f\xfd",
            "type": "compression",
            "desc": "Zstandard (ZSTD) container magic bytes"
        },
        "LZ4 Frame Magic": {
            "bytes": b"\x04\x22\x4d\x18",
            "type": "compression",
            "desc": "LZ4 Framing format magic"
        },
        "Oodle Kraken / Selkie Magic": {
            "bytes": b"\x8c\x06",
            "type": "compression",
            "desc": "Epic Games / RAD Game Tools Oodle Network/File compression stream"
        },
        "GZIP Magic": {
            "bytes": b"\x1f\x8b",
            "type": "compression",
            "desc": "GZIP compressed archive magic header"
        },
        "Bzip2 Magic": {
            "bytes": b"BZh",
            "type": "compression",
            "desc": "Bzip2 compressed stream magic header"
        },

        # Encoders & Alphabets
        "Base64 Standard Alphabet": {
            "bytes": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "type": "encoding",
            "desc": "Standard RFC 4648 Base64 character translation table"
        },
        "Base58 Bitcoin Alphabet": {
            "bytes": b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            "type": "encoding",
            "desc": "Base58 encoding alphabet"
        }
    }

    # ── Windows Crypto & Security API Patterns ─────────────────────
    CRYPTO_APIS = {
        "bcrypt.dll": {
            "BCryptOpenAlgorithmProvider": "Opens cryptographic algorithm provider (e.g. SHA256, AES)",
            "BCryptCreateHash": "Creates a hash or MAC object",
            "BCryptHashData": "Hashes a block of data (anti-tamper integrity check / token hashing)",
            "BCryptFinishHash": "Completes hash calculation and retrieves digest",
            "BCryptEncrypt": "Symmetric/Asymmetric encryption",
            "BCryptDecrypt": "Symmetric/Asymmetric decryption",
            "BCryptGenerateSymmetricKey": "Generates key object from raw AES/DES key"
        },
        "advapi32.dll": {
            "CryptAcquireContextA": "Legacy Windows CryptoAPI context initialization",
            "CryptAcquireContextW": "Legacy Windows CryptoAPI context initialization",
            "CryptCreateHash": "CryptoAPI hash object creation",
            "CryptHashData": "CryptoAPI data hashing",
            "CryptDeriveKey": "CryptoAPI key derivation from password",
            "CryptDecrypt": "CryptoAPI decryption"
        }
    }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon entropy of a byte stream (0.0 to 8.0). Values > 7.2 indicate encryption/compression."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def scan_file(cls, file_path: str) -> Dict[str, Any]:
        """Comprehensive scan of a binary for all cryptographic algorithms, APIs, and protection mechanisms."""
        if not os.path.exists(file_path):
            return {"status": "error", "error": f"File not found: {file_path}"}

        with open(file_path, "rb") as f:
            data = f.read()

        file_size = len(data)
        overall_entropy = cls.calculate_entropy(data)

        # 1. Scan for Cryptographic Constants
        detected_constants = []
        for name, info in cls.SIGNATURES.items():
            pattern = info["bytes"]
            pos = 0
            offsets = []
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                offsets.append(f"0x{pos:X}")
                pos += 1
                if len(offsets) >= 15:
                    break
            if offsets:
                detected_constants.append({
                    "name": name,
                    "type": info["type"],
                    "description": info["desc"],
                    "occurrences": len(offsets),
                    "offsets": offsets[:8]
                })

        # 2. Check PE Import Table for Crypto Libraries & APIs
        detected_apis = []
        is_pe = data.startswith(b"MZ")
        sections_entropy = []

        if is_pe:
            try:
                import lief
                binary = lief.PE.parse(file_path)
                if binary:
                    for section in binary.sections:
                        s_bytes = bytes(section.content)
                        s_entropy = cls.calculate_entropy(s_bytes)
                        is_encrypted_or_packed = s_entropy > 7.2
                        sections_entropy.append({
                            "name": section.name,
                            "virtual_address": f"0x{section.virtual_address:X}",
                            "raw_size": section.size,
                            "entropy": s_entropy,
                            "is_packed_or_encrypted": is_encrypted_or_packed
                        })

                    for imp in binary.imports:
                        lib_name = imp.name.lower()
                        if lib_name in cls.CRYPTO_APIS:
                            matched_funcs = []
                            for entry in imp.entries:
                                if entry.name in cls.CRYPTO_APIS[lib_name]:
                                    matched_funcs.append({
                                        "name": entry.name,
                                        "description": cls.CRYPTO_APIS[lib_name][entry.name],
                                        "iat_address": f"0x{entry.iat_address:X}"
                                    })
                            if matched_funcs:
                                detected_apis.append({
                                    "library": imp.name,
                                    "functions": matched_funcs
                                })
            except Exception as e:
                pass

        # 3. Detect XOR Encrypted Blocks
        xor_candidates = cls.detect_xor_patterns(data[:min(len(data), 500000)])

        # 4. Anti-Tamper & Protection Assessment
        protection_flags = []
        has_bcrypt = any(api["library"].lower() == "bcrypt.dll" for api in detected_apis)
        if has_bcrypt:
            protection_flags.append("Anti-Tamper Integrity Check (Windows BCrypt SHA-256 / SHA-1 validation active)")
        if any(c["name"].startswith("TEA") for c in detected_constants):
            protection_flags.append("TEA / XTEA Symmetric Obfuscation used for internal asset/preset protection")
        if any(c["name"].startswith("CRC32") for c in detected_constants):
            protection_flags.append("CRC32 Checksums used for fast structural data validation")
        if any(s.get("is_packed_or_encrypted") for s in sections_entropy):
            protection_flags.append("High-Entropy Sections detected (potential binary packing or encrypted payload)")

        return {
            "status": "success",
            "file_path": file_path,
            "file_size": file_size,
            "overall_entropy": overall_entropy,
            "is_likely_packed_or_encrypted": overall_entropy > 7.1,
            "detected_cryptographic_constants": detected_constants,
            "detected_crypto_apis": detected_apis,
            "sections_entropy": sections_entropy,
            "detected_xor_candidates": xor_candidates,
            "protection_summary": protection_flags
        }

    @staticmethod
    def detect_xor_patterns(sample: bytes) -> List[Dict[str, Any]]:
        """Quick heuristic search for repeated XOR keys in ASCII string tables."""
        candidates = []
        # Test 1-byte XOR against common English/code words
        probes = [b"http", b"Unreal", b"Stalker", b"Addon", b"Texture", b"Version"]
        for probe in probes:
            for key in range(1, 256):
                xored = bytes([b ^ key for b in probe])
                idx = sample.find(xored)
                if idx != -1:
                    candidates.append({
                        "type": "Single-Byte XOR",
                        "candidate_key": f"0x{key:02X}",
                        "matched_string": probe.decode(errors='ignore'),
                        "offset": f"0x{idx:X}"
                    })
                    break
            if len(candidates) >= 3:
                break
        return candidates

if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else r"D:\ZoneTerra_extracted\ZoneTerra.addon64"
    res = CryptoDetector.scan_file(target)
    print(json.dumps(res, indent=2))
