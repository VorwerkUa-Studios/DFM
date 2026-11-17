#!/usr/bin/env python3
"""
Decod Universal Reverse Engineering & Decompilation CLI
Single entry point for all Decod tools: AST decompilation, crypto scanning,
engine detection, memory analysis, and headless MCP server.
"""

import sys
import os
import argparse
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from tools.decompiler.decompile_full_binary import deconstruct_entire_binary
from tools.decompiler.project_decompiler import ProjectDecompiler
from tools.decompiler.crypto_detector import CryptoDetector
from tools.decompiler.dll_analyzer import DLLAnalyzer
from engines.detector import detect_engine

def main():
    parser = argparse.ArgumentParser(
        description="Decod: Universal Reverse Engineering, Decompilation & Binary Deconstruction Toolkit"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available Decod commands")

    # Command: decompile
    p_decomp = subparsers.add_parser("decompile", help="Decompile native binary to C++ source code")
    p_decomp.add_argument("binary", help="Path to binary (.dll, .exe, .addon64, .so)")
    p_decomp.add_argument("output", nargs="?", default=None, help="Output directory for generated C++ project")
    p_decomp.add_argument("--all", action="store_true", default=True, help="Decompile 100% of all functions (default: true)")
    p_decomp.add_argument("--chunk-size", type=int, default=500, help="Number of functions per module file (default 500)")

    # Command: crypto
    p_crypto = subparsers.add_parser("crypto", help="Scan binary for cryptography, hashes, and anti-tamper protections")
    p_crypto.add_argument("binary", help="Path to binary file")

    # Command: engine
    p_eng = subparsers.add_parser("engine", help="Detect game engine and unpackable assets")
    p_eng.add_argument("path", help="Path to game executable or folder")

    # Command: mcp
    p_mcp = subparsers.add_parser("mcp", help="Launch Decod Headless MCP Server (JSON-RPC over stdio)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "decompile":
        out_dir = args.output
        if not out_dir:
            base_name = os.path.splitext(os.path.basename(args.binary))[0]
            out_dir = os.path.join(os.path.dirname(args.binary), f"{base_name}_Decompiled_Project")

        print(f"[*] Decod Universal Decompiler starting...")
        print(f"[*] Target: {args.binary}")
        print(f"[*] Output: {out_dir}")
        res = deconstruct_entire_binary(args.binary, out_dir, chunk_size=args.chunk_size)
        print(json.dumps(res, indent=2))

    elif args.command == "crypto":
        res = CryptoDetector.scan_file(args.binary)
        print(json.dumps(res, indent=2))

    elif args.command == "engine":
        res = detect_engine(args.path)
        print(json.dumps(res, indent=2))

    elif args.command == "mcp":
        from core.mcp_server import main as mcp_main
        mcp_main()

if __name__ == "__main__":
    main()
