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
from engines.ue5.world_converter import WorldConverter
from engines.ue5.cue4parse_helper import scan_ue_iostore_assets

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
    p_decomp.add_argument("--domain-cluster", action="store_true", default=False, help="Cluster decompiled functions by architectural domain (core, editor, storage, gui, engine, runtime)")

    # Command: crypto
    p_crypto = subparsers.add_parser("crypto", help="Scan binary for cryptography, hashes, and anti-tamper protections")
    p_crypto.add_argument("binary", help="Path to binary file")

    # Command: engine
    p_eng = subparsers.add_parser("engine", help="Detect game engine and unpackable assets")
    p_eng.add_argument("path", help="Path to game executable or folder")

    # Command: mcp
    p_mcp = subparsers.add_parser("mcp", help="Launch Decod Headless MCP Server (JSON-RPC over stdio)")

    p_world = subparsers.add_parser("world-job", help="Create an automatic STALKER 2/UE5 world export job")
    p_world.add_argument("game_root", help="S.T.A.L.K.E.R. 2 installation or Stalker2 directory")
    p_world.add_argument("output", help="Output directory for manifest and exports")

    p_landscape = subparsers.add_parser(
        "landscape-heightmap-export",
        help="Reconstruct or stitch UE Landscape height grids from CUE4Parse probe reports and .ubulk files",
    )
    p_landscape.add_argument("probe_report", help="One probe JSON report or a directory of batch probe reports")
    p_landscape.add_argument("output", help="Output JSON height grid")
    p_landscape.add_argument("--bulk-file", default="", help="Optional .ubulk path if not listed in the probe report")

    p_cells = subparsers.add_parser(
        "world-cell-export",
        help="Batch-export one World Partition layer over a grid-coordinate rectangle",
    )
    p_cells.add_argument("game_root", help="STALKER 2 installation or Content/Paks directory")
    p_cells.add_argument("cell_index", help="JSON index of World Partition map package paths")
    p_cells.add_argument("output_dir", help="Directory for probe reports and extracted package payloads")
    p_cells.add_argument("--layer", required=True, choices=WorldConverter.WORLD_CELL_LAYERS)
    p_cells.add_argument("--min-x", required=True, type=int)
    p_cells.add_argument("--max-x", required=True, type=int)
    p_cells.add_argument("--min-y", required=True, type=int)
    p_cells.add_argument("--max-y", required=True, type=int)

    p_iostore = subparsers.add_parser(
        "ue-iostore-scan",
        help="Index Unreal PAK/IoStore assets headlessly with CUE4Parse",
    )
    p_iostore.add_argument("game_root", help="Unreal game root or Content/Paks directory")
    p_iostore.add_argument("output", help="Path for the JSON asset index")
    p_iostore.add_argument("--filter", default="", help="Only return package paths containing this text")
    p_iostore.add_argument("--limit", type=int, default=2000, help="Maximum package paths to write")
    p_iostore.add_argument("--game-version", default="GAME_UE5_5", help="CUE4Parse EGame enum value")
    p_iostore.add_argument("--probe", default="", help="Optional package path to parse and list exports")
    p_iostore.add_argument(
        "--package-type",
        choices=["all", "maps", "assets"],
        default="all",
        help="Limit results to all packages, .umap maps, or .uasset assets",
    )
    p_iostore.add_argument("--extract-dir", default="", help="Optional directory to save a probed package payload")

    p_modpack = subparsers.add_parser(
        "gummervibe-export-profile",
        help="Build a Minecraft 1.16.5 GummerVibe export profile from an installed modpack instance",
    )
    p_modpack.add_argument("modpack_instance", help="GummerCraft instance/minecraft directory")
    p_modpack.add_argument("output", help="Path for the export profile JSON")

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
        res = deconstruct_entire_binary(args.binary, out_dir, chunk_size=args.chunk_size, domain_cluster=args.domain_cluster)
        print(json.dumps(res, indent=2))

    elif args.command == "crypto":
        res = CryptoDetector.scan_file(args.binary)
        print(json.dumps(res, indent=2))

    elif args.command == "engine":
        res = detect_engine(args.path)
        print(json.dumps(res, indent=2))

    elif args.command == "world-job":
        res = WorldConverter.create_stalker_world_export_job(args.game_root, args.output)
        print(json.dumps(res, indent=2))

    elif args.command == "gummervibe-export-profile":
        res = WorldConverter.build_gummervibe_export_profile(
            args.modpack_instance,
            args.output,
        )
        print(json.dumps(res, indent=2))

    elif args.command == "landscape-heightmap-export":
        res = WorldConverter.export_landscape_heightmap_from_probe(
            args.probe_report,
            args.output,
            bulk_path=args.bulk_file,
        )
        print(json.dumps(res, indent=2))

    elif args.command == "world-cell-export":
        selection = WorldConverter.select_world_partition_cells(
            args.cell_index,
            args.layer,
            args.min_x,
            args.max_x,
            args.min_y,
            args.max_y,
        )
        if not selection["packages"]:
            raise ValueError(
                f"No {args.layer} L0 cells found in requested grid bounds: {selection['grid_bounds']}"
            )
        output_dir = os.path.abspath(args.output_dir)
        os.makedirs(output_dir, exist_ok=True)
        selection_path = os.path.join(output_dir, "selection.json")
        with open(selection_path, "w", encoding="utf-8") as handle:
            json.dump(selection, handle, ensure_ascii=False, indent=2)
        scan = scan_ue_iostore_assets(
            args.game_root,
            os.path.join(output_dir, "batch-index.json"),
            max_results=1,
            game_version="GAME_UE5_5",
            package_type="maps",
            extract_dir=os.path.join(output_dir, "raw"),
            batch_probe_assets=selection["packages"],
        )
        probe_data = scan.get("probe") or {}
        export_detail_error_count = 0
        for probe_result in probe_data.get("probes") or []:
            report_path = probe_result.get("report")
            if not report_path:
                raise ValueError(f"Batch probe did not provide a report path: {probe_result}")
            with open(report_path, "r", encoding="utf-8") as handle:
                probe_report = json.load(handle)
            probe_details = (probe_report.get("probe") or {}).get("export_details_errors") or []
            if not isinstance(probe_details, list):
                raise ValueError(f"Probe detail errors must be a list: {report_path}")
            export_detail_error_count += len(probe_details)
        res = {
            "status": scan.get("status"),
            "layer": selection["layer"],
            "grid_bounds": selection["grid_bounds"],
            "selected_package_count": selection["package_count"],
            "parsed_package_count": probe_data.get("parsed_count", 0),
            "partial_package_count": probe_data.get("partial_count", 0),
            "failed_package_count": probe_data.get("error_count", 0)
                + probe_data.get("raw_only_count", 0),
            "export_detail_error_count": export_detail_error_count,
            "selection": selection_path,
            "index": scan.get("output"),
            "probe_reports": probe_data.get("report_directory"),
            "extraction_dir": os.path.join(output_dir, "raw"),
        }
        with open(os.path.join(output_dir, "batch-summary.json"), "w", encoding="utf-8") as handle:
            json.dump(res, handle, ensure_ascii=False, indent=2)
        print(json.dumps(res, indent=2))

    elif args.command == "ue-iostore-scan":
        res = scan_ue_iostore_assets(
            args.game_root,
            args.output,
            filter_query=args.filter,
            max_results=args.limit,
            game_version=args.game_version,
            probe_asset=args.probe,
            package_type=args.package_type,
            extract_dir=args.extract_dir,
        )
        print(json.dumps(res, indent=2))

    elif args.command == "mcp":
        from core.mcp_server import main as mcp_main
        mcp_main()

if __name__ == "__main__":
    main()
