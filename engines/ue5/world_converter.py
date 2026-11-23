"""
World transfer helpers for Unreal/UE4SS maps and Minecraft exports.

This module deliberately uses simple, inspectable formats: CSV/JSON height grids,
OBJ meshes, UE asset-name manifests, and Minecraft .mcfunction output.
"""

import csv
import json
import math
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _landscape_owner_from_reference(object_name: str) -> str:
    if "'" not in object_name:
        return ""
    object_path = object_name.split("'", 1)[1].rsplit("'", 1)[0].split(":")[-1]
    parts = object_path.split(".")
    return parts[-2] if len(parts) > 1 else ""


def _landscape_world_transform(
    details: List[Dict[str, Any]],
    components: List[Dict[str, Any]],
    min_x: int,
    min_y: int,
    raw_min: int,
    raw_max: int,
) -> Optional[Dict[str, Any]]:
    owner_actor = next((component["owner_actor"] for component in components if component["owner_actor"]), "")
    if not owner_actor:
        return None

    proxy = next(
        (
            detail for detail in details
            if detail.get("type") == "LandscapeStreamingProxy"
            and detail.get("name") == owner_actor
        ),
        None,
    )
    if not proxy:
        return None

    proxy_properties = (proxy.get("data") or {}).get("Properties") or {}
    root_reference = (proxy_properties.get("RootComponent") or {}).get("ObjectName", "")
    root_name = root_reference.split("'", 1)[1].rsplit("'", 1)[0].rsplit(".", 1)[-1] if "'" in root_reference else ""
    root_component = next(
        (
            detail for detail in details
            if detail.get("type") == "SceneComponent"
            and detail.get("name") == root_name
            and (detail.get("data") or {}).get("Outer") == owner_actor
        ),
        None,
    )
    if not root_component:
        return None

    root_properties = (root_component.get("data") or {}).get("Properties") or {}
    location = root_properties.get("RelativeLocation")
    scale = root_properties.get("RelativeScale3D")
    section_offset = proxy_properties.get("LandscapeSectionOffset")
    if not isinstance(location, dict) or not isinstance(scale, dict) or not isinstance(section_offset, dict):
        return None

    origin_x = float(location["X"]) + (min_x - int(section_offset["X"])) * float(scale["X"])
    origin_y = float(location["Y"]) + (min_y - int(section_offset["Y"])) * float(scale["Y"])
    origin_z = float(location["Z"])
    height_scale = float(scale["Z"]) / 128.0
    return {
        "unreal_origin_cm": {"x": origin_x, "y": origin_y, "z": origin_z},
        "cm_per_grid_sample": {"x": float(scale["X"]), "y": float(scale["Y"])},
        "landscape_scale_z_cm": float(scale["Z"]),
        "height_cm_per_raw_unit": height_scale,
        "height_cm_range": {
            "min": origin_z + (raw_min - 32768) * height_scale,
            "max": origin_z + (raw_max - 32768) * height_scale,
        },
        "height_formula": "origin_z + (raw_height - 32768) * landscape_scale_z_cm / 128",
    }


class WorldConverter:
    WORLD_CELL_LAYERS = (
        "Terrain",
        "Architecture",
        "Props",
        "TreesEnv",
        "BakedFoliageGrid",
        "BakedFoliageGridNonDistantTrees",
        "MainGrid",
    )

    MODPACK_BLOCK_IDS = {
        "concrete": "gummervibe:bricks_1",
        "brick": "gummervibe:bricks_2",
        "white_brick": "gummervibe:white_bricks",
        "wood": "gummervibe:wood_1",
        "metal": "gummervibe:metal_1",
        "door": "gummervibe:door_standart",
        "metal_door": "gummervibe:door_metal",
        "electro": "gummervibe:anomaly_elektro",
        "burner": "gummervibe:anomaly_zharka",
        "grinder": "gummervibe:anomaly_miasorubka",
        "spatial": "gummervibe:anomaly_prostorova",
        "launch": "gummervibe:anomaly_tramplin",
        "glass_shards": "gummervibe:anomaly_sklyani_ulamky",
        "chemical": "gummervibe:anomaly_khimichna",
        "radiation": "gummervibe:radiation_block",
    }

    @staticmethod
    def build_gummervibe_export_profile(modpack_root: str, output_path: str) -> Dict[str, Any]:
        root = Path(modpack_root)
        if not root.is_dir():
            raise FileNotFoundError(f"Modpack instance not found: {root}")

        mods_dir = root / "mods"
        resourcepacks_dir = root / "resourcepacks"
        jar_names = sorted(path.name for path in mods_dir.glob("*.jar")) if mods_dir.is_dir() else []
        resource_pack_names = sorted(
            path.name
            for path in resourcepacks_dir.iterdir()
            if resourcepacks_dir.is_dir() and (path.is_file() or path.is_dir())
        ) if resourcepacks_dir.is_dir() else []

        anomaly_blocks = {
            category: block_id
            for category, block_id in WorldConverter.MODPACK_BLOCK_IDS.items()
            if category in {
                "electro",
                "burner",
                "grinder",
                "spatial",
                "launch",
                "glass_shards",
                "chemical",
                "radiation",
            }
        }
        profile = {
            "format": "decod-gummervibe-export-profile-v1",
            "minecraft": "1.16.5",
            "loader": "Forge",
            "modpack_instance": str(root.resolve()),
            "active_resource_packs": [
                "vanilla",
                "mod_resources",
                "file/gcstldz",
            ],
            "resource_pack": "gcstldz",
            "jars": jar_names,
            "resourcepacks": resource_pack_names,
            "gummervibe_block_palette": WorldConverter.MODPACK_BLOCK_IDS,
            "anomaly_blocks": anomaly_blocks,
            "building_blocks": {
                "concrete": "gummervibe:bricks_1",
                "brick": "gummervibe:bricks_2",
                "white_brick": "gummervibe:white_bricks",
                "wood": "gummervibe:wood_1",
                "metal": "gummervibe:metal_1",
                "door": "gummervibe:door_standart",
                "metal_door": "gummervibe:door_metal",
                "road": "gummervibe:floor_1",
            },
            "implementation_status": {
                "terrain": "implemented_by_heightmap_export",
                "vanilla_vegetation": "implemented_as_blocks",
                "gummervibe_buildings": "catalogued; mesh-voxel mapping in progress",
                "gummervibe_anomalies": "catalogued_and_mapped_to_existing_behaviour_blocks",
                "mob_and_weapon_objects": "excluded_until separate item/entity mapping is verified",
            },
            "anomaly_implementation_hint": {
                "electro": "gvb.jar: ElectroAnomalyBlock",
                "burner": "gvb.jar: HazardAnomalyBlock",
                "grinder": "gvb.jar: GrinderAnomalyBlock",
                "spatial": "gvb.jar: SpatialAnomalyBlock",
                "launch": "gvb.jar: LaunchAnomalyBlock",
                "glass_shards": "gvb.jar: GlassShardsAnomalyBlock",
                "chemical": "gvb.jar: HazardAnomalyBlock",
                "radiation": "gvb.jar: RadiationBlockHazard",
            },
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "status": "success",
            "output": str(output.resolve()),
            "minecraft": profile["minecraft"],
            "loader": profile["loader"],
            "jar_count": len(jar_names),
            "resource_pack_count": len(resource_pack_names),
            "anomaly_block_count": len(anomaly_blocks),
        }

    @staticmethod
    def select_world_partition_cells(
        index_path: str,
        layer: str,
        min_x: int,
        max_x: int,
        min_y: int,
        max_y: int,
    ) -> Dict[str, Any]:
        if layer not in WorldConverter.WORLD_CELL_LAYERS:
            raise ValueError(f"Unsupported World Partition layer: {layer}")
        if min_x > max_x or min_y > max_y:
            raise ValueError("World Partition bounds must be ordered minimum-to-maximum")

        source = Path(index_path)
        if not source.is_file():
            raise FileNotFoundError(f"World Partition package index not found: {index_path}")
        index = json.loads(source.read_text(encoding="utf-8"))
        packages = index.get("packages")
        if not isinstance(packages, list):
            raise ValueError("World Partition package index must contain a packages array")

        cell_pattern = re.compile(
            rf"/{re.escape(layer)}_L0_X(-?\d+)Y(-?\d+)(?:_DL[0-9A-F]+)?\.umap$",
            re.IGNORECASE,
        )
        selected = []
        for package in packages:
            if not isinstance(package, str):
                continue
            match = cell_pattern.search(package)
            if not match:
                continue
            x, y = map(int, match.groups())
            if min_x <= x <= max_x and min_y <= y <= max_y:
                selected.append(package)
        selected.sort(key=str.casefold)
        return {
            "status": "success" if selected else "empty",
            "index": str(source.resolve()),
            "layer": layer,
            "level": 0,
            "grid_bounds": {
                "min_x": min_x,
                "max_x": max_x,
                "min_y": min_y,
                "max_y": max_y,
            },
            "package_count": len(selected),
            "packages": selected,
        }

    @staticmethod
    def create_stalker_world_export_job(game_root: str, output_dir: str) -> Dict[str, Any]:
        root = Path(game_root)
        if not root.exists():
            raise FileNotFoundError(f"STALKER 2 root not found: {game_root}")

        stalker_root = root
        if (root / "Stalker2").exists():
            stalker_root = root / "Stalker2"

        paks = stalker_root / "Content" / "Paks"
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)

        pak_files = sorted(paks.glob("*.pak")) if paks.exists() else []
        utoc_files = sorted(paks.glob("*.utoc")) if paks.exists() else []
        ucas_files = sorted(paks.glob("*.ucas")) if paks.exists() else []

        fmodel_dir = Path(__file__).resolve().parents[2] / "components" / "FModel"
        fmodel_exe = fmodel_dir / "FModel.exe"
        cue4parse_project = Path(__file__).resolve().parents[2] / "tools" / "ue5" / "cue4parse_cli" / "Decod.Cue4Parse.csproj"
        ue4ss_mod = stalker_root / "Binaries" / "Win64" / "ue4ss" / "Mods" / "MapEditor"
        job = {
            "format": "decod-stalker-world-export-job-v1",
            "status": "ready_for_runtime_export",
            "game_root": str(stalker_root),
            "output_dir": str(output),
            "source_inventory": {
                "pak_count": len(pak_files),
                "utoc_count": len(utoc_files),
                "ucas_count": len(ucas_files),
                "largest_ucas": [
                    str(path)
                    for path in sorted(ucas_files, key=lambda item: item.stat().st_size, reverse=True)[:12]
                ],
            },
            "tools": {
                "repak": str(Path(__file__).resolve().parents[2] / "bin" / "repak.exe"),
                "fmodel": str(fmodel_exe),
                "fmodel_available": fmodel_exe.exists(),
                "cue4parse_project": str(cue4parse_project),
                "cue4parse_available": cue4parse_project.exists() and shutil.which("dotnet") is not None,
                "ue4ss_mod": str(ue4ss_mod),
                "ue4ss_mod_deployed": ue4ss_mod.exists(),
            },
            "automatic_steps": [
                "Run Decod's headless CUE4Parse scanner against Content/Paks to inventory .uasset/.umap package paths.",
                "Use world-cell-export to batch probe selected World Partition terrain, architecture, prop, tree, and foliage layers.",
                "Use landscape-heightmap-export on the terrain probe directory to stitch the exported height tiles.",
                "Launch STALKER 2 in the selected location.",
                "Open UE4SS console and run dumpworldassets.",
                "Convert output/stalker_world_dump.json with export_ue_actor_dump_minecraft.",
                "Apply an optional PNG/height grid through export_heightmap_minecraft.",
            ],
            "manual_steps": [
                "Select the exact Minecraft location/world and set origin coordinates.",
                "Choose Minecraft block replacements for exported UE actor classes.",
                "Voxelize/export static meshes at the chosen block scale.",
            ],
            "constraints": [
                "PAK/UCAS assets may require game-specific AES/key and mappings.",
                "CUE4Parse indexing is headless; parsing package contents can still require the matching AES key and .usmap mappings.",
                "A live UE4SS dump is required for loaded-world actor positions.",
                "No complete UE-to-Minecraft mesh conversion is claimed until source meshes are exported and tested.",
            ],
            "conversion_policy": {
                "terrain": "export from Landscape heightmaps",
                "vegetation": "replace tree meshes with vanilla log-and-leaf trees and other plants with vanilla Minecraft plants",
                "static_buildings_and_props": "export as geometry placements",
                "anomalies_and_behavioral_objects": "exclude from static conversion; catalog separately for Minecraft mod implementation",
            },
        }
        job_path = output / "stalker_world_export_job.json"
        job_path.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "status": "success",
            "job": str(job_path),
            "pak_count": len(pak_files),
            "utoc_count": len(utoc_files),
            "ucas_count": len(ucas_files),
            "fmodel_available": fmodel_exe.exists(),
            "cue4parse_available": cue4parse_project.exists() and shutil.which("dotnet") is not None,
            "ue4ss_mod_deployed": ue4ss_mod.exists(),
        }

    @staticmethod
    def scan_level_assets(source: str, filter_query: str = "") -> Dict[str, Any]:
        source_path = Path(source)
        if not source_path.exists():
            raise FileNotFoundError(f"World source not found: {source}")

        wanted = filter_query.lower().strip()
        categories = {
            "worldpartition": [],
            "maps": [],
            "landscape": [],
            "meshes": [],
            "materials": [],
        }
        if source_path.is_file():
            candidates = [source_path.name]
        else:
            candidates = [
                str(path.relative_to(source_path)).replace("\\", "/")
                for path in source_path.rglob("*")
                if path.is_file()
            ]

        for name in candidates:
            lower = name.lower()
            if wanted and wanted not in lower:
                continue
            if lower.endswith(".umap"):
                categories["maps"].append(name)
            elif "worldpartition" in lower:
                categories["worldpartition"].append(name)
            if "landscape" in lower or "terrain" in lower:
                categories["landscape"].append(name)
            if lower.endswith((".uasset", ".fbx", ".obj")) and "staticmesh" in lower:
                categories["meshes"].append(name)
            if lower.endswith((".uasset", ".png", ".tga", ".dds")) and "material" in lower:
                categories["materials"].append(name)

        counts = {key: len(value) for key, value in categories.items()}
        return {
            "status": "success",
            "source": str(source_path),
            "filter": filter_query,
            "counts": counts,
            "categories": categories,
            "recommended_next_step": (
                "Run scan_ue_iostore_assets on the game root or Content/Paks directory; "
                "use package_type='maps' and a location filter to find candidate .umap files."
            ),
        }

    @staticmethod
    def export_landscape_heightmap_from_probe(
        probe_report_path: str,
        output_path: str,
        bulk_path: str = "",
    ) -> Dict[str, Any]:
        report_path = Path(probe_report_path)
        if report_path.is_dir():
            return WorldConverter.export_landscape_heightmap_from_probe_directory(
                report_path,
                output_path,
            )
        if not report_path.is_file():
            raise FileNotFoundError(f"CUE4Parse probe report not found: {probe_report_path}")

        report = json.loads(report_path.read_text(encoding="utf-8"))
        probe = report.get("probe")
        if not isinstance(probe, dict) or probe.get("parse_status") != "success":
            parse_error = probe.get("parse_error") if isinstance(probe, dict) else None
            raise ValueError(f"Probe report does not contain a successfully parsed package: {parse_error or 'missing probe data'}")

        if bulk_path:
            bulk_file = Path(bulk_path)
        else:
            bulk_files = [
                Path(path)
                for path in probe.get("extracted_files", [])
                if Path(path).suffix.lower() == ".ubulk"
            ]
            if len(bulk_files) != 1:
                raise ValueError(
                    "Probe report must list exactly one extracted .ubulk file or bulk_path must be supplied"
                )
            bulk_file = bulk_files[0]
        if not bulk_file.is_file():
            raise FileNotFoundError(f"Landscape bulk data not found: {bulk_file}")
        bulk_data = bulk_file.read_bytes()

        details = probe.get("export_details") or []
        textures = {
            detail.get("name"): detail.get("data") or {}
            for detail in details
            if detail.get("type") == "Texture2D"
        }
        components = []
        for detail in details:
            if detail.get("type") != "LandscapeComponent":
                continue
            properties = (detail.get("data") or {}).get("Properties") or {}
            texture_ref = properties.get("HeightmapTexture") or {}
            object_name = texture_ref.get("ObjectName", "")
            if "'" in object_name:
                object_name = object_name.split("'", 1)[1].rsplit("'", 1)[0]
            texture_name = object_name.rsplit(".", 1)[-1]
            texture = textures.get(texture_name)
            if not texture:
                raise ValueError(f"Heightmap texture {texture_name!r} is missing from probe export details")
            if texture.get("PixelFormat") != "PF_B8G8R8A8":
                raise ValueError(
                    f"Unsupported Landscape heightmap pixel format: {texture.get('PixelFormat')}"
                )

            width = int(texture.get("SizeX", 0))
            height = int(texture.get("SizeY", 0))
            mips = texture.get("Mips") or []
            if width < 1 or height < 1 or not mips:
                raise ValueError(f"Heightmap texture {texture_name!r} has no usable mip data")
            mip_bulk = mips[0].get("BulkData") or {}
            offset_value = mip_bulk.get("OffsetInFile")
            offset = int(offset_value, 0) if isinstance(offset_value, str) else int(offset_value)
            size_on_disk = int(mip_bulk.get("SizeOnDisk", 0))
            required_size = width * height * 4
            if size_on_disk < required_size or offset < 0 or offset + required_size > len(bulk_data):
                raise ValueError(f"Heightmap texture {texture_name!r} bulk data is outside the .ubulk file")

            component_quads = int(properties.get("ComponentSizeQuads", 0))
            subsection_quads = int(properties.get("SubsectionSizeQuads", 0))
            subsection_count = int(properties.get("NumSubsections", 0))
            vertex_count = component_quads + 1
            if component_quads < 1 or subsection_quads < 1 or subsection_count < 1:
                raise ValueError(f"Landscape component {detail.get('name')} has invalid dimensions")
            if width != height or width != vertex_count + subsection_count - 1:
                raise ValueError(
                    f"Heightmap dimensions for {detail.get('name')} do not match its Landscape component"
                )

            duplicate_edges = {
                index * (subsection_quads + 1)
                for index in range(1, subsection_count)
            }
            if any(index >= width for index in duplicate_edges):
                raise ValueError(f"Landscape component {detail.get('name')} has an invalid subsection layout")

            def sample(pixel_x: int, pixel_y: int) -> int:
                pixel_offset = offset + (pixel_y * width + pixel_x) * 4
                red = bulk_data[pixel_offset + 2]
                green = bulk_data[pixel_offset + 1]
                return (red << 8) | green

            for edge in duplicate_edges:
                if any(sample(edge - 1, y) != sample(edge, y) for y in range(height)):
                    raise ValueError(f"Landscape heightmap {texture_name!r} has inconsistent subsection columns")
                if any(sample(x, edge - 1) != sample(x, edge) for x in range(width)):
                    raise ValueError(f"Landscape heightmap {texture_name!r} has inconsistent subsection rows")

            pixel_indices = [index for index in range(width) if index not in duplicate_edges]
            if len(pixel_indices) != vertex_count:
                raise ValueError(f"Landscape component {detail.get('name')} has an invalid heightmap vertex count")
            heights = [
                [sample(pixel_x, pixel_y) for pixel_x in pixel_indices]
                for pixel_y in pixel_indices
            ]
            components.append(
                {
                    "name": detail.get("name", ""),
                    "section_base_x": int(properties["SectionBaseX"]),
                    "section_base_y": int(properties["SectionBaseY"]),
                    "component_size_quads": component_quads,
                    "texture": texture_name,
                    "owner_actor": _landscape_owner_from_reference(
                        (properties.get("AttachParent") or {}).get("ObjectName", "")
                    ),
                    "heights": heights,
                }
            )

        if not components:
            raise ValueError("Probe report contains no LandscapeComponent exports")

        min_x = min(component["section_base_x"] for component in components)
        min_y = min(component["section_base_y"] for component in components)
        max_x = max(component["section_base_x"] + component["component_size_quads"] for component in components)
        max_y = max(component["section_base_y"] + component["component_size_quads"] for component in components)
        grid = [[None] * (max_x - min_x + 1) for _ in range(max_y - min_y + 1)]
        for component in components:
            for local_y, row in enumerate(component["heights"]):
                grid_y = component["section_base_y"] - min_y + local_y
                for local_x, height_value in enumerate(row):
                    grid_x = component["section_base_x"] - min_x + local_x
                    existing = grid[grid_y][grid_x]
                    if existing is not None and existing != height_value:
                        raise ValueError(
                            f"Landscape components disagree at section coordinate "
                            f"({min_x + grid_x}, {min_y + grid_y})"
                        )
                    grid[grid_y][grid_x] = height_value

        if any(value is None for row in grid for value in row):
            raise ValueError("Landscape components leave gaps in the reconstructed height grid")

        raw_min = min(min(row) for row in grid)
        raw_max = max(max(row) for row in grid)
        world_transform = _landscape_world_transform(
            details,
            components,
            min_x,
            min_y,
            raw_min,
            raw_max,
        )
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        result_data = {
            "format": "decod-landscape-heightmap-v1",
            "source_probe": str(report_path.resolve()),
            "bulk_file": str(bulk_file.resolve()),
            "height_encoding": "UE Landscape uint16: red channel high byte, green channel low byte",
            "height_units": "raw UE Landscape height values; not converted to Unreal centimeters",
            "section_origin": {"x": min_x, "y": min_y},
            "grid_size": {"width": len(grid[0]), "height": len(grid)},
            "raw_height_range": {
                "min": raw_min,
                "max": raw_max,
            },
            "world_transform": world_transform,
            "components": [
                {
                    key: value
                    for key, value in component.items()
                    if key not in {"heights", "owner_actor"}
                }
                for component in components
            ],
            "heightmap": grid,
        }
        output.write_text(json.dumps(result_data, ensure_ascii=False), encoding="utf-8")
        return {
            "status": "success",
            "output": str(output.resolve()),
            "grid_size": [len(grid), len(grid[0])],
            "component_count": len(components),
            "raw_height_range": [
                result_data["raw_height_range"]["min"],
                result_data["raw_height_range"]["max"],
            ],
            "height_units": result_data["height_units"],
            "world_transform": world_transform,
        }

    @staticmethod
    def export_landscape_heightmap_from_probe_directory(
        report_directory: Path,
        output_path: str,
    ) -> Dict[str, Any]:
        reports = sorted(report_directory.glob("*.json"))
        if not reports:
            raise ValueError(f"No per-package probe JSON files found in: {report_directory}")

        with tempfile.TemporaryDirectory(prefix="decod-landscape-") as temp_dir:
            tiles = []
            skipped_reports = []
            for index, report in enumerate(reports):
                report_data = json.loads(report.read_text(encoding="utf-8"))
                probe = report_data.get("probe")
                if not isinstance(probe, dict) or probe.get("parse_status") != "success":
                    parse_error = probe.get("parse_error") if isinstance(probe, dict) else None
                    raise ValueError(
                        f"Probe report {report.name} did not parse successfully: "
                        f"{parse_error or 'missing probe data'}"
                    )
                if not any(
                    detail.get("type") == "LandscapeComponent"
                    for detail in probe.get("export_details") or []
                ):
                    skipped_reports.append(report.name)
                    continue
                tile_path = Path(temp_dir) / f"{index:06d}.json"
                result = WorldConverter.export_landscape_heightmap_from_probe(
                    str(report),
                    str(tile_path),
                )
                tile_data = json.loads(tile_path.read_text(encoding="utf-8"))
                tiles.append((report, tile_data, result))
        if not tiles:
            raise ValueError(f"No Landscape components found in probe reports: {report_directory}")

        min_x = min(tile[1]["section_origin"]["x"] for tile in tiles)
        min_y = min(tile[1]["section_origin"]["y"] for tile in tiles)
        max_x = max(
            tile[1]["section_origin"]["x"] + tile[1]["grid_size"]["width"] - 1
            for tile in tiles
        )
        max_y = max(
            tile[1]["section_origin"]["y"] + tile[1]["grid_size"]["height"] - 1
            for tile in tiles
        )
        width = max_x - min_x + 1
        height = max_y - min_y + 1
        grid = [[None] * width for _ in range(height)]
        for report, tile, _result in tiles:
            origin_x = tile["section_origin"]["x"]
            origin_y = tile["section_origin"]["y"]
            for row_index, row in enumerate(tile["heightmap"]):
                target_y = origin_y - min_y + row_index
                for column_index, value in enumerate(row):
                    target_x = origin_x - min_x + column_index
                    existing = grid[target_y][target_x]
                    if existing is not None and existing != value:
                        raise ValueError(
                            f"Terrain probe reports disagree at section coordinate "
                            f"({min_x + target_x}, {min_y + target_y})"
                        )
                    grid[target_y][target_x] = value

        missing_samples = sum(value is None for row in grid for value in row)
        available_values = [value for row in grid for value in row if value is not None]
        reference_transform = tiles[0][1].get("world_transform")
        for _report, tile, _result in tiles[1:]:
            transform = tile.get("world_transform")
            if not reference_transform or not transform:
                raise ValueError("Every terrain probe must include a Landscape world transform")
            for axis, coordinate in (("x", "x"), ("y", "y")):
                expected_origin = (
                    reference_transform["unreal_origin_cm"][coordinate]
                    + (tile["section_origin"][coordinate] - tiles[0][1]["section_origin"][coordinate])
                    * reference_transform["cm_per_grid_sample"][coordinate]
                )
                actual_origin = transform["unreal_origin_cm"][coordinate]
                if abs(expected_origin - actual_origin) > 1.0:
                    raise ValueError(f"Terrain probe world origins do not align on the {axis.upper()} axis")
            if (
                transform["cm_per_grid_sample"] != reference_transform["cm_per_grid_sample"]
                or transform["landscape_scale_z_cm"] != reference_transform["landscape_scale_z_cm"]
            ):
                raise ValueError("Terrain probe reports use inconsistent Landscape scales")

        if not reference_transform:
            raise ValueError("Terrain probe reports do not contain Landscape world transforms")
        combined_transform = dict(reference_transform)
        combined_transform["unreal_origin_cm"] = dict(reference_transform["unreal_origin_cm"])
        combined_transform["unreal_origin_cm"]["x"] += (
            min_x - tiles[0][1]["section_origin"]["x"]
        ) * reference_transform["cm_per_grid_sample"]["x"]
        combined_transform["unreal_origin_cm"]["y"] += (
            min_y - tiles[0][1]["section_origin"]["y"]
        ) * reference_transform["cm_per_grid_sample"]["y"]
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        result_data = {
            "format": "decod-landscape-heightmap-v1",
            "source_probe_directory": str(report_directory.resolve()),
            "height_encoding": "UE Landscape uint16: red channel high byte, green channel low byte",
            "height_units": "raw UE Landscape height values; not converted to Unreal centimeters",
            "section_origin": {"x": min_x, "y": min_y},
            "grid_size": {"width": width, "height": height},
            "raw_height_range": {"min": min(available_values), "max": max(available_values)},
            "missing_sample_count": missing_samples,
            "world_transform": combined_transform,
            "source_probe_count": len(tiles),
            "skipped_probe_reports": skipped_reports,
            "components": [
                component
                for _report, tile, _result in tiles
                for component in tile["components"]
            ],
            "heightmap": grid,
        }
        output.write_text(json.dumps(result_data, ensure_ascii=False), encoding="utf-8")
        return {
            "status": "success",
            "output": str(output.resolve()),
            "grid_size": [height, width],
            "source_probe_count": len(tiles),
            "skipped_probe_reports": skipped_reports,
            "missing_sample_count": missing_samples,
            "raw_height_range": [
                result_data["raw_height_range"]["min"],
                result_data["raw_height_range"]["max"],
            ],
            "height_units": result_data["height_units"],
            "world_transform": combined_transform,
        }

    @staticmethod
    def _read_height_grid(input_path: str) -> List[List[float]]:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Height grid not found: {input_path}")

        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = data.get("heightmap") or data.get("grid") or data.get("heights")
            if not isinstance(data, list):
                raise ValueError("JSON heightmap must contain a heightmap/grid/heights array")
            return [[float(value) for value in row] for row in data]

        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.reader(handle))
            return [[float(value.strip()) for value in row if value.strip()] for row in rows]

        if path.suffix.lower() == ".png":
            try:
                from PIL import Image
            except ImportError as error:
                raise RuntimeError("Pillow is required for PNG heightmaps") from error
            image = Image.open(path).convert("L")
            pixels = list(image.getdata())
            width, height = image.size
            return [
                [float(pixels[row * width + column]) for column in range(width)]
                for row in range(height)
            ]

        raise ValueError("Height grid must be JSON, CSV, or PNG")

    @staticmethod
    def export_heightmap_mcfunction(
        heightmap_path: str,
        output_path: str,
        base_block: str = "minecraft:stone",
        surface_block: str = "minecraft:grass_block",
        z_scale: int = 1,
        x_origin: int = 0,
        y_origin: int = 64,
        z_origin: int = 0,
        vertical_offset: int = 0,
        png_height_scale: float = 0.25,
    ) -> Dict[str, Any]:
        grid = WorldConverter._read_height_grid(heightmap_path)
        if not grid or not grid[0]:
            raise ValueError("Height grid is empty")

        width = len(grid[0])
        if any(len(row) != width for row in grid):
            raise ValueError("All height-grid rows must have the same width")

        z_scale = max(1, int(z_scale))
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        commands: List[str] = []
        for row_index, row in enumerate(grid):
            z = z_origin + row_index * z_scale
            for column_index, raw_height in enumerate(row):
                x = x_origin + column_index
                height_scale = png_height_scale if Path(heightmap_path).suffix.lower() == ".png" else 1.0
                height = int(math.floor(raw_height * height_scale)) + vertical_offset
                for y in range(y_origin, y_origin + max(1, height)):
                    block = surface_block if y == y_origin + height - 1 else base_block
                    commands.append(f"setblock {x} {y} {z} {block}")

        output.write_text("\n".join(commands) + ("\n" if commands else ""), encoding="utf-8")
        return {
            "status": "success",
            "input": str(Path(heightmap_path)),
            "output": str(output),
            "grid_size": [len(grid), width],
            "minecraft_origin": [x_origin, y_origin, z_origin],
            "setblock_commands": len(commands),
            "surface_block": surface_block,
            "base_block": base_block,
        }

    @staticmethod
    def export_ue_actor_dump_minecraft(
        dump_path: str,
        output_path: str,
        x_origin: int = 0,
        y_origin: int = 64,
        z_origin: int = 0,
        uu_per_meter: float = 100.0,
        blocks_per_meter: float = 1.0,
        manifest_only: bool = False,
    ) -> Dict[str, Any]:
        path = Path(dump_path)
        if not path.exists():
            raise FileNotFoundError(f"UE world dump not found: {dump_path}")
        dump = json.loads(path.read_text(encoding="utf-8"))
        actors = dump.get("actors", [])
        if not isinstance(actors, list):
            raise ValueError("UE world dump must contain an 'actors' array")

        def actor_text(actor: Dict[str, Any]) -> str:
            return " ".join([
                str(actor.get("name", "")),
                str(actor.get("full_name", "")),
                str(actor.get("class_name", "")),
                str(actor.get("mesh", "")),
                str(actor.get("mesh_name", "")),
                str(actor.get("asset_path", "")),
            ]).lower()

        def classify(actor: Dict[str, Any]) -> str:
            text = actor_text(actor)
            anomaly_palette = (
                ("electro", ("electro", "electric")),
                ("burner", ("burner", "fire", "heat", "zharka")),
                ("grinder", ("grinder", "meat", "miasorubka")),
                ("spatial", ("spatial", "space", "prostorova")),
                ("launch", ("launch", "tramplin", "jump")),
                ("glass_shards", ("glass", "shard", "sklyani")),
                ("chemical", ("chemical", "khimichna", "acid")),
                ("radiation", ("radiation", "radioactive")),
            )
            for category, tokens in anomaly_palette:
                if any(token in text for token in tokens):
                    return f"gummervibe:{WorldConverter.MODPACK_BLOCK_IDS[category].split(':', 1)[1]}"
            if "flower" in text:
                return "minecraft:poppy"
            if "dead" in text and any(token in text for token in ("bush", "plant", "foliage")):
                return "minecraft:dead_bush"
            if any(token in text for token in ("grass", "fern", "plant", "foliage", "bush", "shrub")):
                return "minecraft:fern"
            if any(token in text for token in ("road", "asphalt", "concrete", "street")):
                return "gummervibe:floor_1"
            if any(token in text for token in ("metal_door", "bunker_door")):
                return WorldConverter.MODPACK_BLOCK_IDS["metal_door"]
            if "door" in text:
                return WorldConverter.MODPACK_BLOCK_IDS["door"]
            if any(token in text for token in ("metal", "steel", "industrial")):
                return WorldConverter.MODPACK_BLOCK_IDS["metal"]
            if any(token in text for token in ("wood", "timber", "log", "cottage")):
                return WorldConverter.MODPACK_BLOCK_IDS["wood"]
            if any(token in text for token in ("house", "building", "wall", "brick", "concrete")):
                return WorldConverter.MODPACK_BLOCK_IDS["brick"]
            if any(token in text for token in ("water", "pond", "river")):
                return "minecraft:water"
            return "minecraft:light_gray_concrete"

        def tree_blocks(tree_text: str, x: int, y: int, z: int) -> List[Dict[str, Any]]:
            if "birch" in tree_text:
                species = "birch"
            elif any(token in tree_text for token in ("spruce", "pine", "conifer")) or re.search(
                r"(?:^|[^a-z])fir(?:$|[^a-z])",
                tree_text,
            ):
                species = "spruce"
            elif any(token in tree_text for token in ("jungle", "palm")):
                species = "jungle"
            else:
                species = "oak"
            log = f"minecraft:{species}_log"
            leaves = f"minecraft:{species}_leaves[distance=1,persistent=true]"
            blocks = [
                {"block": log, "x": x, "y": y + offset, "z": z}
                for offset in range(4)
            ]
            for dx in range(-2, 3):
                for dz in range(-2, 3):
                    if abs(dx) == 2 and abs(dz) == 2:
                        continue
                    blocks.append({"block": leaves, "x": x + dx, "y": y + 3, "z": z + dz})
            for dx in range(-1, 2):
                for dz in range(-1, 2):
                    if dx or dz:
                        blocks.append({"block": leaves, "x": x + dx, "y": y + 4, "z": z + dz})
            blocks.append({"block": leaves, "x": x, "y": y + 5, "z": z})
            return blocks

        voxels_by_position: Dict[tuple, Dict[str, Any]] = {}
        tree_count = 0
        vegetation_actor_count = 0
        for actor in actors:
            transform = actor.get("transform")
            if not isinstance(transform, dict):
                continue
            scale = blocks_per_meter / uu_per_meter
            x = int(round(float(transform["x"]) * scale))
            y = int(round(float(transform["z"]) * scale))
            z = int(round(float(transform["y"]) * scale))
            text = actor_text(actor)
            is_tree = any(
                token in text
                for token in ("tree", "birch", "spruce", "pine", "conifer", "palm")
            ) or re.search(r"(?:^|[^a-z])fir(?:$|[^a-z])", text) is not None
            is_vegetation = is_tree or any(
                token in text
                for token in ("bush", "shrub", "foliage", "grass", "plant", "fern", "flower")
            )
            if is_vegetation:
                vegetation_actor_count += 1
            blocks = (
                tree_blocks(text, x, y, z)
                if is_tree
                else [{
                    "block": classify(actor),
                    "x": x,
                    "y": y,
                    "z": z,
                }]
            )
            if is_tree:
                tree_count += 1

            for block in blocks:
                position = (block["x"], block["y"], block["z"])
                voxel = {
                    "name": actor.get("name"),
                    "class": actor.get("class_name"),
                    **block,
                }
                previous = voxels_by_position.get(position)
                if previous is None or block["block"].endswith("_log"):
                    voxels_by_position[position] = voxel

        voxels = list(voxels_by_position.values())

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        manifest = {
            "format": "decod-minecraft-world-v1",
            "source": str(path),
            "origin": [x_origin, y_origin, z_origin],
            "units": {"blocks_per_meter": blocks_per_meter, "uu_per_meter": uu_per_meter},
            "limitations": [
                "Actor dump preserves positions and rotations/scales only.",
                "Real building meshes must be exported from UE/FModel and attached through an asset manifest.",
                "Trees use approximate vanilla log-and-leaf shapes; their original meshes are not exported.",
            ],
            "voxels": voxels,
        }
        manifest_path = output.with_suffix(".json")
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        commands: List[str] = []
        if not manifest_only:
            for voxel in voxels:
                commands.append(
                    f"setblock {voxel['x'] + x_origin} {voxel['y'] + y_origin} "
                    f"{voxel['z'] + z_origin} {voxel['block']}"
                )
            output.write_text("\n".join(commands) + ("\n" if commands else ""), encoding="utf-8")

        return {
            "status": "success",
            "source": str(path),
            "manifest": str(manifest_path),
            "mcfunction": None if manifest_only else str(output),
            "actor_count": len(actors),
            "voxel_count": len(voxels),
            "tree_count": tree_count,
            "vegetation_actor_count": vegetation_actor_count,
            "setblock_commands": len(commands),
            "minecraft_origin": [x_origin, y_origin, z_origin],
        }

    @staticmethod
    def export_voxel_manifest_mcfunction(
        manifest_path: str,
        output_path: str,
        x_origin: int = 0,
        y_origin: int = 64,
        z_origin: int = 0,
    ) -> Dict[str, Any]:
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"Voxel manifest not found: {manifest_path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        voxels = data.get("voxels", data) if isinstance(data, dict) else data
        if not isinstance(voxels, list):
            raise ValueError("Voxel manifest must be a JSON array or contain a 'voxels' array")

        palette = data.get("palette", {}) if isinstance(data, dict) else {}
        commands: List[str] = []
        for voxel in voxels:
            if not isinstance(voxel, dict):
                continue
            x = int(voxel["x"]) + x_origin
            y = int(voxel["y"]) + y_origin
            z = int(voxel["z"]) + z_origin
            block = voxel.get("block") or palette.get(str(voxel.get("color")), "minecraft:stone")
            if block:
                commands.append(f"setblock {x} {y} {z} {block}")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(commands) + ("\n" if commands else ""), encoding="utf-8")
        return {
            "status": "success",
            "input": str(path),
            "output": str(output),
            "voxel_count": len(voxels),
            "setblock_commands": len(commands),
            "minecraft_origin": [x_origin, y_origin, z_origin],
        }
