import json
import tempfile
from pathlib import Path

from engines.ue5.world_converter import WorldConverter


def test_modpack_palette_contains_existing_gummervibe_anomalies():
    palette = WorldConverter.MODPACK_BLOCK_IDS
    assert palette["electro"] == "gummervibe:anomaly_elektro"
    assert palette["burner"] == "gummervibe:anomaly_zharka"
    assert palette["grinder"] == "gummervibe:anomaly_miasorubka"
    assert palette["spatial"] == "gummervibe:anomaly_prostorova"


def test_gummervibe_export_profile(tmp_path):
    instance = r"C:\Users\knyaz\Documents\GummerCraft\instances\staldayz\minecraft"
    if not Path(instance).is_dir():
        instance = str(tmp_path)
    result = WorldConverter.build_gummervibe_export_profile(
        instance,
        str(tmp_path / "profile.json"),
    )
    assert result["status"] == "success"


def test_heightmap_export():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        heightmap = root / "height.json"
        heightmap.write_text(json.dumps({"heightmap": [[64, 65], [66, 67]]}), encoding="utf-8")
        output = root / "terrain.mcfunction"
        result = WorldConverter.export_heightmap_mcfunction(
            str(heightmap),
            str(output),
            y_origin=64,
        )
        assert result["status"] == "success"
        assert result["setblock_commands"] > 0
        assert "setblock " in output.read_text(encoding="utf-8")


def test_landscape_heightmap_from_probe():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        bulk_path = root / "terrain.ubulk"
        pixels = bytearray()
        for y in range(4):
            for x in range(4):
                source_x = x if x < 2 else x - 1
                source_y = y if y < 2 else y - 1
                height = 32768 + source_y * 10 + source_x
                pixels.extend((0, height & 0xFF, height >> 8, 255))
        bulk_path.write_bytes(pixels)

        report_path = root / "probe.json"
        report_path.write_text(json.dumps({
            "probe": {
                "parse_status": "success",
                "extracted_files": [str(bulk_path)],
                "export_details": [
                    {
                        "name": "LandscapeComponent_0",
                        "type": "LandscapeComponent",
                        "data": {
                            "Properties": {
                                "SectionBaseX": 10,
                                "SectionBaseY": 20,
                                "ComponentSizeQuads": 2,
                                "SubsectionSizeQuads": 1,
                                "NumSubsections": 2,
                                "HeightmapTexture": {
                                    "ObjectName": "Texture2D'Package:Level.Texture2D_0'",
                                },
                                "AttachParent": {
                                    "ObjectName": "SceneComponent'WorldMap:PersistentLevel.LandscapeStreamingProxy_0.RootComponent0'",
                                },
                            },
                        },
                    },
                    {
                        "name": "LandscapeStreamingProxy_0",
                        "type": "LandscapeStreamingProxy",
                        "data": {
                            "Properties": {
                                "RootComponent": {
                                    "ObjectName": "SceneComponent'WorldMap:PersistentLevel.LandscapeStreamingProxy_0.RootComponent0'",
                                },
                                "LandscapeSectionOffset": {"X": 10, "Y": 20},
                            },
                        },
                    },
                    {
                        "name": "RootComponent0",
                        "type": "SceneComponent",
                        "data": {
                            "Name": "RootComponent0",
                            "Outer": "LandscapeStreamingProxy_0",
                            "Properties": {
                                "RelativeLocation": {"X": 1000, "Y": 2000, "Z": 300},
                                "RelativeScale3D": {"X": 100, "Y": 100, "Z": 50},
                            },
                        },
                    },
                    {
                        "name": "Texture2D_0",
                        "type": "Texture2D",
                        "data": {
                            "PixelFormat": "PF_B8G8R8A8",
                            "SizeX": 4,
                            "SizeY": 4,
                            "Mips": [{
                                "BulkData": {
                                    "OffsetInFile": "0x0",
                                    "SizeOnDisk": len(pixels),
                                    "ElementCount": len(pixels),
                                },
                            }],
                        },
                    },
                ],
            },
        }), encoding="utf-8")

        output_path = root / "heightmap.json"
        result = WorldConverter.export_landscape_heightmap_from_probe(
            str(report_path),
            str(output_path),
        )
        exported = json.loads(output_path.read_text(encoding="utf-8"))
        assert result["status"] == "success"
        assert result["grid_size"] == [3, 3]
        assert exported["heightmap"] == [
            [32768, 32769, 32770],
            [32778, 32779, 32780],
            [32788, 32789, 32790],
        ]
        assert exported["world_transform"]["unreal_origin_cm"] == {
            "x": 1000.0,
            "y": 2000.0,
            "z": 300.0,
        }
        assert exported["world_transform"]["height_cm_range"] == {
            "min": 300.0,
            "max": 308.59375,
        }


def test_stitch_landscape_heightmap_probe_directory():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)

        def write_probe(name, section_x, location_x, values):
            bulk_path = root / f"{name}.ubulk"
            pixels = bytearray()
            for value in values:
                pixels.extend((0, value & 0xFF, value >> 8, 255))
            bulk_path.write_bytes(pixels)

            probe_dir = root / "probes"
            probe_dir.mkdir(exist_ok=True)
            report_path = probe_dir / f"{name}.json"
            report_path.write_text(json.dumps({
                "probe": {
                    "parse_status": "success",
                    "extracted_files": [str(bulk_path)],
                    "export_details": [
                        {
                            "name": f"LandscapeComponent_{name}",
                            "type": "LandscapeComponent",
                            "data": {"Properties": {
                                "SectionBaseX": section_x,
                                "SectionBaseY": 20,
                                "ComponentSizeQuads": 1,
                                "SubsectionSizeQuads": 1,
                                "NumSubsections": 1,
                                "HeightmapTexture": {
                                    "ObjectName": f"Texture2D'Package:Level.Texture_{name}'",
                                },
                                "AttachParent": {
                                    "ObjectName": f"SceneComponent'WorldMap:PersistentLevel.Proxy_{name}.Root_{name}'",
                                },
                            }},
                        },
                        {
                            "name": f"Proxy_{name}",
                            "type": "LandscapeStreamingProxy",
                            "data": {"Properties": {
                                "RootComponent": {
                                    "ObjectName": f"SceneComponent'WorldMap:PersistentLevel.Proxy_{name}.Root_{name}'",
                                },
                                "LandscapeSectionOffset": {"X": section_x, "Y": 20},
                            }},
                        },
                        {
                            "name": f"Root_{name}",
                            "type": "SceneComponent",
                            "data": {
                                "Name": f"Root_{name}",
                                "Outer": f"Proxy_{name}",
                                "Properties": {
                                    "RelativeLocation": {"X": location_x, "Y": 2000, "Z": 300},
                                    "RelativeScale3D": {"X": 100, "Y": 100, "Z": 50},
                                },
                            },
                        },
                        {
                            "name": f"Texture_{name}",
                            "type": "Texture2D",
                            "data": {
                                "PixelFormat": "PF_B8G8R8A8",
                                "SizeX": 2,
                                "SizeY": 2,
                                "Mips": [{"BulkData": {
                                    "OffsetInFile": "0x0",
                                    "SizeOnDisk": len(pixels),
                                    "ElementCount": len(pixels),
                                }}],
                            },
                        },
                    ],
                },
            }), encoding="utf-8")
            return report_path.parent

        probe_directory = write_probe("west", 10, 1000, [32768, 32769, 32778, 32779])
        write_probe("east", 11, 1100, [32769, 32770, 32779, 32780])
        (probe_directory / "empty.json").write_text(json.dumps({
            "probe": {
                "parse_status": "success",
                "extracted_files": [],
                "export_details": [],
            },
        }), encoding="utf-8")
        output_path = root / "stitched-heightmap.json"

        result = WorldConverter.export_landscape_heightmap_from_probe_directory(
            probe_directory,
            str(output_path),
        )
        exported = json.loads(output_path.read_text(encoding="utf-8"))
        assert result["status"] == "success"
        assert result["source_probe_count"] == 2
        assert result["skipped_probe_reports"] == ["empty.json"]
        assert result["grid_size"] == [2, 3]
        assert exported["heightmap"] == [
            [32768, 32769, 32770],
            [32778, 32779, 32780],
        ]
        assert exported["missing_sample_count"] == 0
        assert exported["world_transform"]["unreal_origin_cm"]["x"] == 1000.0


def test_png_heightmap_export():
    from PIL import Image
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        heightmap = root / "height.png"
        Image.new("L", (2, 2), 64).save(heightmap)
        output = root / "terrain.mcfunction"
        result = WorldConverter.export_heightmap_minecraft(
            str(heightmap),
            str(output),
            y_origin=64,
        ) if hasattr(WorldConverter, "export_heightmap_minecraft") else WorldConverter.export_heightmap_mcfunction(
            str(heightmap),
            str(output),
            y_origin=64,
        )
        assert result["status"] == "success"
        assert result["setblock_commands"] > 0


def test_actor_dump_export():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        dump = root / "world.json"
        dump.write_text(json.dumps({
            "format": "decod-ue-world-v1",
            "actors": [{
                "name": "House_01",
                "full_name": "/Game/Buildings/House_01",
                "class_name": "StaticMeshActor",
                "transform": {"x": 100, "y": 200, "z": 300},
            }],
        }), encoding="utf-8")
        output = root / "actors.mcfunction"
        result = WorldConverter.export_ue_actor_dump_minecraft(
            str(dump),
            str(output),
            y_origin=64,
        )
        manifest = root / "actors.json"
        assert result["actor_count"] == 1
        assert result["voxel_count"] == 1
        assert manifest.exists()
        assert "setblock " in output.read_text(encoding="utf-8")


def test_actor_dump_uses_vanilla_wood_and_leaves_for_trees():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        dump = root / "vegetation-dump.json"
        dump.write_text(json.dumps({
            "actors": [
                {
                    "name": "SM_env_pine_tree_01",
                    "class_name": "StaticMeshActor",
                    "transform": {"x": 100, "y": 200, "z": 300},
                },
                {
                    "name": "fern_patch",
                    "class_name": "StaticMeshActor",
                    "transform": {"x": 0, "y": 0, "z": 0},
                },
            ],
        }), encoding="utf-8")
        output = root / "vegetation.mcfunction"

        result = WorldConverter.export_ue_actor_dump_minecraft(
            str(dump),
            str(output),
            y_origin=64,
        )
        manifest = json.loads((root / "vegetation.json").read_text(encoding="utf-8"))
        tree_voxels = [
            voxel for voxel in manifest["voxels"]
            if voxel["name"] == "SM_env_pine_tree_01"
        ]
        tree_blocks = {voxel["block"] for voxel in tree_voxels}
        commands = output.read_text(encoding="utf-8")

        assert result["tree_count"] == 1
        assert result["vegetation_actor_count"] == 2
        assert tree_blocks == {
            "minecraft:spruce_log",
            "minecraft:spruce_leaves[distance=1,persistent=true]",
        }
        assert len(tree_voxels) > 4
        assert any(voxel["block"] == "minecraft:fern" for voxel in manifest["voxels"])
        assert "minecraft:spruce_log" in commands
        assert "minecraft:spruce_leaves[distance=1,persistent=true]" in commands


def test_stalker_world_export_job():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        game_root = root / "Stalker2"
        paks = game_root / "Content" / "Paks"
        paks.mkdir(parents=True)
        (paks / "pakchunk0-Windows.pak").write_bytes(b"pak")
        (paks / "global.utoc").write_bytes(b"utoc")
        (paks / "global.ucas").write_bytes(b"ucas-data")
        output = root / "export"

        result = WorldConverter.create_stalker_world_export_job(str(root), str(output))

        job = json.loads((output / "stalker_world_export_job.json").read_text(encoding="utf-8"))
        assert result["status"] == "success"
        assert result["pak_count"] == 1
        assert result["utoc_count"] == 1
        assert result["ucas_count"] == 1
        assert job["source_inventory"]["largest_ucas"]
        assert job["status"] == "ready_for_runtime_export"
        assert job["tools"]["cue4parse_available"]
        assert any("dumpworldassets" in step for step in job["automatic_steps"])


def test_select_world_partition_cells_by_layer_and_grid_bounds():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        index_path = root / "cells.json"
        index_path.write_text(json.dumps({
            "packages": [
                "Stalker2/Content/Maps/_Generated_/Terrain_L0_X-1Y2.umap",
                "Stalker2/Content/Maps/_Generated_/Terrain_L0_X0Y2.umap",
                "Stalker2/Content/Maps/_Generated_/Terrain_L0_X0Y2_DL8B57CCED.umap",
                "Stalker2/Content/Maps/_Generated_/Terrain_L1_X0Y2.umap",
                "Stalker2/Content/Maps/_Generated_/Props_L0_X0Y2.umap",
            ],
        }), encoding="utf-8")

        result = WorldConverter.select_world_partition_cells(
            str(index_path),
            "Terrain",
            min_x=-1,
            max_x=0,
            min_y=2,
            max_y=2,
        )
        assert result["package_count"] == 3
        assert all("/Terrain_L0_" in path for path in result["packages"])


if __name__ == "__main__":
    test_heightmap_export()
    test_landscape_heightmap_from_probe()
    test_png_heightmap_export()
    test_actor_dump_export()
    test_stalker_world_export_job()
    test_select_world_partition_cells_by_layer_and_grid_bounds()
    print("World converter tests passed")
