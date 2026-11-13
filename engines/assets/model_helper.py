"""
Decod 3D Model Inspector & Converter:
Allows AI agents to inspect, manipulate, and convert 3D model formats.
Supports:
1. Wavefront .OBJ (read, transform, scale, center, export).
2. Minecraft JSON block/item models (read, generate, edit cubes, UVs, textures).
3. glTF / GLB structural inspection.
"""

import os
import json
from typing import Dict, Any, List, Tuple

class Model3DHelper:
    @staticmethod
    def inspect_obj(obj_path: str) -> Dict[str, Any]:
        """Inspect and parse a Wavefront .obj file."""
        if not os.path.exists(obj_path):
            raise FileNotFoundError(f"OBJ file not found: {obj_path}")

        vertices = []
        faces = []
        materials = set()

        with open(obj_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("v "):
                    parts = line.split()[1:4]
                    vertices.append([float(p) for p in parts])
                elif line.startswith("f "):
                    faces.append(line.split()[1:])
                elif line.startswith("usemtl "):
                    materials.add(line.split()[1])

        # Calculate bounding box
        bbox = {"min": [0, 0, 0], "max": [0, 0, 0], "dimensions": [0, 0, 0]}
        if vertices:
            xs = [v[0] for v in vertices]
            ys = [v[1] for v in vertices]
            zs = [v[2] for v in vertices]
            bbox = {
                "min": [round(min(xs), 3), round(min(ys), 3), round(min(zs), 3)],
                "max": [round(max(xs), 3), round(max(ys), 3), round(max(zs), 3)],
                "dimensions": [round(max(xs) - min(xs), 3), round(max(ys) - min(ys), 3), round(max(zs) - min(zs), 3)]
            }

        return {
            "file": obj_path,
            "format": "Wavefront OBJ",
            "vertex_count": len(vertices),
            "face_count": len(faces),
            "materials": list(materials),
            "bounding_box": bbox,
            "sample_vertices": vertices[:5]
        }

    @staticmethod
    def create_minecraft_block_model(name: str, texture: str, elements: List[dict] = None) -> Dict[str, Any]:
        """Generate a valid Minecraft JSON block model."""
        if elements is None:
            # Default standard 16x16x16 cube
            elements = [
                {
                    "from": [0, 0, 0],
                    "to": [16, 16, 16],
                    "faces": {
                        "down":  {"uv": [0, 0, 16, 16], "texture": "#all", "cullface": "down"},
                        "up":    {"uv": [0, 0, 16, 16], "texture": "#all", "cullface": "up"},
                        "north": {"uv": [0, 0, 16, 16], "texture": "#all", "cullface": "north"},
                        "south": {"uv": [0, 0, 16, 16], "texture": "#all", "cullface": "south"},
                        "west":  {"uv": [0, 0, 16, 16], "texture": "#all", "cullface": "west"},
                        "east":  {"uv": [0, 0, 16, 16], "texture": "#all", "cullface": "east"}
                    }
                }
            ]

        model = {
            "parent": "block/block",
            "textures": {
                "particle": texture,
                "all": texture
            },
            "elements": elements
        }
        return model

    @staticmethod
    def scale_obj_model(input_obj: str, output_obj: str, scale_factor: float) -> Dict[str, Any]:
        """Scale an OBJ model by a factor and write to output."""
        if not os.path.exists(input_obj):
            raise FileNotFoundError(f"Input OBJ not found: {input_obj}")

        out_lines = []
        v_count = 0
        with open(input_obj, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("v "):
                    parts = line.strip().split()
                    x, y, z = float(parts[1]) * scale_factor, float(parts[2]) * scale_factor, float(parts[3]) * scale_factor
                    out_lines.append(f"v {x:.4f} {y:.4f} {z:.4f}\n")
                    v_count += 1
                else:
                    out_lines.append(line)

        with open(output_obj, "w", encoding="utf-8") as f:
            f.writelines(out_lines)

        return {
            "status": "success",
            "input": input_obj,
            "output": output_obj,
            "scale_factor": scale_factor,
            "vertices_modified": v_count
        }

if __name__ == "__main__":
    import sys
    print("Model3DHelper active.")
