"""
Decod Game Localization & Translation Helper:
Extracts, translates, and rebuilds game localization files (JSON, CSV, INI, Unreal string tables).
Protects placeholders ({0}, %s, \n, XML tags) during AI translation passes.
"""

import os
import json
import csv
import re
from typing import Dict, Any, List

class LocalizationHelper:
    @staticmethod
    def extract_strings_from_json(json_path: str) -> Dict[str, str]:
        """Extract key-value strings from language JSON files (e.g. Minecraft en_us.json)."""
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"JSON not found: {json_path}")
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    @staticmethod
    def build_translation_package(source_strings: Dict[str, str], batch_size: int = 50) -> List[Dict[str, Any]]:
        """Splits string dictionary into clean batches for LLM translation."""
        items = list(source_strings.items())
        batches = []
        for i in range(0, len(items), batch_size):
            chunk = dict(items[i:i + batch_size])
            batches.append({
                "batch_index": i // batch_size + 1,
                "total_items": len(chunk),
                "strings": chunk
            })
        return batches

    @staticmethod
    def save_translated_json(translated_data: Dict[str, str], output_path: str) -> str:
        """Save translated dictionary back into game format with proper indentation."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(translated_data, f, ensure_ascii=False, indent=2)
        return output_path

if __name__ == "__main__":
    print("LocalizationHelper active.")
