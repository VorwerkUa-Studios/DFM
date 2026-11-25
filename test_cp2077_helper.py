import tempfile
from pathlib import Path

from engines.redengine.cp2077_helper import (
    detect_cp2077,
    inventory_cp2077_mods,
    inspect_cp2077_archive,
    scaffold_cp2077_mod,
    patch_cp2077_text_file,
    get_cp2077_ecosystem,
    inspect_cp2077_project,
    get_cp2077_platform_status,
)


def test_cp2077_helper():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        (root / "bin" / "x64").mkdir(parents=True)
        (root / "archive" / "pc" / "content").mkdir(parents=True)
        (root / "archive" / "pc" / "mod").mkdir(parents=True)
        (root / "bin" / "x64" / "Cyberpunk2077.exe").write_bytes(b"test")
        (root / "archive" / "pc" / "content" / "basegame.archive").write_bytes(b"REDarchive-header")

        detected = detect_cp2077(str(root))
        assert detected["engine"] == "redengine"
        assert detected["archive_count"] == 1
        assert detected["executable"].endswith("Cyberpunk2077.exe")

        inventory = inventory_cp2077_mods(str(root))
        assert inventory["status"] == "ok"

        inspected = inspect_cp2077_archive(str(root / "archive" / "pc" / "content" / "basegame.archive"))
        assert inspected["size_bytes"] > 0

        scaffold = scaffold_cp2077_mod(str(root / "generated"), "Test Mod", "cet")
        init_lua = Path(scaffold["created"][0])
        assert init_lua.name == "init.lua"
        assert init_lua.exists()

        patched = patch_cp2077_text_file(
            str(init_lua),
            {"print(\"[Test Mod] initialized\")": "print(\"[Patched] initialized\")"},
        )
        assert patched["changed"] is True
        assert patched["backup"]
        assert "Patched" in init_lua.read_text(encoding="utf-8")

        ecosystem = get_cp2077_ecosystem(category="audio_pipeline")
        ids = {item["id"] for item in ecosystem["libraries"]}
        assert {"wwise", "audioweaver"}.issubset(ids)

        project = root / "audio-mod"
        (project / "r6" / "tweaks").mkdir(parents=True)
        (project / "r6" / "tweaks" / "audio.yaml").write_text("test: 1\n", encoding="utf-8")
        (project / "source").mkdir()
        (project / "source" / "dialogue.wem").write_bytes(b"test")
        inspection = inspect_cp2077_project(str(project))
        detected_ids = {item["id"] for item in inspection["detected"]}
        assert {"tweakxl", "wwise", "audioweaver"}.issubset(detected_ids)

        platform_status = get_cp2077_platform_status()
        assert platform_status["platform"] in {"windows", "linux"}
        assert "tools" in platform_status


if __name__ == "__main__":
    test_cp2077_helper()
    print("CP2077 helper tests passed")
