import json
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
import unittest
from unittest.mock import patch

from engines.ue5.cue4parse_helper import scan_ue_iostore_assets


class Cue4ParseHelperTests(unittest.TestCase):
    def test_scan_resolves_game_paks_and_returns_cli_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paks = root / "Stalker2" / "Content" / "Paks"
            paks.mkdir(parents=True)
            (paks / "global.utoc").write_bytes(b"utoc")
            summary = {"status": "success", "package_count": 12, "output": str(root / "index.json")}

            with patch(
                "engines.ue5.cue4parse_helper.subprocess.run",
                return_value=CompletedProcess(args=[], returncode=0, stdout=json.dumps(summary), stderr=""),
            ) as run:
                result = scan_ue_iostore_assets(
                    str(root),
                    str(root / "index.json"),
                    filter_query="Lesser",
                    max_results=25,
                    probe_asset="Stalker2/Content/Maps/TestMap",
                    package_type="maps",
                    extract_dir=str(root / "assets"),
                )

            self.assertEqual(result, summary)
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--") + 1], str(paks.resolve()))
            self.assertEqual(
                command[-4:],
                ["25", "Stalker2/Content/Maps/TestMap", "maps", str(root / "assets")],
            )
            self.assertEqual(command[command.index("--") + 3], "GAME_UE5_5")

    def test_scan_surfaces_cue4parse_process_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pakchunk0.pak").write_bytes(b"pak")

            with patch(
                "engines.ue5.cue4parse_helper.subprocess.run",
                return_value=CompletedProcess(args=[], returncode=1, stdout="compiler details", stderr="build failed"),
            ):
                with self.assertRaisesRegex(RuntimeError, "compiler details"):
                    scan_ue_iostore_assets(str(root), str(root / "index.json"))

    def test_scan_rejects_missing_archive_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(FileNotFoundError, "No .utoc or .pak"):
                scan_ue_iostore_assets(temp, str(Path(temp) / "index.json"))

    def test_extract_requires_a_probe_asset(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "probe_asset is required"):
                scan_ue_iostore_assets(
                    temp,
                    str(Path(temp) / "index.json"),
                    extract_dir=str(Path(temp) / "assets"),
                )

    def test_batch_probe_writes_manifest_and_uses_one_cli_process(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paks = root / "Content" / "Paks"
            paks.mkdir(parents=True)
            (paks / "global.utoc").write_bytes(b"utoc")
            summary = {"status": "success", "probe_status": "parsed"}

            def run_cli(command, **_kwargs):
                manifest = Path(command[command.index("--") + 6].removeprefix("@batch:"))
                self.assertEqual(
                    json.loads(manifest.read_text(encoding="utf-8")),
                    ["Terrain_L0_X0Y0", "Architecture_L0_X0Y0"],
                )
                self.assertEqual(command[-1], str(root / "assets"))
                return CompletedProcess(args=command, returncode=0, stdout=json.dumps(summary), stderr="")

            with patch("engines.ue5.cue4parse_helper.subprocess.run", side_effect=run_cli) as run:
                result = scan_ue_iostore_assets(
                    str(root),
                    str(root / "batch.json"),
                    batch_probe_assets=[
                        "Terrain_L0_X0Y0",
                        "Architecture_L0_X0Y0",
                        "Terrain_L0_X0Y0",
                    ],
                    extract_dir=str(root / "assets"),
                )

            self.assertEqual(result, summary)
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
