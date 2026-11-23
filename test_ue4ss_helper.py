import tempfile
import unittest
from pathlib import Path

from engines.ue5.ue4ss_helper import enable_mod, list_mods, scaffold_map_editor


class MapEditorDeploymentTests(unittest.TestCase):
    def test_deploys_to_active_ue4ss_folder_and_registers_without_deleting_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_root = root / "Stalker2"
            active_mods = game_root / "Binaries" / "Win64" / "ue4ss" / "Mods"
            active_mods.mkdir(parents=True)
            load_order = active_mods / "mods.txt"
            load_order.write_text(
                "ConsoleEnablerMod : 1\n\n; Add your mods above this line, e.g. MyMod : 1\n",
                encoding="utf-8",
            )
            inactive_mods = game_root / "Binaries" / "Win64" / "Mods"
            inactive_mods.mkdir(parents=True)
            (inactive_mods / "keep.txt").write_text("untouched", encoding="utf-8")

            output_dir = root / "output"
            result = scaffold_map_editor(str(output_dir), str(game_root))
            deploy_path = active_mods / "MapEditor"

            self.assertTrue(result["deployed"])
            self.assertEqual(Path(result["deploy_path"]), deploy_path)
            self.assertTrue(result["load_order_registered"])
            self.assertIn("MapEditor : 1", load_order.read_text(encoding="utf-8"))
            generated_script = (deploy_path / "scripts" / "main.lua").read_text(encoding="utf-8")
            self.assertIn("dumpusmap", generated_script)
            self.assertIn("dumpbakedfoliage", generated_script)
            self.assertIn("/Script/Engine.PlayerController:ClientRestart", generated_script)
            self.assertNotIn("/Script/Engine.GameInstance:Init", generated_script)

            user_file = deploy_path / "user-data.txt"
            user_file.write_text("preserve", encoding="utf-8")
            scaffold_map_editor(str(output_dir), str(game_root))
            self.assertEqual(user_file.read_text(encoding="utf-8"), "preserve")
            self.assertEqual((inactive_mods / "keep.txt").read_text(encoding="utf-8"), "untouched")
            self.assertEqual(list_mods(str(game_root))["mods_dir"], str(active_mods))
            self.assertEqual(enable_mod(str(game_root), "MapEditor")["path"], str(deploy_path))


if __name__ == "__main__":
    unittest.main()
