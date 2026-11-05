import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless((ROOT / "install.py").exists(), "Installer tests apply to the repository checkout")
class InstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("migration_installer", ROOT / "install.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_install_is_repeatable_and_preserves_changed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            first = self.module.install(ROOT, config)
            self.assertGreater(first["changed"], 0)
            self.assertEqual((first["skill"] / "SKILL.md").read_bytes(), (ROOT / "SKILL.md").read_bytes())
            self.assertEqual(first["command"].read_bytes(), (ROOT / "commands/f5-migration.md").read_bytes())
            self.assertFalse((first["skill"] / ".git").exists())
            self.assertFalse(list(first["skill"].rglob("*.pyc")))
            self.assertEqual(self.module.install(ROOT, config)["changed"], 0)
            first["command"].write_text("Local command customization")
            replacement = self.module.install(ROOT, config)
            self.assertEqual(replacement["changed"], 1)
            self.assertEqual((replacement["backup"] / "commands/f5-migration.md").read_text(), "Local command customization")

    def test_install_from_existing_skill_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            installed = self.module.install(ROOT, config)
            command_source = installed["skill"] / "commands/f5-migration.md"
            command_source.parent.mkdir()
            command_source.write_bytes((ROOT / "commands/f5-migration.md").read_bytes())
            self.assertEqual(self.module.install(installed["skill"], config)["changed"], 0)
