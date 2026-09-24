import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bootstrap", Path(__file__).resolve().parents[1] / "scripts/bootstrap.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BootstrapTests(unittest.TestCase):
    def test_credential_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module.bootstrap(root)
            base = root / ".loom"
            token = (base / "client.token").read_text()
            registry = (base / "identity/credentials.json").read_text()
            self.assertGreater(len(token), 40)
            self.assertNotIn(token, registry)
            self.assertEqual(stat.S_IMODE((base / "client.token").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
            self.assertNotEqual(token, (base / "pipeline.token").read_text())
            self.assertEqual(len(json.loads(registry)), 2)
            module.bootstrap(root)
            self.assertEqual(token, (base / "client.token").read_text())

    def test_partial_setup_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".loom").mkdir()
            (root / ".loom/client.token").write_text("incomplete")
            with self.assertRaises(RuntimeError):
                module.bootstrap(root)
