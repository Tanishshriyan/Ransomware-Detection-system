import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from utils.config import Config


class ConfigTests(unittest.TestCase):
    def _write_config(self, directory: str) -> str:
        config_path = Path(directory) / "config.yaml"
        config_path.write_text(
            textwrap.dedent(
                """
                system:
                  name: RansomGuard
                  version: "1.0"
                server:
                  host: 127.0.0.1
                  port: 8000
                killswitch:
                  enabled: true
                  threat_threshold: 60
                ml_model:
                  model_path: ml_model/models/lightgbm_model_v3.0.pkl
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return str(config_path)

    def test_loads_yaml_and_supports_legacy_aliases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(self._write_config(tmpdir))

        self.assertEqual(cfg.server_host, "127.0.0.1")
        self.assertEqual(cfg.server_port, 8000)
        self.assertEqual(
            cfg.get("ml.model_path"),
            "ml_model/models/lightgbm_model_v3.0.pkl",
        )
        self.assertTrue(cfg.validate())

    def test_environment_overrides_are_coerced(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = self._write_config(tmpdir)
            with mock.patch.dict(
                "os.environ",
                {
                    "RG_SERVER_PORT": "9001",
                    "RG_KILLSWITCH_ENABLED": "false",
                    "RG_KILLSWITCH_THRESHOLD": "73",
                    "RG_GEMINI_API_KEY": "demo-key",
                },
                clear=False,
            ):
                cfg = Config(config_path)

        self.assertEqual(cfg.server_port, 9001)
        self.assertFalse(cfg.killswitch_enabled)
        self.assertEqual(cfg.killswitch_threshold, 73)
        self.assertEqual(cfg.get("integrations.gemini.api_key"), "demo-key")
