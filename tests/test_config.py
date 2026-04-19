from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.config import load_config


class ConfigTests(unittest.TestCase):
    def test_missing_config_uses_defaults(self) -> None:
        cfg = load_config("not_exists_config.json")
        self.assertIn("server", cfg)
        self.assertIn("client", cfg)
        self.assertIn("rooms", cfg)

    def test_partial_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.json"
            p.write_text(json.dumps({"server": {"port": 19999}}), encoding="utf-8")
            cfg = load_config(p)
            self.assertEqual(cfg["server"]["port"], 19999)
            self.assertEqual(cfg["server"]["host"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
