from __future__ import annotations

import unittest

from src.client import parse_slash_command


class ClientCommandTests(unittest.TestCase):
    def test_parse_command(self) -> None:
        self.assertEqual(parse_slash_command("/users"), ("users", []))
        self.assertEqual(parse_slash_command("/history 20"), ("history", ["20"]))

    def test_parse_non_command(self) -> None:
        self.assertIsNone(parse_slash_command("hello"))
        self.assertIsNone(parse_slash_command("/"))


if __name__ == "__main__":
    unittest.main()
