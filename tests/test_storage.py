from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.storage import ChatStorage


class StorageTests(unittest.TestCase):
    def test_message_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "chat.db"
            st = ChatStorage(str(db))
            st.add_message("alice", "127.0.0.1", 5000, "lobby", "hello")
            st.add_message("bob", "127.0.0.1", 5001, "lobby", "world")
            hist = st.get_history(10, room="lobby")
            self.assertEqual(len(hist), 2)
            self.assertEqual(hist[0]["nickname"], "alice")
            self.assertEqual(hist[1]["nickname"], "bob")
            st.close()

    def test_online_users(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "chat.db"
            st = ChatStorage(str(db))
            st.set_client_online("s1", "alice", "1.1.1.1", 1234, "lobby")
            users = st.list_online_users("lobby")
            self.assertEqual(len(users), 1)
            st.set_client_offline("s1")
            users_after = st.list_online_users("lobby")
            self.assertEqual(len(users_after), 0)
            st.close()


if __name__ == "__main__":
    unittest.main()
