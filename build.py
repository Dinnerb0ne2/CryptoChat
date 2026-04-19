from __future__ import annotations

import subprocess
import sys


def main() -> int:
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--onefile",
        "--follow-imports",
        "--include-package=cryptochat",
        "--output-dir=dist",
        "src/cryptochat/cli/app.py",
    ]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
