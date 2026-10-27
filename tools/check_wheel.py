"""Check installed-layout metadata assets and exercise the isolated built wheel on CI."""

import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from architecture import RUNTIME_ASSETS

SMOKE = """import sys
sys.path.insert(0, sys.argv[1])
import kryvola_fabric
assert sys.argv[1] in kryvola_fabric.__file__
from kryvola_fabric.control import decode_control
assert decode_control('GetCapabilitiesRequest', bytes.fromhex('0a0131'))['schema_version']=='1'
"""
root = Path(__file__).resolve().parents[1]
wheel = max((root / "dist").glob("*.whl"), key=lambda path: path.stat().st_mtime_ns)
with ZipFile(wheel) as archive:
    for name in RUNTIME_ASSETS:
        assert (
            archive.read("kryvola_fabric/_spec/" + name)
            == (root / "src/kryvola_fabric/_spec" / name).read_bytes()
        )
with TemporaryDirectory() as directory:
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            SMOKE,
            str(wheel),
        ],
        cwd=directory,
        check=True,
    )
