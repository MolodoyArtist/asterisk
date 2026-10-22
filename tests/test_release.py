import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


class ReleaseBootstrapTests(unittest.TestCase):
    def run_bootstrap(self, corrupt=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "release.tar.gz"
            payload = b'#!/usr/bin/env bash\nprintf "%s" "$0" >"${BOOTSTRAP_RESULT}"\n'
            with tarfile.open(archive, "w:gz") as bundle:
                entry = tarfile.TarInfo("vpnctl-v0.0.0/install.sh")
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            template = Path(__file__).resolve().parents[1] / "scripts/release-bootstrap.sh.in"
            bootstrap = root / "bootstrap.sh"
            bootstrap.write_text(template.read_text().replace("@RELEASE_TAG@", "v0.0.0").replace("@ARCHIVE_SHA256@", expected))
            if corrupt:
                archive.write_bytes(archive.read_bytes() + b"tampered")
            binaries = root / "bin"
            binaries.mkdir()
            curl = binaries / "curl"
            curl.write_text('#!/usr/bin/env bash\nset -eu\nwhile (($#)); do\n  if [[ "$1" == -o ]]; then cp "${BOOTSTRAP_ARCHIVE}" "$2"; exit; fi\n  shift\ndone\nexit 1\n')
            curl.chmod(0o755)
            marker = root / "installer-result"
            result = subprocess.run(
                ["bash", str(bootstrap)],
                env=dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}", BOOTSTRAP_ARCHIVE=str(archive), BOOTSTRAP_RESULT=str(marker)),
                capture_output=True,
                check=False,
                timeout=15,
            )
            if corrupt:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists(), "An unverified installer must never run")
            else:
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertTrue(marker.exists())
                self.assertFalse(Path(marker.read_text()).exists(), "The extracted source must be cleaned after installation")

    def test_verified_release_runs_and_cleans_temporary_files(self):
        self.run_bootstrap()

    def test_tampered_release_never_runs(self):
        self.run_bootstrap(corrupt=True)
