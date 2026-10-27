import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zlib

from tools import build_installer

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'install.sh'

class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            [sys.executable, str(ROOT / 'tools/build_installer.py')],
            cwd=ROOT, check=True,
        )
        cls.script = INSTALLER.read_bytes()

    def test_output_is_deterministic_and_embeds_exact_sources_only(self):
        generated = build_installer.build_script()
        self.assertEqual(generated, self.script)
        self.assertEqual(build_installer.build_script(), generated)
        start_marker = b"PAYLOAD = '''"
        end_marker = b"'''\n"
        start = generated.index(start_marker) + len(start_marker)
        encoded = generated[start:generated.index(end_marker, start)]
        payload = json.loads(zlib.decompress(base64.b64decode(encoded)))
        self.assertEqual(payload, {
            'patch_kakaotalk': (ROOT / 'patch_kakaotalk.py').read_text(),
            'distribution_entry': (ROOT / 'distribution_entry.py').read_text(),
        })
        self.assertNotIn(b'KakaoTalk.app/Contents', generated)
        self.assertNotIn(b'manifest.json":{"entries"', generated)
        self.assertNotIn(b'/Users/', generated)

    def test_shell_syntax_freshness_and_cwd_independent_argument_validation(self):
        subprocess.run(['sh', '-n', str(INSTALLER)], cwd='/', check=True)
        for arguments in (['invalid'], ['apply', 'extra'], ['import-backup'], ['import-backup', 'a', 'b']):
            result = subprocess.run(
                ['sh', str(INSTALLER), *arguments], cwd='/', capture_output=True,
                env={**os.environ, 'KAKAOTALK_ADBLOCK_APP': '/nonexistent/app', 'KAKAOTALK_ADBLOCK_BACKUP_ROOT': '/nonexistent/backup'},
            )
            self.assertEqual(result.returncode, 2, result.stderr.decode())
            self.assertIn(b'usage:', result.stderr)

    def test_missing_and_old_interpreters_fail_before_app_access(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
            marker = Path(directory) / 'app-accessed'
            tools = Path(directory) / 'bin'
            tools.mkdir()
            (tools / 'python3').symlink_to('/usr/bin/false')
            for tool in ('sh', 'dirname', 'uname'):
                (tools / tool).symlink_to(Path('/bin') / tool)
            result = subprocess.run(
                ['sh', str(INSTALLER), 'status'], capture_output=True,
                env={'PATH': str(tools), 'KAKAOTALK_ADBLOCK_APP': str(marker), 'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(marker)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Python 3.9 or newer', result.stderr)
            self.assertFalse(marker.exists())

    def test_truncated_or_empty_payload_never_runs_the_engine(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
            app = Path(directory) / 'KakaoTalk.app'
            app.mkdir()
            before = hashlib.sha256(INSTALLER.read_bytes()).hexdigest()
            environment = {**os.environ, 'KAKAOTALK_ADBLOCK_APP': str(app), 'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(Path(directory) / 'backups')}
            result = subprocess.run(['sh', '-s', '--', 'status'], input=b'', capture_output=True, env=environment)
            self.assertEqual(result.returncode, 0)  # Empty stdin contains no command to reject.
            self.assertEqual(list(app.iterdir()), [])
            truncated = self.script[:self.script.index(b'KAKAOTALK_ADBLOCK_PAYLOAD\n', self.script.index(b"PAYLOAD = '''"))]
            result = subprocess.run(['sh', '-s', '--', 'status'], input=truncated, capture_output=True, env=environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'incomplete', result.stderr)
            self.assertEqual(list(app.iterdir()), [])
            self.assertEqual(hashlib.sha256(INSTALLER.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
