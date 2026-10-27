import hashlib
import http.server
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

import patch_kakaotalk as patcher
from tools.build_installer import build_script

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / '.adblock-backups/KakaoTalk-26.9.0-2006.app'

class Handler(http.server.BaseHTTPRequestHandler):
    script = b''
    truncated = b''
    def do_GET(self):
        if self.path == '/install.sh':
            body, status = self.script, 200
        elif self.path == '/truncated.sh':
            body, status = self.truncated, 200
        else:
            body, status = b'not found\n', 404
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args):
        pass

class CurlInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ORIGINAL.is_dir():
            raise unittest.SkipTest('Verified original full-app backup is required')
        cls.script = build_script()
        Handler.script = cls.script
        marker = cls.script.index(b'KAKAOTALK_ADBLOCK_PAYLOAD\n', cls.script.index(b"PAYLOAD = '''"))
        Handler.truncated = cls.script[:marker]
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=10)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / 'primary/KakaoTalk.app'
        self.app.parent.mkdir()
        shutil.copytree(ORIGINAL, self.app, symlinks=True)
        self.binary = self.app / 'Contents/MacOS/KakaoTalk'
        self.code_resources = self.app / 'Contents/_CodeSignature/CodeResources'
        self.original_code_resources = self.code_resources.read_bytes()
        self.backup_root = self.root / 'home/Library/Application Support/KakaoTalkAdblock/backups'
        self.environment = {
            **os.environ,
            'KAKAOTALK_ADBLOCK_APP': str(self.app),
            'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(self.backup_root),
        }

    def curl_pipe(self, path='/install.sh', arguments=(), environment=None):
        curl = subprocess.Popen(
            ['curl', '-fsSL', '--max-time', '90', self.base_url + path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        shell = subprocess.run(
            ['sh', '-s', *(('--', *arguments) if arguments else ())],
            stdin=curl.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.environment if environment is None else environment,
            cwd='/',
        )
        curl.stdout.close()
        curl_error = curl.stderr.read()
        curl_status = curl.wait(timeout=100)
        return curl_status, shell, curl_error

    def codesign_verify(self, app):
        subprocess.run(
            ['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)],
            capture_output=True, check=True,
        )

    def entitlements(self, app):
        result = subprocess.run(
            ['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)],
            capture_output=True, check=True,
        )
        return plistlib.loads(result.stdout)

    def snapshot(self, root):
        timestamps = {
            str(path.relative_to(root)): path.lstat().st_mtime_ns
            for path in root.rglob('*')
        }
        return patcher.tree_manifest(root), timestamps

    def test_real_curl_download_lifecycle_import_and_failed_downloads(self):
        self.assertEqual(patcher.inspect_app(self.app), patcher.AppState.ORIGINAL)
        original_hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.assertEqual(original_hash, patcher.TARGET.original_sha256)
        self.codesign_verify(self.app)
        original_entitlements = self.entitlements(self.app)

        downloaded = self.root / 'downloaded/install.sh'
        downloaded.parent.mkdir()
        with downloaded.open('wb') as stream:
            subprocess.run(
                ['curl', '-fsSL', self.base_url + '/install.sh'],
                stdout=stream, check=True, cwd='/',
            )
        self.assertEqual(hashlib.sha256(downloaded.read_bytes()).hexdigest(), hashlib.sha256(self.script).hexdigest())

        # A curl -f HTTP failure produces no shell program. Plain sh therefore returns 0.
        curl_status, result, curl_error = self.curl_pipe('/absent', ['status'])
        self.assertEqual(curl_status, 22)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'404', curl_error)
        self.assertEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(), original_hash)
        curl_status, result, _ = self.curl_pipe('/truncated.sh', ['status'])
        self.assertEqual(curl_status, 0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'incomplete', result.stderr)
        self.assertEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(), original_hash)

        curl_status, result, _ = self.curl_pipe()
        self.assertEqual((curl_status, result.returncode), (0, 0), result.stderr.decode())
        self.assertIn(b'PATCHED', result.stdout)
        self.codesign_verify(self.app)
        self.assertEqual(self.entitlements(self.app), original_entitlements)
        backup = self.backup_root / ORIGINAL.name
        self.assertEqual(hashlib.sha256((backup / 'Contents/MacOS/KakaoTalk').read_bytes()).hexdigest(), original_hash)
        self.assertEqual(json.loads((self.backup_root / 'manifest.json').read_text())['version'], '26.9.0')
        self.assertNotEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(), original_hash)
        patched_bytes = self.binary.read_bytes()
        patched_mtime = self.binary.stat().st_mtime_ns
        backup_before = self.snapshot(backup)

        curl_status, result, _ = self.curl_pipe(arguments=['apply'])
        self.assertEqual((curl_status, result.returncode), (0, 0), result.stderr.decode())
        self.assertEqual(self.binary.read_bytes(), patched_bytes)
        self.assertEqual(self.binary.stat().st_mtime_ns, patched_mtime)
        self.assertEqual(self.snapshot(backup), backup_before)
        curl_status, result, _ = self.curl_pipe(arguments=['status'])
        self.assertEqual((curl_status, result.returncode), (0, 0), result.stderr.decode())
        self.assertIn(b'PATCHED', result.stdout)

        second_app = self.root / 'secondary/KakaoTalk.app'
        second_app.parent.mkdir()
        shutil.copytree(self.app, second_app, symlinks=True)
        second_binary = second_app / 'Contents/MacOS/KakaoTalk'
        second_backup = self.root / 'second-backups'
        second_environment = {
            **self.environment,
            'KAKAOTALK_ADBLOCK_APP': str(second_app),
            'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(second_backup),
        }
        curl_status, result, _ = self.curl_pipe(
            arguments=['import-backup', str(self.backup_root)], environment=second_environment,
        )
        self.assertEqual((curl_status, result.returncode), (0, 0), result.stderr.decode())
        self.assertEqual(second_binary.read_bytes(), patched_bytes)
        self.assertEqual(self.snapshot(backup), backup_before)
        self.assertEqual(
            (second_backup / ORIGINAL.name / 'Contents/MacOS/KakaoTalk').read_bytes(),
            (backup / 'Contents/MacOS/KakaoTalk').read_bytes(),
        )
        self.assertEqual((second_backup / 'manifest.json').read_bytes(), (self.backup_root / 'manifest.json').read_bytes())
        curl_status, result, _ = self.curl_pipe(arguments=['restore'], environment=second_environment)
        self.assertEqual((curl_status, result.returncode), (0, 0), result.stderr.decode())
        self.assertEqual(hashlib.sha256(second_binary.read_bytes()).hexdigest(), original_hash)
        self.assertEqual((second_app / 'Contents/_CodeSignature/CodeResources').read_bytes(), self.original_code_resources)
        self.codesign_verify(second_app)

        curl_status, result, _ = self.curl_pipe(arguments=['restore'])
        self.assertEqual((curl_status, result.returncode), (0, 0), result.stderr.decode())
        self.assertIn(b'ORIGINAL', result.stdout)
        self.assertEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(), original_hash)
        self.assertEqual(self.code_resources.read_bytes(), self.original_code_resources)
        self.codesign_verify(self.app)
        self.assertEqual(self.entitlements(self.app), original_entitlements)
        self.assertEqual(self.snapshot(backup), backup_before)


if __name__ == '__main__':
    unittest.main()
