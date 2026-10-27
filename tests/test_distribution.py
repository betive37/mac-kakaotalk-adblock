import contextlib
import io
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import patch_kakaotalk as patcher
from distribution_entry import distribution_main
from tests.test_patch_kakaotalk import LifecycleFixture


class DistributionFixture(LifecycleFixture):
    def setUp(self):
        super().setUp()
        self.installed_override = mock.patch.object(patcher, '_INSTALLED_APP', self.app)
        self.installed_override.start()
        self.addCleanup(self.installed_override.stop)
        self.target_override = mock.patch.object(patcher, 'TARGET', self.spec)
        self.target_override.start()
        self.addCleanup(self.target_override.stop)
        self.entitlements = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>'
        signing_override = mock.patch.object(patcher, 'resign_app', side_effect=self.record_signed_fixture)
        signing_override.start()
        self.addCleanup(signing_override.stop)
        entitlement_override = mock.patch.object(patcher, 'extract_entitlements', return_value=self.entitlements)
        entitlement_override.start()
        self.addCleanup(entitlement_override.stop)

    def record_signed_fixture(self, app, entitlements, target=None, *, allow_installed=False):
        # Preserve sparse fixture bytes; only signature metadata comes from the real signed app.
        signed_app = Path(__file__).resolve().parents[1] / 'KakaoTalk.app'
        recorded = (signed_app / 'Contents/MacOS/KakaoTalk').read_bytes()
        signed = bytearray(patcher.patched_executable(self.original, self.spec))
        for index, slice_spec in enumerate(self.spec.slices):
            signed[8 + index * 20 + 12:8 + index * 20 + 16] = recorded[8 + index * 20 + 12:8 + index * 20 + 16]
            position = slice_spec.offset + 32
            command_count = patcher.struct.unpack_from('<I', self.original, slice_spec.offset + 16)[0]
            for _ in range(command_count):
                command, command_size = patcher.struct.unpack_from('<II', self.original, position)
                if command == 0x1D:
                    signed[position + 8:position + 16] = recorded[position + 8:position + 16]
                elif command == 0x19 and self.original[position + 8:position + 24].rstrip(b'\0') == b'__LINKEDIT':
                    signed[position + 48:position + 56] = recorded[position + 48:position + 56]
                position += command_size
            start, end = slice_spec.offset + slice_spec.signature_offset, slice_spec.offset + slice_spec.size
            signed[start:end] = recorded[start:end]
        (app / 'Contents/MacOS/KakaoTalk').write_bytes(signed)
        (app / 'Contents/_CodeSignature/CodeResources').write_bytes(
            (signed_app / 'Contents/_CodeSignature/CodeResources').read_bytes(),
        )

    def environment(self):
        return {
            'KAKAOTALK_ADBLOCK_APP': str(self.app),
            'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(self.backup_root),
        }

    def invoke(self, arguments, environ=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = distribution_main(arguments, self.environment() if environ is None else environ)
        return result, stdout.getvalue(), stderr.getvalue()

class DistributionTests(DistributionFixture, unittest.TestCase):
    def test_distribution_permission_does_not_leak_into_existing_api(self):
        with self.assertRaisesRegex(patcher.PatchError, 'installed'):
            patcher.apply_patch(self.app, self.backup_root, self.spec)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertEqual(
            patcher.apply_patch(self.app, self.backup_root, self.spec, allow_installed=True),
            patcher.AppState.PATCHED,
        )
        self.assertEqual(
            (self.backup / 'Contents/MacOS/KakaoTalk').read_bytes(), self.original,
        )

    def test_distribution_apply_uses_both_explicit_disposable_overrides(self):
        result, output, error = self.invoke(['apply'])
        self.assertEqual((result, error), (0, ''))
        self.assertIn('PATCHED', output)
        self.assertEqual(patcher.inspect_app(self.app, self.spec), patcher.AppState.PATCHED)
        self.assertTrue(self.manifest_path.is_file())

    def test_default_no_arguments_applies_only_to_configured_installed_target(self):
        home = self.root / 'home'
        home.mkdir()
        with mock.patch.object(patcher, '_PROJECT_ROOT', self.root), \
                mock.patch.object(Path, 'home', return_value=home):
            local_result, _, local_error = self.invoke_local(['apply'])
            result, output, error = self.invoke([], {})
        self.assertEqual(local_result, 1)
        self.assertIn('installed', local_error)
        self.assertEqual((result, error), (0, ''))
        self.assertIn('PATCHED', output)
        expected_backup = home / 'Library/Application Support/KakaoTalkAdblock/backups/KakaoTalk-26.9.0-2006.app'
        self.assertEqual((expected_backup / 'Contents/MacOS/KakaoTalk').read_bytes(), self.original)

    def invoke_local(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = patcher.main(arguments)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_invalid_commands_and_partial_test_overrides_fail_before_mutation(self):
        for arguments, environ in (
            (['unknown'], self.environment()),
            (['apply', 'extra'], self.environment()),
            ([], {'KAKAOTALK_ADBLOCK_APP': str(self.app)}),
            ([], {'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(self.backup_root)}),
        ):
            with self.subTest(arguments=arguments, environ=environ):
                result, _, error = self.invoke(arguments, environ)
                self.assertEqual(result, 2)
                self.assertIn('usage:', error)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup_root.exists())

    def test_wrong_version_and_symlink_app_are_still_rejected(self):
        with self.app.joinpath('Contents/Info.plist').open('rb') as stream:
            info = plistlib.load(stream)
        info['CFBundleShortVersionString'] = 'not-supported'
        with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
            plistlib.dump(info, stream)
        result, _, error = self.invoke(['apply'])
        self.assertEqual(result, 1)
        self.assertIn('CFBundleShortVersionString', error)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup_root.exists())

        info['CFBundleShortVersionString'] = '26.9.0'
        with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
            plistlib.dump(info, stream)
        link = self.root / 'linked.app'
        link.symlink_to(self.app, target_is_directory=True)
        environment = self.environment()
        environment['KAKAOTALK_ADBLOCK_APP'] = str(link)
        result, _, error = self.invoke(['apply'], environment)
        self.assertEqual(result, 1)
        self.assertIn('not a real directory', error)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup_root.exists())

    def test_running_target_is_refused_without_signing_or_termination(self):
        real_run = patcher.subprocess.run
        def running_process(command, **kwargs):
            if command[0] == 'pgrep':
                return subprocess.CompletedProcess(command, 0, stdout='123\n', stderr='')
            return real_run(command, **kwargs)
        with mock.patch.object(patcher.subprocess, 'run', side_effect=running_process) as run:
            result, _, error = self.invoke(['apply'])
        self.assertEqual(result, 1)
        self.assertIn('running target application', error)
        self.assertEqual(run.call_args.args[0][0], 'pgrep')
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertEqual((self.backup / 'Contents/MacOS/KakaoTalk').read_bytes(), self.original)

    def test_system_python_39_can_load_distribution_entrypoint(self):
        code = (
            'import distribution_entry, patch_kakaotalk; '
            'assert distribution_entry.distribution_main([\'bad\'], {}) == 2'
        )
        result = subprocess.run(
            ['/usr/bin/python3', '-c', code], cwd=patcher._PROJECT_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


class BackupImportTests(DistributionFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.source_root = self.root / 'existing-backups'
        self.source_backup = self.source_root / self.backup.name
        self.destination_root = self.root / 'registered-backups'
        self.source_executable = self.source_backup / 'Contents/MacOS/KakaoTalk'
        patcher.backup_app(self.app, self.source_root, self.spec, allow_installed=True)
        self.binary.write_bytes(patcher.patched_executable(self.original, self.spec))
        self.record_signed_fixture(self.app, self.entitlements, allow_installed=True)
        self.patched_before = self.binary.read_bytes()
        self.source_before = patcher.tree_manifest(self.source_root)
        self.manifest_before = (self.source_root / 'manifest.json').read_bytes()

    def test_import_preserves_source_and_current_app_and_registers_verified_backup(self):
        destination = patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        self.assertEqual(destination, self.destination_root / self.backup.name)
        self.assertEqual(patcher.tree_manifest(self.destination_root), self.source_before)
        self.assertEqual((self.destination_root / 'manifest.json').read_bytes(), self.manifest_before)
        self.assertEqual(patcher.tree_manifest(self.source_root), self.source_before)
        self.assertEqual(self.binary.read_bytes(), self.patched_before)
        result, output, error = self.invoke(
            ['import-backup', str(self.source_root)],
            {**self.environment(), 'KAKAOTALK_ADBLOCK_BACKUP_ROOT': str(self.destination_root)},
        )
        self.assertEqual((result, error), (0, ''))
        self.assertIn(str(destination), output)

    def test_source_equals_destination_and_existing_identical_destination_are_idempotent(self):
        first = patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        before = patcher.tree_manifest(self.destination_root)
        self.assertEqual(patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec), first)
        self.assertEqual(patcher.import_backup(self.app, self.source_root, self.source_root, self.spec), self.source_backup)
        self.assertEqual(patcher.tree_manifest(self.destination_root), before)

    def test_corrupt_source_or_changed_target_resources_never_create_destination(self):
        self.resource.write_text('target resource changed\n')
        with self.assertRaisesRegex(patcher.PatchError, 'resources differ'):
            patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        self.assertFalse(self.destination_root.exists())
        self.resource.write_text('original resource\n')
        self.source_executable.write_bytes(b'corrupt backup\n')
        with self.assertRaises(patcher.PatchError):
            patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        self.assertFalse(self.destination_root.exists())
        self.assertEqual(self.binary.read_bytes(), self.patched_before)

    def test_existing_destination_is_not_overwritten_by_conflicting_source(self):
        patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        (self.destination_root / 'manifest.json').write_text('do not overwrite\n')
        with self.assertRaises(patcher.PatchError):
            patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        self.assertEqual((self.destination_root / 'manifest.json').read_text(), 'do not overwrite\n')

    def test_copy_failure_cleans_staging_and_preserves_source(self):
        original_copy = patcher.shutil.copy2
        def fail_copy(source, destination, **kwargs):
            if Path(source) == self.source_backup / 'Contents/Resources/original.txt':
                raise OSError('injected import copy failure')
            return original_copy(source, destination, **kwargs)
        with mock.patch.object(patcher.shutil, 'copy2', side_effect=fail_copy):
            with self.assertRaisesRegex(patcher.PatchError, 'injected import copy failure'):
                patcher.import_backup(self.app, self.source_root, self.destination_root, self.spec)
        self.assertFalse(self.backup.exists())
        self.assertEqual(patcher.tree_manifest(self.source_root), self.source_before)
        self.assertFalse((self.destination_root / 'manifest.json').exists())
        if self.destination_root.exists():
            self.assertEqual(list(self.destination_root.iterdir()), [])

    def test_import_cli_rejects_missing_or_extra_source_before_mutation(self):
        for arguments in (['import-backup'], ['import-backup', str(self.source_root), 'extra']):
            result, _, error = self.invoke(arguments)
            self.assertEqual(result, 2)
            self.assertIn('usage:', error)
        result, _, error = self.invoke(['import-backup', str(self.root / 'absent')])
        self.assertEqual(result, 1)
        self.assertIn('required', error)
        self.assertFalse(self.backup_root.exists())


if __name__ == '__main__':
    unittest.main()
