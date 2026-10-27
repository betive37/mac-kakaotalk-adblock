import contextlib
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from patch_kakaotalk import (
    AppState,
    PatchError,
    SliceSpec,
    TARGET,
    TargetSpec,
    apply_patch,
    backup_app,
    extract_entitlements,
    inspect_app,
    main,
    patched_executable,
    resign_app,
    restore_patch,
    tree_manifest,
    verify_unchanged_resources,
)

ROOT = Path(__file__).resolve().parent.parent
REAL_APP = ROOT / 'KakaoTalk.app'
REAL_BINARY = REAL_APP / 'Contents/MacOS/KakaoTalk'
PATCH_OFFSETS = {0x1113896, 0x1113897, 0x378A55C, 0x378A55D, 0x378A55E, 0x378A55F}
CHANGED_OFFSETS = PATCH_OFFSETS - {0x378A55E}  # ARM64 byte 3 remains zero in both instructions.
CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fixture_target():
    return TargetSpec(
        bundle_id='com.kakao.KakaoTalkMac',
        version='26.9.0',
        build='2006',
        original_sha256=TARGET.original_sha256,
        normalized_original_sha256=TARGET.normalized_original_sha256,
        slices=(
            SliceSpec(CPU_X86_64, 0x4000, 0x287E1A0, 14, 0x2828E30, 0x55370),
            SliceSpec(CPU_ARM64, 0x2884000, 0x241EBC0, 14, 0x2407D30, 0x16E90),
        ),
        patches=TARGET.patches,
    )


def command_range(data, slice_spec):
    count = struct.unpack_from('<I', data, slice_spec.offset + 16)[0]
    return slice_spec.offset + 32, count


def find_load_command(data, slice_spec, wanted, name=None):
    position, count = command_range(data, slice_spec)
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, position)
        command_name = data[position + 8:position + 24].rstrip(b'\0')
        if command == wanted and (name is None or command_name == name):
            return position
        position += size
    raise ValueError(f'missing load command {wanted:#x}')


def normalize_fixture(data, spec):
    result = bytearray(data)
    signature_ranges = []
    for index, slice_spec in enumerate(spec.slices):
        struct.pack_into('>I', result, 8 + index * 20 + 12, 0)
        position, count = command_range(data, slice_spec)
        for _ in range(count):
            command, size = struct.unpack_from('<II', data, position)
            if command == 0x19 and data[position + 8:position + 24].rstrip(b'\0') == b'__LINKEDIT':
                result[position + 48:position + 56] = b'\0' * 8
            elif command == 0x1D:
                result[position + 8:position + 16] = b'\0' * 8
            position += size
        start = slice_spec.offset + slice_spec.signature_offset
        signature_ranges.append((start, slice_spec.offset + slice_spec.size))
    for start, end in sorted(signature_ranges, reverse=True):
        del result[start:end]
    return sha256(result)


class TargetFixture:
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(dir='/private/tmp')
        cls.fixture_root = Path(cls.tempdir.name)
        cls.app = cls.fixture_root / 'KakaoTalk.app'
        cls.binary = cls.app / 'Contents/MacOS/KakaoTalk'
        cls.binary.parent.mkdir(parents=True)
        real_app = REAL_APP
        if inspect_app(REAL_APP) == AppState.PATCHED:
            real_app = REAL_APP.parent / '.adblock-backups/KakaoTalk-26.9.0-2006.app'
            if inspect_app(real_app) != AppState.ORIGINAL:
                raise unittest.SkipTest('A verified original backup is required for sparse fixtures')
        real_binary = real_app / 'Contents/MacOS/KakaoTalk'
        # Metadata and the short patch neighborhoods come from the authorized original.
        # The rest is deterministic zero-filled fixture data, not a production backup.
        real = real_binary.read_bytes()
        data = bytearray(len(real))
        header_regions = [(0, 0x80)]
        for slice_spec in fixture_target().slices:
            commands_size = struct.unpack_from('<I', real, slice_spec.offset + 20)[0]
            header_regions.append((slice_spec.offset, slice_spec.offset + 32 + commands_size))
        for start, end in (
            *header_regions,
            (0x1113896 - 16, 0x1113896 + 16),
            (0x378A55C - 16, 0x378A55C + 16),
        ):
            data[start:end] = real[start:end]
        for patch in TARGET.patches:
            site = data[patch.file_offset:patch.file_offset + len(patch.original)]
            if site not in (patch.original, patch.replacement):
                raise unittest.SkipTest('Copied app has an unsupported patch-site state')
            data[patch.file_offset:patch.file_offset + len(patch.original)] = patch.original
        for slice_spec in fixture_target().slices:
            signature_start = slice_spec.offset + slice_spec.signature_offset
            data[signature_start:signature_start + slice_spec.signature_size] = b'\xA5' * slice_spec.signature_size
        cls.original = bytes(data)
        with real_app.joinpath('Contents/Info.plist').open('rb') as stream:
            cls.info = plistlib.load(stream)
        with cls.app.joinpath('Contents/Info.plist').open('wb') as stream:
            plistlib.dump(cls.info, stream)
        cls.spec = dataclasses.replace(
            fixture_target(),
            original_sha256=sha256(cls.original),
            normalized_original_sha256=normalize_fixture(cls.original, fixture_target()),
        )

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def setUp(self):
        self.binary.write_bytes(self.original)

    def write(self, data):
        self.binary.write_bytes(data)

    @classmethod
    def pure_patch(cls):
        data = bytearray(cls.original)
        for patch in cls.spec.patches:
            data[patch.file_offset:patch.file_offset + len(patch.original)] = patch.replacement
        return data

    @classmethod
    def signed_patch(cls):
        data = cls.pure_patch()
        for index, slice_spec in enumerate(cls.spec.slices):
            command = find_load_command(data, slice_spec, 0x1D)
            linkedit = find_load_command(data, slice_spec, 0x19, b'__LINKEDIT')
            reduction = 192
            struct.pack_into('<I', data, command + 12, slice_spec.signature_size - reduction)
            struct.pack_into('<Q', data, linkedit + 48, struct.unpack_from('<Q', data, linkedit + 48)[0] - reduction)
            struct.pack_into('>I', data, 8 + index * 20 + 12, slice_spec.size - reduction)
            padding = slice_spec.offset + slice_spec.signature_offset + slice_spec.signature_size - reduction
            data[padding:slice_spec.offset + slice_spec.size] = b'\0' * reduction
        current_end = max(struct.unpack_from('>II', data, 8 + index * 20 + 8) for index in range(len(cls.spec.slices)))
        del data[sum(current_end):]
        return data

class TargetValidationTests(TargetFixture, unittest.TestCase):
    def test_original_and_signed_patched_fixtures_are_distinguished(self):
        self.assertEqual(inspect_app(self.app, self.spec), AppState.ORIGINAL)
        self.write(self.signed_patch())
        self.assertEqual(inspect_app(self.app, self.spec), AppState.PATCHED)

    def test_wrong_identity_version_or_build_is_rejected(self):
        for field in ('CFBundleIdentifier', 'CFBundleShortVersionString', 'CFBundleVersion'):
            with self.subTest(field=field):
                info = dict(self.info)
                info[field] = 'wrong-target'
                with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
                    plistlib.dump(info, stream)
                with self.assertRaises(PatchError):
                    inspect_app(self.app, self.spec)
        with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
            plistlib.dump(self.info, stream)

    def test_wrong_original_digest_is_rejected(self):
        with self.assertRaises(PatchError):
            inspect_app(self.app, dataclasses.replace(self.spec, original_sha256='0' * 64))

    def test_fat_and_slice_structure_must_match(self):
        mutations = {
            'fat magic': (0, '>I', 0),
            'x86 CPU': (8, '>I', CPU_ARM64),
            'slice offset': (16, '>I', 0x8000),
            'alignment': (24, '>I', 4),
        }
        for name, (offset, fmt, value) in mutations.items():
            with self.subTest(name=name):
                data = bytearray(self.original)
                struct.pack_into(fmt, data, offset, value)
                self.write(data)
                with self.assertRaises(PatchError):
                    inspect_app(self.app, self.spec)

    def test_partial_patch_and_unexpected_patch_bytes_are_rejected(self):
        for patch in self.spec.patches:
            with self.subTest(partial=patch.architecture):
                data = bytearray(self.original)
                data[patch.file_offset:patch.file_offset + len(patch.original)] = patch.replacement
                self.write(data)
                with self.assertRaises(PatchError):
                    inspect_app(self.app, self.spec)
        data = bytearray(self.original)
        data[self.spec.patches[0].file_offset] = 0xFF
        self.write(data)
        with self.assertRaises(PatchError):
            inspect_app(self.app, self.spec)

    def test_only_signing_size_fields_are_normalized(self):
        mutations = {
            'non-signature code': (0x1113896 + 0x20, 1, 0x5A),
            'load command': (find_load_command(self.original, self.spec.slices[0], 0x1D) + 20, 1, 0x5A),
            'LINKEDIT': (self.spec.slices[0].offset + self.spec.slices[0].signature_offset - 32, 1, 0x5A),
            'signature padding': (self.spec.slices[0].offset + self.spec.slices[0].size - 1, 1, 0x5A),
        }
        for name, (offset, length, value) in mutations.items():
            with self.subTest(name=name):
                data = bytearray(self.signed_patch())
                data[offset:offset + length] = bytes([value]) * length
                self.write(data)
                with self.assertRaises(PatchError):
                    inspect_app(self.app, self.spec)

    def test_signature_reservation_and_malformed_commands_are_rejected(self):
        first = self.spec.slices[0]
        signature_command = find_load_command(self.original, first, 0x1D)
        cases = []
        data = self.signed_patch()
        struct.pack_into('<I', data, signature_command + 8, first.signature_offset + 1)
        cases.append(('moved signature offset', data))
        data = self.signed_patch()
        struct.pack_into('<I', data, signature_command + 12, first.signature_size + 1)
        cases.append(('oversized signature', data))
        data = self.signed_patch()
        struct.pack_into('<I', data, signature_command + 12, first.signature_size - 193)
        cases.append(('nonzero bytes after signature', data))
        for name, data in cases:
            with self.subTest(name=name):
                self.write(data)
                with self.assertRaises(PatchError):
                    inspect_app(self.app, self.spec)
        for name, mutate in (
            ('short load command', lambda d: struct.pack_into('<I', d, self.spec.slices[0].offset + 36, 4)),
            ('load command beyond slice', lambda d: struct.pack_into('<I', d, self.spec.slices[0].offset + 36, 0xFFFFFFFF)),
            ('negative command count', lambda d: struct.pack_into('<I', d, self.spec.slices[0].offset + 16, 0xFFFFFFFF)),
        ):
            with self.subTest(name=name):
                data = bytearray(self.signed_patch())
                mutate(data)
                self.write(data)
                with self.assertRaises(PatchError):
                    inspect_app(self.app, self.spec)

    def test_pure_patch_changes_only_authorized_instruction_bytes(self):
        result = patched_executable(self.original, self.spec)
        self.assertEqual(len(result), len(self.original))
        self.assertEqual({i for i, (a, b) in enumerate(zip(self.original, result)) if a != b}, CHANGED_OFFSETS)
        self.assertTrue(CHANGED_OFFSETS <= PATCH_OFFSETS)
        changed = bytearray(self.original)
        changed[0x10000] ^= 1
        with self.assertRaises(PatchError):
            patched_executable(changed, self.spec)

    def test_path_restrictions_reject_unsafe_mutation_targets(self):
        with self.assertRaises(PatchError):
            inspect_app(self.app / 'missing.app', self.spec)
        link = self.fixture_root / 'linked.app'
        link.symlink_to(self.app, target_is_directory=True)
        with self.assertRaises(PatchError):
            inspect_app(link, self.spec)
        self.binary.unlink()
        self.binary.symlink_to(self.fixture_root / 'some-executable')
        with self.assertRaises(PatchError):
            inspect_app(self.app, self.spec)
        self.binary.unlink()
        self.binary.write_bytes(self.original)
        hardlink = self.fixture_root / 'hardlink'
        os.link(self.binary, hardlink)
        with self.assertRaises(PatchError):
            inspect_app(self.app, self.spec)
        hardlink.unlink()

    def test_real_target_patch_sites_and_arm64_destination(self):
        original_digest = sha256(REAL_BINARY.read_bytes())
        data = bytearray(REAL_BINARY.read_bytes())
        for patch in TARGET.patches:
            actual = data[patch.file_offset:patch.file_offset + len(patch.original)]
            self.assertIn(actual, (patch.original, patch.replacement))
            data[patch.file_offset:patch.file_offset + len(patch.original)] = patch.original
        arm64 = next(p for p in TARGET.patches if p.architecture == 'arm64')
        displacement = arm64.destination - arm64.vm_address
        self.assertEqual(displacement, 0x90)
        self.assertEqual(struct.pack('<I', 0x14000000 | (displacement // 4)), arm64.replacement)
        self.assertEqual(sha256(REAL_BINARY.read_bytes()), original_digest)
        # Independent known-answer check for the full original normalizer.
        self.assertEqual(TARGET.normalized_original_sha256, normalize_fixture(data, TARGET))


class LifecycleFixture(TargetFixture):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.root = Path(self.tempdir.name)
        self.app = self.root / 'KakaoTalk.app'
        self.binary = self.app / 'Contents/MacOS/KakaoTalk'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(self.original)
        with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
            plistlib.dump(self.info, stream)
        self.code_resources = self.app / 'Contents/_CodeSignature/CodeResources'
        self.code_resources.parent.mkdir()
        self.code_resources.write_bytes(b'original-code-resources\n')
        self.resource = self.app / 'Contents/Resources/original.txt'
        self.resource.parent.mkdir()
        self.resource.write_text('original resource\n')
        framework = self.app / 'Contents/Frameworks/Test.framework'
        version = framework / 'Versions/A'
        (version / 'Resources').mkdir(parents=True)
        (version / 'Test').write_bytes(b'framework\n')
        (version / 'Resources/Info.plist').write_bytes(b'framework-info\n')
        (framework / 'Versions/Current').symlink_to('A', target_is_directory=True)
        (framework / 'Test').symlink_to('Versions/Current/Test')
        (framework / 'Resources').symlink_to('Versions/Current/Resources', target_is_directory=True)
        self.backup_root = self.root / 'backups'
        self.backup = self.backup_root / 'KakaoTalk-26.9.0-2006.app'
        self.manifest_path = self.backup_root / 'manifest.json'
        self.original_manifest = tree_manifest(self.app)
        signature_override = mock.patch('patch_kakaotalk.verify_signature')
        signature_override.start()
        self.addCleanup(signature_override.stop)

    def tearDown(self):
        self.tempdir.cleanup()

    def apply(self):
        return apply_patch(self.app, self.backup_root, self.spec)

    def restore(self):
        return restore_patch(self.app, self.backup_root, self.spec)


class LifecycleTests(LifecycleFixture, unittest.TestCase):
    def test_backup_preserves_every_entry_and_safe_symlinks(self):
        before = self.binary.stat().st_mtime_ns
        self.assertEqual(self.apply(), AppState.PATCHED)
        self.assertEqual(tree_manifest(self.backup), self.original_manifest)
        self.assertEqual(inspect_app(self.backup, self.spec), AppState.ORIGINAL)
        self.assertEqual(inspect_app(self.app, self.spec), AppState.PATCHED)
        saved = json.loads(self.manifest_path.read_text())
        self.assertEqual(saved['entries'], self.original_manifest)
        for relative, expected in (
            ('Contents/Frameworks/Test.framework/Versions/Current', 'A'),
            ('Contents/Frameworks/Test.framework/Test', 'Versions/Current/Test'),
            ('Contents/Frameworks/Test.framework/Resources', 'Versions/Current/Resources'),
        ):
            link = self.backup / relative
            self.assertTrue(stat.S_ISLNK(link.lstat().st_mode))
            self.assertEqual(os.readlink(link), expected)
        self.assertEqual(self.code_resources.read_bytes(), b'original-code-resources\n')
        self.assertNotEqual(self.binary.stat().st_mtime_ns, before)

    def test_repeated_apply_does_not_rewrite_target_or_backup(self):
        self.apply()
        paths = (self.binary, self.backup / 'Contents/MacOS/KakaoTalk', self.manifest_path)
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]
        saved_backup_manifest = tree_manifest(self.backup)
        self.assertEqual(self.apply(), AppState.PATCHED)
        self.assertEqual([(p.read_bytes(), p.stat().st_mtime_ns) for p in paths], before)
        self.assertEqual(tree_manifest(self.backup), saved_backup_manifest)

    def test_corrupt_backup_and_manifest_are_never_overwritten(self):
        self.apply()
        original_saved = self.manifest_path.read_bytes()
        resource = self.backup / 'Contents/Resources/original.txt'
        original_resource = resource.read_bytes()
        for name, damage, repair in (
            ('changed', lambda: resource.write_bytes(b'corrupt backup'), lambda: resource.write_bytes(original_resource)),
            ('missing', resource.unlink, lambda: resource.write_bytes(original_resource)),
            ('extra', lambda: (self.backup / 'extra').write_text('unexpected'), (self.backup / 'extra').unlink),
        ):
            with self.subTest(backup=name):
                damage()
                with self.assertRaises(PatchError):
                    self.apply()
                with self.assertRaises(PatchError):
                    self.restore()
                self.assertEqual(self.manifest_path.read_bytes(), original_saved)
                repair()
        self.manifest_path.write_text('{"entries": {}}\n')
        with self.assertRaises(PatchError):
            self.apply()
        with self.assertRaises(PatchError):
            self.restore()
        self.assertEqual(self.manifest_path.read_text(), '{"entries": {}}\n')
        self.manifest_path.write_bytes(original_saved)
        (self.backup / 'Contents/MacOS/KakaoTalk').write_bytes(patched_executable(self.original, self.spec))
        with self.assertRaises(PatchError):
            self.apply()
        with self.assertRaises(PatchError):
            self.restore()

    def test_restore_repairs_signature_metadata_without_current_signature_check(self):
        self.apply()
        signed = bytearray(self.signed_patch())
        self.binary.write_bytes(signed)
        self.code_resources.write_bytes(b'damaged-code-resources\n')
        self.assertEqual(self.restore(), AppState.ORIGINAL)
        self.assertEqual(sha256(self.binary.read_bytes()), self.spec.original_sha256)
        self.assertEqual(self.code_resources.read_bytes(), b'original-code-resources\n')
        before = (self.binary.stat().st_mtime_ns, self.code_resources.stat().st_mtime_ns)
        self.assertEqual(self.restore(), AppState.ORIGINAL)
        self.assertEqual((self.binary.stat().st_mtime_ns, self.code_resources.stat().st_mtime_ns), before)
        self.code_resources.write_bytes(b'damaged again\n')
        self.assertEqual(self.restore(), AppState.ORIGINAL)
        self.assertEqual(self.code_resources.read_bytes(), b'original-code-resources\n')

    def test_arbitrary_damaged_executable_is_not_automatically_restored(self):
        self.apply()
        self.binary.write_bytes(b'arbitrary damaged executable')
        with self.assertRaises(PatchError):
            self.restore()
        self.assertEqual(self.binary.read_bytes(), b'arbitrary damaged executable')

    def test_validation_failure_does_not_create_backup(self):
        before = self.binary.read_bytes()
        for patch in self.spec.patches:
            data = bytearray(before)
            data[patch.file_offset:patch.file_offset + len(patch.original)] = patch.replacement
            self.binary.write_bytes(data)
            with self.assertRaises(PatchError):
                self.apply()
            self.assertFalse(self.backup_root.exists())
            self.binary.write_bytes(before)
        with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
            info = dict(self.info)
            info['CFBundleVersion'] = 'other'
            plistlib.dump(info, stream)
        with self.assertRaises(PatchError):
            self.apply()
        self.assertFalse(self.backup_root.exists())
        self.assertEqual(self.binary.read_bytes(), before)
        with self.app.joinpath('Contents/Info.plist').open('wb') as stream:
            plistlib.dump(self.info, stream)

    def test_exact_process_gate_never_matches_installed_application(self):
        processes = []
        try:
            exact = subprocess.Popen([str(self.binary), '30'], executable='/bin/sleep')
            processes.append(exact)
            with self.assertRaises(PatchError):
                self.apply()
            with self.assertRaises(PatchError):
                self.restore()
            self.assertFalse(self.backup_root.exists())
            exact.terminate()
            exact.wait(timeout=5)
            processes.remove(exact)
            other = subprocess.Popen(['/Applications/KakaoTalk.app/Contents/MacOS/KakaoTalk', '30'], executable='/bin/sleep')
            processes.append(other)
            self.assertEqual(self.apply(), AppState.PATCHED)
            self.assertTrue(other.poll() is None)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)

    def test_atomic_failures_preserve_existing_files_and_remove_temps(self):
        original = self.binary.read_bytes()
        for name, target in (('write', 'patch_kakaotalk.os.write'), ('replace', 'patch_kakaotalk.os.replace')):
            with self.subTest(apply=name):
                with mock.patch(target, side_effect=OSError('injected failure')):
                    with self.assertRaises(PatchError):
                        self.apply()
                self.assertEqual(self.binary.read_bytes(), original)
                self.assertEqual(list(self.binary.parent.glob('.KakaoTalk.adblock-*')), [])
        self.apply()
        patched = self.binary.read_bytes()
        for name, target in (('write', 'patch_kakaotalk.os.write'), ('replace', 'patch_kakaotalk.os.replace')):
            with self.subTest(restore=name):
                with mock.patch(target, side_effect=OSError('injected failure')):
                    with self.assertRaises(PatchError):
                        self.restore()
                self.assertEqual(self.binary.read_bytes(), patched)
                self.assertEqual(list(self.binary.parent.glob('.KakaoTalk.adblock-*')), [])

    def test_partial_restore_is_actionable_and_retryable(self):
        self.apply()
        self.code_resources.write_bytes(b'new-signature-resources\n')
        backup_manifest = tree_manifest(self.backup)
        real_replace = os.replace
        calls = []
        def fail_second(source, destination):
            calls.append(Path(destination))
            if len(calls) == 2:
                raise OSError('injected second-file failure')
            return real_replace(source, destination)
        with mock.patch('patch_kakaotalk.os.replace', side_effect=fail_second):
            with self.assertRaisesRegex(PatchError, 'restore|Restore'):
                self.restore()
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertEqual(self.code_resources.read_bytes(), b'new-signature-resources\n')
        self.assertEqual(tree_manifest(self.backup), backup_manifest)
        self.assertEqual(self.restore(), AppState.ORIGINAL)
        self.assertEqual(self.code_resources.read_bytes(), b'original-code-resources\n')

    def test_resource_add_remove_and_change_are_rejected(self):
        self.apply()
        extra = self.app / 'Contents/Resources/extra.txt'
        for name, mutate, repair in (
            ('changed', lambda: self.resource.write_text('changed'), lambda: self.resource.write_text('original resource\n')),
            ('removed', self.resource.unlink, lambda: self.resource.write_text('original resource\n')),
            ('added', lambda: extra.write_text('extra'), extra.unlink),
        ):
            with self.subTest(resource=name):
                mutate()
                with self.assertRaises(PatchError):
                    verify_unchanged_resources(self.app, self.backup)
                with self.assertRaises(PatchError):
                    self.restore()
                self.assertEqual(inspect_app(self.app, self.spec), AppState.PATCHED)
                repair()
        self.assertEqual(self.restore(), AppState.ORIGINAL)

    def test_short_writes_complete_and_zero_write_preserves_current_file(self):
        real_write = os.write
        calls = 0
        def short_write(descriptor, data):
            nonlocal calls
            calls += 1
            return real_write(descriptor, data[:1] if calls == 1 else data)
        with mock.patch('patch_kakaotalk.os.write', side_effect=short_write):
            self.assertEqual(self.apply(), AppState.PATCHED)
        self.assertGreater(calls, 1)
        patched = self.binary.read_bytes()
        with mock.patch('patch_kakaotalk.os.write', return_value=0):
            with self.assertRaises(PatchError):
                self.restore()
        self.assertEqual(self.binary.read_bytes(), patched)
        self.assertEqual(list(self.binary.parent.glob('.KakaoTalk.adblock-*')), [])

    def test_source_mutation_during_staging_aborts_without_backup_commit(self):
        real_copy2 = shutil.copy2
        mutated = False
        def mutate_resource(source, destination, **kwargs):
            nonlocal mutated
            if Path(source) == self.resource and not mutated:
                mutated = True
                self.resource.write_text('changed during backup\n')
            return real_copy2(source, destination, **kwargs)
        with mock.patch('patch_kakaotalk.shutil.copy2', side_effect=mutate_resource):
            with self.assertRaises(PatchError):
                self.apply()
        self.assertTrue(mutated)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.manifest_path.exists())
        self.assertEqual(list(self.backup_root.glob('.adblock-staging-*')), [])
        self.assertEqual(self.binary.read_bytes(), self.original)

    def test_partial_backup_pairs_are_never_overwritten(self):
        self.backup_root.mkdir()
        self.manifest_path.write_text('incomplete manifest\n')
        with self.assertRaises(PatchError):
            self.apply()
        with self.assertRaises(PatchError):
            self.restore()
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.manifest_path.read_text(), 'incomplete manifest\n')
        self.manifest_path.unlink()
        backup_app(self.app, self.backup_root, self.spec)
        saved_entries = tree_manifest(self.backup)
        self.manifest_path.unlink()
        with self.assertRaises(PatchError):
            self.apply()
        with self.assertRaises(PatchError):
            self.restore()
        self.assertFalse(self.manifest_path.exists())
        self.assertEqual(tree_manifest(self.backup), saved_entries)
        self.assertEqual(self.binary.read_bytes(), self.original)

    def test_internal_dangling_link_remains_a_link_in_backup(self):
        dangling = self.resource.parent / 'dangling'
        dangling.symlink_to('missing/Info.plist')
        expected = tree_manifest(self.app)
        self.assertEqual(self.apply(), AppState.PATCHED)
        copied = self.backup / dangling.relative_to(self.app)
        self.assertTrue(stat.S_ISLNK(copied.lstat().st_mode))
        self.assertEqual(os.readlink(copied), 'missing/Info.plist')
        self.assertEqual(tree_manifest(self.backup), expected)

    def test_hardlink_tampering_with_verified_backup_is_rejected(self):
        self.apply()
        saved_manifest = self.manifest_path.read_bytes()
        backup_resource = self.backup / self.resource.relative_to(self.app)
        external = self.root / 'external-hardlink'
        os.link(backup_resource, external)
        external.write_text('modified through hardlink\n')
        with self.assertRaises(PatchError):
            self.apply()
        with self.assertRaises(PatchError):
            self.restore()
        self.assertEqual(self.manifest_path.read_bytes(), saved_manifest)
        external.unlink()
        backup_executable = self.backup / 'Contents/MacOS/KakaoTalk'
        os.link(backup_executable, external)
        with self.assertRaises(PatchError):
            self.apply()
        with self.assertRaises(PatchError):
            self.restore()
        self.assertEqual(self.manifest_path.read_bytes(), saved_manifest)

    def test_production_target_cannot_mutate_another_application_or_installed_backup(self):
        installed = Path('/Applications/KakaoTalk.app')
        with mock.patch('patch_kakaotalk.inspect_app', side_effect=PatchError('unauthorized inspection boundary')):
            with self.assertRaisesRegex(PatchError, 'authorized|installed'):
                apply_patch(installed, self.backup_root, TARGET)
        installed_backup = installed / '.adblock-test-backups'
        with mock.patch('patch_kakaotalk._require_local_path', side_effect=PatchError('filesystem boundary')):
            with self.assertRaisesRegex(PatchError, 'authorized|installed'):
                apply_patch(self.app, installed_backup, self.spec)
        with mock.patch('patch_kakaotalk._require_local_path', side_effect=PatchError('filesystem boundary')):
            with self.assertRaisesRegex(PatchError, 'installed'):
                backup_app(self.app, installed_backup, self.spec)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup_root.exists())

    def test_missing_code_resources_blocks_backup_and_apply(self):
        self.code_resources.unlink()
        with self.assertRaisesRegex(PatchError, 'CodeResources'):
            self.apply()
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.manifest_path.exists())

    def test_symlink_code_resources_blocks_backup_and_apply(self):
        self.code_resources.unlink()
        self.code_resources.symlink_to('../Resources/original.txt')
        with self.assertRaisesRegex(PatchError, 'CodeResources'):
            self.apply()
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.manifest_path.exists())

    def test_code_resources_changed_after_backup_validation_is_not_restored(self):
        self.apply()
        current_resources = self.code_resources.read_bytes()
        import patch_kakaotalk as patcher
        real_validate = patcher._validate_backup
        def change_after_validation(app, backup_root, target):
            backup = real_validate(app, backup_root, target)
            (backup / 'Contents/_CodeSignature/CodeResources').write_bytes(b'tampered after validation\n')
            return backup
        with mock.patch('patch_kakaotalk._validate_backup', side_effect=change_after_validation):
            with self.assertRaisesRegex(PatchError, 'CodeResources|manifest'):
                self.restore()
        self.assertEqual(inspect_app(self.app, self.spec), AppState.PATCHED)
        self.assertEqual(self.code_resources.read_bytes(), current_resources)

    def test_staging_cleanup_failure_preserves_original_error_context(self):
        with mock.patch('patch_kakaotalk.shutil.copytree', side_effect=OSError('injected copy failure')), \
                mock.patch('patch_kakaotalk.shutil.rmtree', side_effect=OSError('injected cleanup failure')):
            with self.assertRaises(PatchError) as caught:
                backup_app(self.app, self.backup_root, self.spec)
        self.assertIn('injected copy failure', str(caught.exception))
        self.assertIn('injected cleanup failure', str(caught.exception))
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.manifest_path.exists())

    def test_unsafe_backup_and_bundle_links_are_rejected(self):
        with self.assertRaises(PatchError):
            backup_app(self.app, self.app / '.backups', self.spec)
        self.assertFalse((self.app / '.backups').exists())
        outside = self.root / 'outside'
        outside.mkdir()
        root_link = self.root / 'linked-backups'
        root_link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(PatchError):
            backup_app(self.app, root_link, self.spec)
        for name, links in (
            ('absolute', [('bad', '/absolute')]),
            ('escaping', [('bad', '../../../outside')]),
            ('expanded escape', [('up', '../..'), ('bad', 'up/../outside')]),
            ('loop', [('loop-a', 'loop-b'), ('loop-b', 'loop-a')]),
        ):
            with self.subTest(link=name):
                paths = []
                for link_name, destination in links:
                    link = self.resource.parent / link_name
                    link.symlink_to(destination)
                    paths.append(link)
                with self.assertRaises(PatchError):
                    tree_manifest(self.app)
                with self.assertRaises(PatchError):
                    self.apply()
                for link in paths:
                    link.unlink()
        self.assertEqual(self.apply(), AppState.PATCHED)


class CommandTests(TargetFixture, unittest.TestCase):
    ENTITLEMENTS = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>test</key><true/></dict></plist>'

    def setUp(self):
        super().setUp()
        source_app = self.app
        self.root = Path(tempfile.mkdtemp(prefix='cli-', dir=self.fixture_root))
        self.app = self.root / 'KakaoTalk.app'
        shutil.copytree(source_app, self.app, symlinks=True, copy_function=shutil.copy2)
        self.binary = self.app / 'Contents/MacOS/KakaoTalk'
        self.backup_root = self.root / '.adblock-backups'
        self.backup = self.backup_root / 'KakaoTalk-26.9.0-2006.app'
        self.manifest_path = self.backup_root / 'manifest.json'
        self.paths = (self.backup_root, self.backup, self.manifest_path)
        self.resource = self.app / 'Contents/Resources/original.txt'
        self.resource.parent.mkdir(parents=True, exist_ok=True)
        self.resource.write_text('original resource\n')
        self.code_resources = self.app / 'Contents/_CodeSignature/CodeResources'
        self.code_resources.parent.mkdir(parents=True, exist_ok=True)
        self.code_resources.write_text('original signature metadata\n')
        target_override = mock.patch('patch_kakaotalk.TARGET', self.spec)
        target_override.start()
        self.addCleanup(target_override.stop)
        root_override = mock.patch('patch_kakaotalk._PROJECT_ROOT', self.root)
        root_override.start()
        self.addCleanup(root_override.stop)
        signature_override = mock.patch('patch_kakaotalk.verify_signature')
        signature_override.start()
        self.addCleanup(signature_override.stop)

    def make_patched_backup(self):
        backup_app(self.app, self.backup_root, self.spec)
        self.binary.write_bytes(self.pure_patch())

    def invoke(self, command):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main([command])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_original_status_is_read_only_without_a_backup(self):
        result, output, error = self.invoke('status')
        self.assertEqual((result, error), (0, ''))
        self.assertIn('ORIGINAL', output)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertFalse(self.backup_root.exists())

    def test_patched_status_verifies_signature_and_canonical_entitlements(self):
        self.make_patched_backup()
        alternate = self.ENTITLEMENTS.replace(b'<dict>', b'\n  <dict>')
        with mock.patch('patch_kakaotalk.verify_signature') as verify, \
                mock.patch('patch_kakaotalk.extract_entitlements', side_effect=[self.ENTITLEMENTS, alternate]), \
                mock.patch('patch_kakaotalk.resign_app') as resign:
            result, output, error = self.invoke('status')
        self.assertEqual((result, error), (0, ''))
        self.assertIn('PATCHED', output)
        verify.assert_has_calls((mock.call(self.backup), mock.call(self.app)))
        resign.assert_not_called()

    def test_apply_signs_patched_executable_with_backup_entitlements(self):
        with mock.patch('patch_kakaotalk.extract_entitlements', return_value=self.ENTITLEMENTS), \
                mock.patch('patch_kakaotalk.resign_app') as resign:
            result, output, error = self.invoke('apply')
        self.assertEqual((result, error), (0, ''))
        self.assertIn('PATCHED', output)
        self.assertEqual(inspect_app(self.app, self.spec), AppState.PATCHED)
        self.assertEqual((self.backup / 'Contents/MacOS/KakaoTalk').read_bytes(), self.original)
        self.assertEqual(resign.call_args.args[1], self.ENTITLEMENTS)

    def test_signed_patched_apply_does_not_rewrite_or_resign(self):
        self.make_patched_backup()
        watched = (self.binary, self.code_resources, self.backup / 'Contents/MacOS/KakaoTalk', self.manifest_path)
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in watched}
        with mock.patch('patch_kakaotalk.verify_signature'), \
                mock.patch('patch_kakaotalk.extract_entitlements', side_effect=[self.ENTITLEMENTS, self.ENTITLEMENTS]), \
                mock.patch('patch_kakaotalk.resign_app') as resign:
            result, output, error = self.invoke('apply')
        self.assertEqual((result, error), (0, ''))
        resign.assert_not_called()
        self.assertEqual({path: (path.read_bytes(), path.stat().st_mtime_ns) for path in watched}, before)

    def test_signing_failure_restores_and_verifies_original(self):
        original_resources = self.code_resources.read_bytes()
        def failed_signing(app, entitlements, target, *, allow_installed=False):
            self.binary.write_bytes(b'partially-signed-executable')
            self.code_resources.write_bytes(b'partially-signed-resources')
            raise PatchError('injected signing failure')
        with mock.patch('patch_kakaotalk.extract_entitlements', side_effect=[self.ENTITLEMENTS, self.ENTITLEMENTS, self.ENTITLEMENTS]), \
                mock.patch('patch_kakaotalk.resign_app', side_effect=failed_signing), \
                mock.patch('patch_kakaotalk.verify_signature') as verify:
            result, output, error = self.invoke('apply')
        self.assertEqual(result, 1)
        self.assertIn('injected signing failure', error)
        self.assertIn('ORIGINAL', error)
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertEqual(self.code_resources.read_bytes(), original_resources)
        self.assertEqual(inspect_app(self.app, self.spec), AppState.ORIGINAL)
        verify.assert_has_calls((mock.call(self.backup), mock.call(self.app)))

    def test_rollback_failure_reports_backup_and_manual_restore(self):
        with mock.patch('patch_kakaotalk.extract_entitlements', return_value=self.ENTITLEMENTS), \
                mock.patch('patch_kakaotalk.resign_app', side_effect=PatchError('injected signing failure')), \
                mock.patch('patch_kakaotalk.restore_patch', side_effect=PatchError('injected rollback failure')):
            result, output, error = self.invoke('apply')
        self.assertEqual(result, 1)
        self.assertIn(str(self.backup), error)
        self.assertIn('restore', error)
        self.assertIn('injected rollback failure', error)
        self.assertEqual(inspect_app(self.app, self.spec), AppState.PATCHED)
        self.assertTrue((self.backup / 'Contents/MacOS/KakaoTalk').is_file())

    def test_restore_verifies_original_signature_and_bad_commands_fail(self):
        self.make_patched_backup()
        self.code_resources.write_text('patched signature metadata\n')
        with mock.patch('patch_kakaotalk.verify_signature') as verify:
            result, output, error = self.invoke('restore')
        self.assertEqual((result, error), (0, ''))
        self.assertIn('ORIGINAL', output)
        verify.assert_has_calls((mock.call(self.backup), mock.call(self.app)))
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertEqual(self.code_resources.read_text(), 'original signature metadata\n')
        result, output, error = self.invoke('not-a-command')
        self.assertEqual(result, 2)
        self.assertIn('status|apply|restore', error)

    def test_malformed_entitlements_are_rejected_before_signing(self):
        with mock.patch('patch_kakaotalk.subprocess.run') as run:
            with self.assertRaises(PatchError):
                resign_app(self.root / 'absent.app', b'not a plist')
        run.assert_not_called()


    def test_resigning_refuses_a_running_target_before_codesign(self):
        self.make_patched_backup()
        with mock.patch('patch_kakaotalk._refuse_running_target', side_effect=PatchError('running target')), \
                mock.patch('patch_kakaotalk._run') as run:
            with self.assertRaisesRegex(PatchError, 'running target'):
                resign_app(self.app, self.ENTITLEMENTS)
        run.assert_not_called()
        self.assertEqual(self.binary.read_bytes(), self.pure_patch())

    def test_entitlement_extraction_failure_precedes_executable_mutation(self):
        with mock.patch('patch_kakaotalk.extract_entitlements', side_effect=PatchError('entitlement extraction failed')), \
                mock.patch('patch_kakaotalk.resign_app') as resign:
            result, output, error = self.invoke('apply')
        self.assertEqual(result, 1)
        self.assertIn('entitlement extraction failed', error)
        resign.assert_not_called()
        self.assertEqual(self.binary.read_bytes(), self.original)
        self.assertTrue(self.backup.is_dir())

    def test_original_signature_failure_blocks_status_backup_and_apply(self):
        for command in ('status', 'apply'):
            with self.subTest(command=command), \
                    mock.patch('patch_kakaotalk.verify_signature', side_effect=PatchError('invalid original signature')):
                result, output, error = self.invoke(command)
                self.assertEqual(result, 1)
                self.assertIn('invalid original signature', error)
                self.assertEqual(self.binary.read_bytes(), self.original)
                self.assertFalse(self.backup_root.exists())

    def test_damaged_backup_signature_blocks_patched_signing(self):
        self.make_patched_backup()
        def verify(app):
            if Path(app) == self.backup:
                raise PatchError('invalid backup signature')
        with mock.patch('patch_kakaotalk.verify_signature', side_effect=verify), \
                mock.patch('patch_kakaotalk.extract_entitlements', return_value=self.ENTITLEMENTS), \
                mock.patch('patch_kakaotalk.resign_app') as resign:
            result, output, error = self.invoke('apply')
        self.assertEqual(result, 1)
        self.assertIn('invalid backup signature', error)
        resign.assert_not_called()
        self.assertEqual(self.binary.read_bytes(), self.pure_patch())

class RealSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(dir='/private/tmp')
        cls.root = Path(cls.tempdir.name)
        if inspect_app(REAL_APP) == AppState.ORIGINAL:
            cls.source = REAL_APP
        else:
            cls.source = REAL_APP.parent / '.adblock-backups/KakaoTalk-26.9.0-2006.app'
            if inspect_app(cls.source) != AppState.ORIGINAL:
                raise unittest.SkipTest('A verified original full-app backup is required for signing tests')
        cls.app = cls.root / 'KakaoTalk.app'
        shutil.copytree(cls.source, cls.app, symlinks=True, copy_function=shutil.copy2)
        cls.binary = cls.app / 'Contents/MacOS/KakaoTalk'
        cls.original = (cls.source / 'Contents/MacOS/KakaoTalk').read_bytes()
        cls.before = tree_manifest(cls.app)
        cls.nested_signatures = {
            relative: entry['sha256'] for relative, entry in cls.before.items()
            if relative.endswith('/_CodeSignature/CodeResources')
            and relative != 'Contents/_CodeSignature/CodeResources'
        }
        cls.entitlements = extract_entitlements(cls.source)
        cls.binary.write_bytes(patched_executable(cls.original))
        invalid = subprocess.run(
            ['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(cls.app)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        cls.invalid_returncode = invalid.returncode
        resign_app(cls.app, cls.entitlements)
        cls.after = tree_manifest(cls.app)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_patched_signature_was_invalid_then_deep_strict_valid(self):
        self.assertNotEqual(self.invalid_returncode, 0)
        verified = subprocess.run(
            ['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(self.app)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode(errors='replace'))
        self.assertEqual(inspect_app(self.app), AppState.PATCHED)
        self.assertEqual(plistlib.loads(extract_entitlements(self.app)), plistlib.loads(self.entitlements))

    def test_only_top_level_executable_and_code_resources_changed(self):
        changed = {path for path in self.before if self.before[path] != self.after[path]}
        self.assertEqual(changed, {'Contents/MacOS/KakaoTalk', 'Contents/_CodeSignature/CodeResources'})
        verify_unchanged_resources(self.app, self.source)
        self.assertTrue(self.nested_signatures)
        self.assertEqual({path: self.after[path]['sha256'] for path in self.nested_signatures}, self.nested_signatures)

    def test_real_signed_slices_normalize_to_original_and_retain_architectures(self):
        data = bytearray(self.binary.read_bytes())
        for patch in TARGET.patches:
            self.assertEqual(data[patch.file_offset:patch.file_offset + len(patch.replacement)], patch.replacement)
            data[patch.file_offset:patch.file_offset + len(patch.original)] = patch.original
        self.assertEqual(normalize_fixture(data, TARGET), TARGET.normalized_original_sha256)
        architectures = subprocess.run(
            ['/usr/bin/lipo', '-info', str(self.binary)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(architectures.returncode, 0, architectures.stderr.decode(errors='replace'))
        self.assertIn('x86_64', architectures.stdout.decode())
        self.assertIn('arm64', architectures.stdout.decode())


if __name__ == '__main__':
    unittest.main()
