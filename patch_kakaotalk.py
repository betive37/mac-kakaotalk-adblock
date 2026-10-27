"""Validated, reversible patch primitives for the copied KakaoTalk application."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import plistlib
import posixpath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from xml.parsers.expat import ExpatError


class PatchError(RuntimeError):
    """The application or patch operation is not in a supported state."""


class AppState(Enum):
    ORIGINAL = 'ORIGINAL'
    PATCHED = 'PATCHED'


@dataclass(frozen=True)
class PatchSpec:
    architecture: str
    file_offset: int
    vm_address: int
    original: bytes
    replacement: bytes
    destination: int


@dataclass(frozen=True)
class SliceSpec:
    cpu: int
    offset: int
    size: int
    alignment: int
    signature_offset: int
    signature_size: int


@dataclass(frozen=True)
class TargetSpec:
    bundle_id: str
    version: str
    build: str
    original_sha256: str
    normalized_original_sha256: str
    slices: tuple[SliceSpec, ...]
    patches: tuple[PatchSpec, ...]


TARGET = TargetSpec(
    bundle_id='com.kakao.KakaoTalkMac',
    version='26.9.0',
    build='2006',
    original_sha256='456e1a3ed7a87168888bdb8c6e4894764a028e62c0af68562a760d9909d2bb65',
    normalized_original_sha256='4f76485c52cf22de8cfc44960ad7c4f1d3c57a2df33b34d8adf24678c8c69d01',
    slices=(
        SliceSpec(0x01000007, 0x4000, 0x287E1A0, 14, 0x2828E30, 0x55370),
        SliceSpec(0x0100000C, 0x2884000, 0x241EBC0, 14, 0x2407D30, 0x16E90),
    ),
    patches=(
        PatchSpec('x86_64', 0x1113896, 0x10110F896, b'\xA8\x01', b'\x30\xC0', 0x10110F943),
        PatchSpec('arm64', 0x378A55C, 0x100F0655C, b'\x80\x04\x00\x36', b'\x24\x00\x00\x14', 0x100F065EC),
    ),
)

_FAT_MAGIC = 0xCAFEBABE
_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
_LC_CODE_SIGNATURE = 0x1D
_EXECUTABLE = Path('Contents/MacOS/KakaoTalk')
_INFO = Path('Contents/Info.plist')
_PROJECT_ROOT = Path(os.path.abspath(__file__)).parent
_INSTALLED_APP = Path('/Applications/KakaoTalk.app')


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise PatchError(f'Cannot inspect required path {path}: {error}') from error


def _reject_symlink(path: Path) -> None:
    if stat.S_ISLNK(_lstat(path).st_mode):
        raise PatchError(f'Symlink is not allowed in an application mutation path: {path}')


def _forbid_installed_writes(path: Path) -> None:
    if path == _INSTALLED_APP or _INSTALLED_APP in path.parents:
        raise PatchError(f'Refusing to mutate or write inside the installed application: {path}')


def _require_authorized_copy(app: Path, backup_root: Path, target: TargetSpec) -> None:
    _forbid_installed_writes(app)
    _forbid_installed_writes(backup_root)
    if target == TARGET and app != _PROJECT_ROOT / 'KakaoTalk.app':
        raise PatchError(f'Only the adjacent authorized copied application may be mutated: {_PROJECT_ROOT / "KakaoTalk.app"}')
    if target == TARGET and backup_root != _PROJECT_ROOT / '.adblock-backups':
        raise PatchError(f'Only the adjacent authorized backup directory may be used: {_PROJECT_ROOT / ".adblock-backups"}')


def _reject_existing_symlink(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise PatchError(f'Cannot inspect path {path}: {error}') from error
    if stat.S_ISLNK(info.st_mode):
        raise PatchError(f'Symlink is not allowed in a mutation path: {path}')


def _absolute(path: Path) -> Path:
    # abspath normalizes '..' without resolving symlinks.
    return Path(os.path.abspath(os.fspath(path)))


def _require_local_path(path: Path) -> None:
    """Refuse mutation on a network/automounted filesystem."""
    try:
        result = subprocess.run(['/sbin/mount'], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PatchError(f'Cannot verify local filesystem for {path}: {error}') from error
    if result.returncode != 0:
        raise PatchError(f'Cannot inspect mounted filesystems: {result.stderr.strip()}')
    candidates = []
    for line in result.stdout.splitlines():
        match = re.match(r'^.+ on (.+) \(([^()]*)\)$', line)
        if not match:
            continue
        mountpoint = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), match.group(1))
        options = {option.strip() for option in match.group(2).split(',')}
        mounted = _absolute(Path(mountpoint))
        if path == mounted or mounted in path.parents:
            candidates.append((len(str(mounted)), options))
    if not candidates:
        raise PatchError(f'Cannot identify the filesystem containing {path}')
    if 'local' not in max(candidates)[1]:
        raise PatchError(f'Refusing mutation on a non-local filesystem: {path}')


def _open_regular(path: Path):
    expected = _lstat(path)
    if not stat.S_ISREG(expected.st_mode):
        raise PatchError(f'Expected a regular file: {path}')
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise PatchError(f'Cannot safely open {path}: {error}') from error
    try:
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise PatchError(f'File changed while it was being opened: {path}')
        return os.fdopen(descriptor, 'rb')
    except Exception:
        os.close(descriptor)
        raise


def _read_regular_bytes(path: Path) -> bytes:
    try:
        with _open_regular(path) as stream:
            return stream.read()
    except PatchError:
        raise
    except OSError as error:
        raise PatchError(f'Cannot read {path}: {error}') from error


def _app_paths(app: Path) -> tuple[Path, Path, Path]:
    app = _absolute(app)
    for parent in app.parents:
        _reject_symlink(parent)
    if not stat.S_ISDIR(_lstat(app).st_mode):
        raise PatchError(f'Application is not a real directory: {app}')
    info = app / _INFO
    executable = app / _EXECUTABLE
    for parent in (info.parent, executable.parent):
        _reject_symlink(parent)
    for path in (info, executable):
        if not stat.S_ISREG(_lstat(path).st_mode):
            raise PatchError(f'Required file is not a regular file: {path}')
    if _lstat(executable).st_nlink != 1:
        raise PatchError(f'Hard-linked executable is not supported: {executable}')
    return app, info, executable


def _verify_identity(info: Path, target: TargetSpec) -> None:
    try:
        properties = plistlib.loads(_read_regular_bytes(info))
        if not isinstance(properties, dict):
            raise PatchError(f'Info.plist is not a dictionary: {info}')
    except PatchError:
        raise
    except (OSError, ValueError, TypeError, ExpatError, plistlib.InvalidFileException) as error:
        raise PatchError(f'Cannot parse {info}: {error}') from error
    expected = {
        'CFBundleIdentifier': target.bundle_id,
        'CFBundleShortVersionString': target.version,
        'CFBundleVersion': target.build,
    }
    for key, value in expected.items():
        if properties.get(key) != value:
            raise PatchError(f'Unsupported {key}: expected {value!r}, found {properties.get(key)!r}')


def _range(data: bytes | bytearray, offset: int, size: int, end: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > end or size > end - offset or end > len(data):
        raise PatchError(f'Invalid or truncated {label}')


def _unpack(fmt: str, data: bytes | bytearray, offset: int, end: int, label: str):
    size = struct.calcsize(fmt)
    _range(data, offset, size, end, label)
    return struct.unpack_from(fmt, data, offset)


def _validate_layout(data: bytes | bytearray, target: TargetSpec) -> None:
    if len(target.slices) != 2 or len(data) < 8:
        raise PatchError('Expected a two-slice universal Mach-O executable')
    magic, count = struct.unpack_from('>II', data)
    if magic != _FAT_MAGIC or count != len(target.slices):
        raise PatchError('Unexpected universal Mach-O magic or slice count')
    _range(data, 8, count * 20, len(data), 'fat architecture table')
    architectures = [struct.unpack_from('>IIIII', data, 8 + index * 20) for index in range(len(target.slices))]
    expected_length = max(item[2] + item[3] for item in architectures)
    if len(data) != expected_length:
        raise PatchError(f'Executable size does not match current fat slices: expected {expected_length}, found {len(data)}')

    for index, slice_spec in enumerate(target.slices):
        cpu, _, offset, size, alignment = architectures[index]
        if (cpu, offset, alignment) != (slice_spec.cpu, slice_spec.offset, slice_spec.alignment):
            raise PatchError(f'Unexpected architecture or layout for slice {index}')
        if size > slice_spec.size or size < 32:
            raise PatchError(f'Unexpected slice size for slice {index}: {size:#x}')
        _range(data, offset, size, len(data), f'current slice {index}')
        if _unpack('<I', data, offset, offset + size, 'Mach-O header')[0] != _MH_MAGIC_64:
            raise PatchError(f'Expected 64-bit Mach-O header in slice {index}')
        command_count, commands_size = _unpack('<II', data, offset + 16, offset + size, 'Mach-O command counts')
        commands_start = offset + 32
        commands_end = commands_start + commands_size
        _range(data, commands_start, commands_size, offset + size, f'load commands for slice {index}')
        if command_count > commands_size // 8:
            raise PatchError(f'Invalid load-command count in slice {index}')
        position = commands_start
        signature = None
        linkedit = None
        for _ in range(command_count):
            command, command_size = _unpack('<II', data, position, commands_end, 'load-command header')
            if command_size < 8 or command_size % 8 or command_size > commands_end - position:
                raise PatchError(f'Invalid load-command size in slice {index}')
            if command == _LC_CODE_SIGNATURE:
                if signature is not None or command_size != 16:
                    raise PatchError(f'Invalid or duplicate code-signature command in slice {index}')
                signature_offset, signature_size = _unpack('<II', data, position + 8, commands_end, 'code-signature range')
                signature = (signature_offset, signature_size)
            elif command == _LC_SEGMENT_64 and data[position + 8:position + 24].rstrip(b'\0') == b'__LINKEDIT':
                if linkedit is not None or command_size < 72:
                    raise PatchError(f'Invalid or duplicate LINKEDIT command in slice {index}')
                linkedit = _unpack('<QQ', data, position + 40, commands_end, 'LINKEDIT file range')
            position += command_size
        if position != commands_end:
            raise PatchError(f'Load-command sizes do not match header in slice {index}')
        if signature is None or linkedit is None:
            raise PatchError(f'Missing LINKEDIT or code-signature command in slice {index}')
        signature_offset, signature_size = signature
        if signature_offset != slice_spec.signature_offset or signature_size > slice_spec.signature_size:
            raise PatchError(f'Unexpected signature reservation in slice {index}')
        if signature_offset + signature_size != size or signature_size == 0:
            raise PatchError(f'Signature must end at the current slice boundary in slice {index}')
        if signature_offset + slice_spec.signature_size != slice_spec.size:
            raise PatchError(f'Unexpected original signature reservation in slice {index}')
        signature_end = offset + signature_offset + signature_size
        original_end = offset + slice_spec.size
        if any(data[signature_end:original_end]):
            raise PatchError(f'Nonzero padding after shortened signature in slice {index}')
        linkedit_offset, linkedit_size = linkedit
        if linkedit_offset + linkedit_size != size:
            raise PatchError(f'LINKEDIT size is inconsistent with signature size in slice {index}')


def _normalized_sha256(original_code: bytes, target: TargetSpec) -> str:
    data = bytearray(original_code)
    signature_ranges = []
    for index, slice_spec in enumerate(target.slices):
        struct.pack_into('>I', data, 8 + index * 20 + 12, 0)
        position = slice_spec.offset + 32
        command_count, _ = struct.unpack_from('<II', original_code, slice_spec.offset + 16)
        for _ in range(command_count):
            command, command_size = struct.unpack_from('<II', original_code, position)
            if command == _LC_CODE_SIGNATURE:
                data[position + 8:position + 16] = b'\0' * 8
            elif command == _LC_SEGMENT_64 and original_code[position + 8:position + 24].rstrip(b'\0') == b'__LINKEDIT':
                data[position + 48:position + 56] = b'\0' * 8
            position += command_size
        start = slice_spec.offset + slice_spec.signature_offset
        signature_ranges.append((start, slice_spec.offset + slice_spec.size))
    for start, end in sorted(signature_ranges, reverse=True):
        del data[start:end]
    return hashlib.sha256(data).hexdigest()


def _read_executable(app: Path, target: TargetSpec) -> tuple[Path, bytes]:
    _, info, executable = _app_paths(app)
    _verify_identity(info, target)
    data = _read_regular_bytes(executable)
    _validate_layout(data, target)
    return executable, data


def inspect_app(app: Path, target: TargetSpec = TARGET) -> AppState:
    """Return only a fully supported original or patched application state."""
    _, data = _read_executable(app, target)
    digest = hashlib.sha256(data).hexdigest()
    if digest == target.original_sha256:
        if any(data[p.file_offset:p.file_offset + len(p.original)] != p.original for p in target.patches):
            raise PatchError('Original digest and patch-site bytes disagree')
        return AppState.ORIGINAL
    if any(data[p.file_offset:p.file_offset + len(p.replacement)] != p.replacement for p in target.patches):
        raise PatchError('Executable is neither the supported original nor a complete approved patch')
    restored = bytearray(data)
    for patch in target.patches:
        restored[patch.file_offset:patch.file_offset + len(patch.original)] = patch.original
    if _normalized_sha256(bytes(restored), target) != target.normalized_original_sha256:
        raise PatchError('Patched executable differs outside the approved signature metadata')
    return AppState.PATCHED


def patched_executable(original: bytes, target: TargetSpec = TARGET) -> bytes:
    """Return the original executable with exactly the two approved branch changes."""
    if not isinstance(original, bytes):
        raise PatchError('Original executable input must be bytes')
    _validate_layout(original, target)
    if hashlib.sha256(original).hexdigest() != target.original_sha256:
        raise PatchError('Refusing to patch an executable with an unexpected original digest')
    for patch in target.patches:
        if original[patch.file_offset:patch.file_offset + len(patch.original)] != patch.original:
            raise PatchError(f'Unexpected original bytes for {patch.architecture} patch')
    result = bytearray(original)
    for patch in target.patches:
        result[patch.file_offset:patch.file_offset + len(patch.original)] = patch.replacement
    return bytes(result)


_CODE_RESOURCES = Path('Contents/_CodeSignature/CodeResources')
_EXCLUDED_FROM_RESOURCE_CHECK = {_EXECUTABLE.as_posix(), _CODE_RESOURCES.as_posix()}


def _bundle_root(root: Path) -> Path:
    root = _absolute(root)
    for parent in root.parents:
        _reject_symlink(parent)
    if not stat.S_ISDIR(_lstat(root).st_mode):
        raise PatchError(f'Bundle root is not a real directory: {root}')
    return root


def _hash_regular(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with _open_regular(path) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except PatchError:
        raise
    except OSError as error:
        raise PatchError(f'Cannot hash {path}: {error}') from error
    return digest.hexdigest()


def _resolve_link(path: str, links: dict[str, str], visited: frozenset[str] = frozenset()) -> str:
    """Expand each symlink in path order, then apply the following component."""
    if posixpath.isabs(path):
        raise PatchError(f'Symlink escapes the application bundle: {path}')
    stack = path.split('/')
    resolved: list[str] = []
    while stack:
        part = stack.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise PatchError(f'Symlink escapes the application bundle: {path}')
            resolved.pop()
            continue
        prefix = posixpath.join(*resolved, part)
        if prefix not in links:
            resolved.append(part)
            continue
        if prefix in visited:
            raise PatchError(f'Symlink loop in application bundle at {prefix}')
        target = links[prefix]
        if posixpath.isabs(target):
            raise PatchError(f'Absolute symlink is not allowed: {prefix} -> {target}')
        target_parts = target.split('/') + stack
        parent_parts = prefix.split('/')[:-1]
        stack = parent_parts + target_parts
        resolved = []
        visited |= {prefix}
    return posixpath.join(*resolved) if resolved else '.'


def tree_manifest(root: Path) -> dict[str, dict[str, int | str]]:
    """Hash regular files but record, rather than follow, validated symlinks."""
    root = _bundle_root(root)
    entries: dict[str, dict[str, int | str]] = {'.': {'type': 'directory'}}
    links: dict[str, str] = {}

    def walk_error(error: OSError):
        raise PatchError(f'Cannot walk application bundle {root}: {error}') from error

    try:
        for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
            dirnames.sort()
            filenames.sort()
            for name in list(dirnames):
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                mode = _lstat(path).st_mode
                if stat.S_ISLNK(mode):
                    target = os.readlink(path)
                    entries[relative] = {'type': 'symlink', 'target': target}
                    links[relative] = target
                    dirnames.remove(name)
                elif stat.S_ISDIR(mode):
                    entries[relative] = {'type': 'directory'}
                else:
                    raise PatchError(f'Unsupported bundle entry: {path}')
            for name in filenames:
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                info = _lstat(path)
                if stat.S_ISREG(info.st_mode):
                    entries[relative] = {'type': 'file', 'size': info.st_size, 'sha256': _hash_regular(path)}
                elif stat.S_ISLNK(info.st_mode):
                    target = os.readlink(path)
                    entries[relative] = {'type': 'symlink', 'target': target}
                    links[relative] = target
                else:
                    raise PatchError(f'Unsupported bundle entry: {path}')
    except PatchError:
        raise
    except OSError as error:
        raise PatchError(f'Cannot inspect bundle entries under {root}: {error}') from error
    for relative in links:
        _resolve_link(relative, links)
    return {key: entries[key] for key in sorted(entries)}


def _backup_paths(app: Path, backup_root: Path, target: TargetSpec) -> tuple[Path, Path, Path]:
    app = _absolute(app)
    backup_root = _absolute(backup_root)
    if backup_root == app or app in backup_root.parents:
        raise PatchError('Backup root must not be inside the application bundle')
    if any(not isinstance(value, str) or Path(value).name != value or value in ('', '.', '..') for value in (target.version, target.build)):
        raise PatchError('Target version/build is unsafe for a backup filename')
    for path in (backup_root, *backup_root.parents):
        _reject_existing_symlink(path)
    _require_local_path(backup_root)
    if backup_root.exists() and not stat.S_ISDIR(_lstat(backup_root).st_mode):
        raise PatchError(f'Backup root is not a real directory: {backup_root}')
    backup = backup_root / f'KakaoTalk-{target.version}-{target.build}.app'
    manifest = backup_root / 'manifest.json'
    if backup == app or backup in app.parents:
        raise PatchError('Application and backup paths must be separate')
    for path in (backup, manifest):
        _reject_existing_symlink(path)
        if path.exists() and not stat.S_ISREG(_lstat(path).st_mode) and path == manifest:
            raise PatchError(f'Backup manifest is not a regular file: {path}')
    return backup_root, backup, manifest


def _manifest_document(backup: Path, target: TargetSpec) -> dict:
    return {
        'bundle_id': target.bundle_id,
        'version': target.version,
        'build': target.build,
        'entries': tree_manifest(backup),
    }


def _validate_backup(app: Path, backup_root: Path, target: TargetSpec) -> Path:
    _, backup, manifest_path = _backup_paths(app, backup_root, target)
    if not backup.exists() or not manifest_path.exists():
        message = f'Verified backup and manifest are both required: {backup}, {manifest_path}'
        if inspect_app(app, target) == AppState.PATCHED:
            message += (
                '. The application is already PATCHED. To register an existing verified '
                'full original backup, run `install.sh import-backup SOURCE_ROOT`'
            )
        raise PatchError(message)
    if not stat.S_ISDIR(_lstat(backup).st_mode):
        raise PatchError(f'Backup is not a real application directory: {backup}')
    if inspect_app(backup, target) != AppState.ORIGINAL:
        raise PatchError(f'Backup executable is not the supported ORIGINAL: {backup}')
    try:
        saved = json.loads(_read_regular_bytes(manifest_path))
    except PatchError:
        raise
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        raise PatchError(f'Cannot parse backup manifest {manifest_path}: {error}') from error
    expected = _manifest_document(backup, target)
    if saved != expected:
        raise PatchError(f'Backup manifest does not match every backup entry: {manifest_path}')
    _backup_code_resources(backup, saved['entries'][_CODE_RESOURCES.as_posix()])
    verify_signature(backup)
    return backup


def import_backup(
    app: Path, source_root: Path, backup_root: Path, target: TargetSpec | None = None,
) -> Path:
    """Register an explicit, verified original backup without modifying the app or source."""
    target = TARGET if target is None else target
    app = _absolute(app)
    source_root = _absolute(source_root)
    backup_root = _absolute(backup_root)
    source_backup = _validate_backup(app, source_root, target)
    verify_unchanged_resources(app, source_backup)
    _, backup, manifest_path = _backup_paths(app, backup_root, target)
    source_manifest = _read_regular_bytes(source_root / 'manifest.json')
    if backup_root == source_root:
        return source_backup
    if backup.exists() or manifest_path.exists():
        existing = _validate_backup(app, backup_root, target)
        if _read_regular_bytes(manifest_path) != source_manifest:
            raise PatchError(f'Existing destination backup differs from the source; refusing to overwrite: {backup_root}')
        return existing
    try:
        backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        for parent in (backup_root, *backup_root.parents):
            _reject_existing_symlink(parent)
        staging_root = Path(tempfile.mkdtemp(prefix='.adblock-import-', dir=backup_root))
    except OSError as error:
        raise PatchError(f'Cannot prepare backup import {backup_root}: {error}') from error
    staging_backup = staging_root / backup.name
    try:
        shutil.copytree(source_backup, staging_backup, symlinks=True, copy_function=shutil.copy2)
        manifest = staging_root / 'manifest.json'
        with manifest.open('xb') as stream:
            stream.write(source_manifest)
            stream.flush()
            os.fsync(stream.fileno())
        _validate_backup(app, staging_root, target)
        _validate_backup(app, source_root, target)
        if backup.exists() or manifest_path.exists():
            raise PatchError(f'Destination appeared during backup import; refusing to overwrite: {backup_root}')
        os.rename(staging_backup, backup)
        try:
            with manifest_path.open('xb') as stream:
                stream.write(source_manifest)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.rename(backup, staging_backup)
            raise
        _validate_backup(app, backup_root, target)
    except (OSError, shutil.Error, PatchError) as error:
        detail = str(error)
        try:
            if staging_root.exists():
                shutil.rmtree(staging_root)
        except OSError as cleanup_error:
            detail += f'; additionally, staging cleanup failed: {cleanup_error}'
        raise PatchError(f'Cannot import verified original backup {backup_root}: {detail}') from error
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)
    return backup


def backup_app(
    app: Path, backup_root: Path, target: TargetSpec = TARGET, *,
    allow_installed: bool = False,
) -> Path:
    app = _absolute(app)
    backup_root = _absolute(backup_root)
    if not allow_installed:
        _forbid_installed_writes(app)
        _forbid_installed_writes(backup_root)
    _require_local_path(app)
    if not allow_installed and target == TARGET and app != _PROJECT_ROOT / 'KakaoTalk.app':
        raise PatchError(f'Only the adjacent authorized copied application may be backed up: {_PROJECT_ROOT / "KakaoTalk.app"}')
    if inspect_app(app, target) != AppState.ORIGINAL:
        raise PatchError('A backup may only be created from the supported ORIGINAL application')
    verify_signature(app)
    _backup_code_resources(app)  # A backup is useful only if both restore sources are safe regular files.
    backup_root, backup, manifest_path = _backup_paths(app, backup_root, target)
    if backup.exists() or manifest_path.exists():
        return _validate_backup(app, backup_root, target)
    source_manifest = tree_manifest(app)
    try:
        backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as error:
        raise PatchError(f'Cannot create backup root {backup_root}: {error}') from error
    for parent in (backup_root, *backup_root.parents):
        _reject_existing_symlink(parent)
    try:
        staging = Path(tempfile.mkdtemp(prefix='.adblock-staging-', dir=backup_root))
    except OSError as error:
        raise PatchError(f'Cannot create a staging backup: {error}') from error
    try:
        shutil.copytree(app, staging, symlinks=True, copy_function=shutil.copy2, dirs_exist_ok=True)
        if tree_manifest(staging) != source_manifest or tree_manifest(app) != source_manifest:
            raise PatchError('Source changed during backup or staged backup differs; original backup not committed')
        if inspect_app(staging, target) != AppState.ORIGINAL or inspect_app(app, target) != AppState.ORIGINAL:
            raise PatchError('Source is no longer ORIGINAL; backup not committed')
        if backup.exists() or manifest_path.exists():
            raise PatchError('Backup appeared during creation; refusing to overwrite it')
        os.rename(staging, backup)
        document = _manifest_document(backup, target)
        with manifest_path.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(document, sort_keys=True, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, shutil.Error, PatchError) as error:
        cleanup_error = None
        if staging.exists():
            try:
                shutil.rmtree(staging)
            except OSError as failure:
                cleanup_error = failure
        detail = f'{error}; cleanup also failed, staging remains at {staging}: {cleanup_error}' if cleanup_error else str(error)
        if isinstance(error, PatchError) and not cleanup_error:
            raise
        raise PatchError(f'Cannot create verified backup {backup}: {detail}') from error
    return backup


def verify_unchanged_resources(app: Path, backup: Path) -> None:
    current = tree_manifest(app)
    original = tree_manifest(backup)
    for path in _EXCLUDED_FROM_RESOURCE_CHECK:
        current.pop(path, None)
        original.pop(path, None)
    if current != original:
        raise PatchError('Application resources differ from the verified backup; refusing automatic mutation')


def _refuse_running_target(app: Path) -> None:
    _, _, executable = _app_paths(app)
    pattern = '^' + re.escape(str(executable)) + r'($| )'
    try:
        result = subprocess.run(['pgrep', '-f', pattern], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PatchError(f'Cannot check whether the target application is running: {error}') from error
    if result.returncode == 1:
        return
    if result.returncode == 0 and result.stdout.strip():
        raise PatchError(f'Refusing to modify a running target application (PID(s): {result.stdout.strip()})')
    raise PatchError(f'Cannot establish an exact-target process gate: {result.stderr.strip() or result.stdout.strip()}')


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError('short write during atomic replacement')
        remaining = remaining[written:]


def _atomic_replace(path: Path, data: bytes, mode: int | None = None) -> bool:
    path = _absolute(path)
    for parent in path.parents:
        _reject_symlink(parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    except OSError as error:
        raise PatchError(f'Cannot inspect replacement target {path}: {error}') from error
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PatchError(f'Replacement target must be a single-link regular file: {path}')
        if _read_regular_bytes(path) == data:
            return False
        mode = stat.S_IMODE(info.st_mode) if mode is None else mode
    if mode is None:
        raise PatchError(f'No mode available for missing replacement target {path}')
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f'.{path.name}.adblock-', dir=path.parent)
    except OSError as error:
        raise PatchError(f'Cannot create temporary file beside {path}: {error}') from error
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = -1
            os.fchmod(stream.fileno(), stat.S_IMODE(mode))
            _write_all(stream.fileno(), data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            raise PatchError(f'Cannot replace {path}: {error}; also cannot remove temporary {temporary}: {cleanup_error}') from error
        raise PatchError(f'Cannot atomically replace {path}; previous file preserved: {error}') from error
    return True


def _backup_code_resources(backup: Path, expected: dict[str, int | str] | None = None) -> tuple[bytes, int]:
    path = backup / _CODE_RESOURCES
    info = _lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise PatchError(f'Backup CodeResources is not a regular file: {path}')
    data = _read_regular_bytes(path)
    if expected is not None and (expected.get('type') != 'file' or expected.get('size') != len(data)
            or expected.get('sha256') != hashlib.sha256(data).hexdigest()):
        raise PatchError(f'Backup CodeResources changed after validation or differs from its manifest: {path}')
    return data, stat.S_IMODE(info.st_mode)


def apply_patch(
    app: Path, backup_root: Path, target: TargetSpec = TARGET, *,
    allow_installed: bool = False,
) -> AppState:
    app = _absolute(app)
    backup_root = _absolute(backup_root)
    if not allow_installed:
        _require_authorized_copy(app, backup_root, target)
    _require_local_path(app)
    state = inspect_app(app, target)
    _refuse_running_target(app)
    backup = backup_app(app, backup_root, target, allow_installed=allow_installed) if state == AppState.ORIGINAL else _validate_backup(app, backup_root, target)
    verify_unchanged_resources(app, backup)
    if state == AppState.PATCHED:
        return AppState.PATCHED
    _refuse_running_target(app)
    state = inspect_app(app, target)
    if state == AppState.PATCHED:
        return AppState.PATCHED
    executable, original = _read_executable(app, target)
    replacement = patched_executable(original, target)
    _atomic_replace(executable, replacement)
    if inspect_app(app, target) != AppState.PATCHED:
        raise PatchError(f'Applied executable failed post-write validation; verified backup is {backup}')
    verify_unchanged_resources(app, backup)
    return AppState.PATCHED


def restore_patch(
    app: Path, backup_root: Path, target: TargetSpec = TARGET, *,
    recover_damaged: bool = False, allow_installed: bool = False,
) -> AppState:
    app = _absolute(app)
    backup_root = _absolute(backup_root)
    if not allow_installed:
        _require_authorized_copy(app, backup_root, target)
    _require_local_path(app)
    def current_state():
        try:
            return inspect_app(app, target)
        except PatchError:
            if not recover_damaged:
                raise
            # Only a known signing failure may recover a damaged executable.
            return None
    state = current_state()
    _refuse_running_target(app)
    backup = _validate_backup(app, backup_root, target)
    verify_unchanged_resources(app, backup)
    try:
        saved_manifest = json.loads(_read_regular_bytes(backup.parent / 'manifest.json'))
        expected_resources = saved_manifest['entries'][_CODE_RESOURCES.as_posix()]
    except (KeyError, TypeError, ValueError) as error:
        raise PatchError(f'Backup manifest cannot provide verified CodeResources metadata: {error}') from error
    original_resources, resources_mode = _backup_code_resources(backup, expected_resources)
    current_resources = app / _CODE_RESOURCES
    if state == AppState.ORIGINAL and current_resources.exists():
        if _read_regular_bytes(current_resources) == original_resources:
            return AppState.ORIGINAL
    _, original_executable = _read_executable(backup, target)
    if hashlib.sha256(original_executable).hexdigest() != target.original_sha256:
        raise PatchError(f'Backup executable changed after validation: {backup}')
    executable = app / _EXECUTABLE
    _refuse_running_target(app)
    state = current_state()
    if state == AppState.ORIGINAL and current_resources.exists() and _read_regular_bytes(current_resources) == original_resources:
        return AppState.ORIGINAL
    try:
        _atomic_replace(executable, original_executable)
    except PatchError as error:
        raise PatchError(f'Restore failed before executable replacement; previous file preserved. Verified backup: {backup}. Retry restore: {error}') from error
    try:
        _atomic_replace(current_resources, original_resources, resources_mode)
    except PatchError as error:
        raise PatchError(
            f'Restore incomplete: executable is restored but CodeResources may still be patched. '
            f'Verified backup preserved at {backup}; retry restore to repair it: {error}'
        ) from error
    if inspect_app(app, target) != AppState.ORIGINAL or _read_regular_bytes(current_resources) != original_resources:
        raise PatchError(f'Restore verification failed; verified backup preserved at {backup}. Retry restore')
    verify_unchanged_resources(app, backup)
    return AppState.ORIGINAL


def _run(command: list[str]) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PatchError(f'Cannot run {command[0]}: {error}') from error
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip()
        raise PatchError(f'{command[0]} failed ({result.returncode}): {detail or "no diagnostic output"}')
    return result


def _canonical_entitlements(data: bytes) -> bytes:
    try:
        value = plistlib.loads(data)
    except (ExpatError, plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise PatchError(f'Invalid entitlements plist: {error}') from error
    if not isinstance(value, dict):
        raise PatchError('Entitlements plist root must be a dictionary')
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def extract_entitlements(app: Path) -> bytes:
    app = _absolute(app)
    with tempfile.TemporaryDirectory(prefix='kakaotalk-adblock-entitlements-') as directory:
        output = Path(directory) / 'entitlements.plist'
        _run(['/usr/bin/codesign', '-d', '--entitlements', str(output), '--xml', str(app)])
        data = _read_regular_bytes(output)
    _canonical_entitlements(data)
    return data


def verify_signature(app: Path) -> None:
    _run(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(_absolute(app))])


def _require_entitlements(app: Path, original: bytes) -> None:
    if _canonical_entitlements(extract_entitlements(app)) != _canonical_entitlements(original):
        raise PatchError('Signed application entitlements differ from the verified original')


def resign_app(
    app: Path, original_entitlements: bytes, target: TargetSpec | None = None, *,
    allow_installed: bool = False,
) -> None:
    original = _canonical_entitlements(original_entitlements)
    app = _absolute(app)
    target = TARGET if target is None else target
    if not allow_installed:
        _forbid_installed_writes(app)
    _require_local_path(app)
    if inspect_app(app, target) != AppState.PATCHED:
        raise PatchError('Re-signing requires the supported PATCHED executable; refusing to sign another state')
    with tempfile.TemporaryDirectory(prefix='kakaotalk-adblock-signing-') as directory:
        entitlements = Path(directory) / 'entitlements.plist'
        descriptor = os.open(entitlements, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_all(descriptor, original)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _refuse_running_target(app)
        _run([
            '/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
            '--entitlements', str(entitlements), str(app),
        ])
    verify_signature(app)
    _require_entitlements(app, original)
    if inspect_app(app, target) != AppState.PATCHED:
        raise PatchError('Re-signing changed bytes outside the allowed signature metadata')


def _authorized_paths() -> tuple[Path, Path]:
    return _PROJECT_ROOT / 'KakaoTalk.app', _PROJECT_ROOT / '.adblock-backups'


def _sign_or_roll_back(
    app: Path, backup_root: Path, original_entitlements: bytes, *,
    target: TargetSpec | None = None, allow_installed: bool = False,
) -> None:
    target = TARGET if target is None else target
    _, backup, _ = _backup_paths(app, backup_root, target)
    try:
        resign_app(app, original_entitlements, target, allow_installed=allow_installed)
    except PatchError as signing_error:
        try:
            restore_patch(
                app, backup_root, target,
                recover_damaged=True, allow_installed=allow_installed,
            )
            verify_signature(app)
            _require_entitlements(app, original_entitlements)
        except PatchError as rollback_error:
            raise PatchError(
                f'{signing_error}; automatic rollback could not be verified: {rollback_error}. '
                f'Verified backup: {backup}. Preserve it and run `{"install.sh restore" if allow_installed else "python3 patch_kakaotalk.py restore"}` manually.'
            ) from rollback_error
        raise PatchError(
            f'{signing_error}; restored ORIGINAL executable and CodeResources, '
            'and verified the original signature and entitlements.'
        ) from signing_error


def _apply_signed(
    app: Path, backup_root: Path, *,
    target: TargetSpec | None = None, allow_installed: bool = False,
) -> AppState:
    target = TARGET if target is None else target
    if not allow_installed:
        _forbid_installed_writes(app)
        _forbid_installed_writes(backup_root)
    state = inspect_app(app, target)
    if state == AppState.PATCHED:
        backup = _validate_backup(app, backup_root, target)
        verify_unchanged_resources(app, backup)
        original_entitlements = extract_entitlements(backup)
        try:
            verify_signature(app)
            _require_entitlements(app, original_entitlements)
        except PatchError:
            pass  # An interrupted signing attempt is completed below; valid signed apps return above.
        else:
            return AppState.PATCHED
    else:
        verify_signature(app)
        backup = backup_app(app, backup_root, target, allow_installed=allow_installed)
        original_entitlements = extract_entitlements(backup)
        _require_entitlements(app, original_entitlements)
        apply_patch(app, backup_root, target, allow_installed=allow_installed)
        verify_unchanged_resources(app, backup)
    _sign_or_roll_back(app, backup_root, original_entitlements, target=target, allow_installed=allow_installed)
    return AppState.PATCHED


def run_command(
    command: str, app: Path, backup_root: Path, *,
    target: TargetSpec | None = None, allow_installed: bool = False,
) -> None:
    target = TARGET if target is None else target
    try:
        if command == 'status':
            state = inspect_app(app, target)
            _, backup_path, manifest_path = _backup_paths(app, backup_root, target)
            if state == AppState.PATCHED or backup_path.exists() or manifest_path.exists():
                backup = _validate_backup(app, backup_root, target)
                verify_unchanged_resources(app, backup)
                if state == AppState.PATCHED:
                    original_entitlements = extract_entitlements(backup)
                    verify_signature(app)
                    _require_entitlements(app, original_entitlements)
            if state == AppState.ORIGINAL:
                verify_signature(app)
            print(state.value + ('; signature verified' if state == AppState.ORIGINAL else '; signature and original entitlements verified'))
        elif command == 'apply':
            _apply_signed(app, backup_root, target=target, allow_installed=allow_installed)
            print('PATCHED; signature and original entitlements verified')
        else:
            restore_patch(app, backup_root, target, allow_installed=allow_installed)
            verify_signature(app)
            print('ORIGINAL; original signature verified')
    except PatchError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1 or arguments[0] not in ('status', 'apply', 'restore'):
        print('usage: python3 patch_kakaotalk.py status|apply|restore', file=sys.stderr)
        return 2
    app, backup_root = _authorized_paths()
    return run_command(arguments[0], app, backup_root)


if __name__ == '__main__':
    raise SystemExit(main())
