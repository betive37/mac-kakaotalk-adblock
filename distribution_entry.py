"""Distribution CLI. Only this entrypoint authorizes installed-target writes."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import patch_kakaotalk as patcher

APP_VARIABLE = 'KAKAOTALK_ADBLOCK_APP'
BACKUP_VARIABLE = 'KAKAOTALK_ADBLOCK_BACKUP_ROOT'
USAGE = 'usage: install.sh [status|apply|restore] | install.sh import-backup SOURCE_ROOT'


def distribution_main(argv=None, environ=None) -> int:
    arguments = sys.argv[1:] if argv is None else list(argv)
    environment = os.environ if environ is None else environ
    arguments = arguments or ['apply']
    if arguments[0] not in ('status', 'apply', 'restore', 'import-backup'):
        print(USAGE, file=sys.stderr)
        return 2
    expected_arguments = 2 if arguments[0] == 'import-backup' else 1
    if len(arguments) != expected_arguments:
        print(USAGE, file=sys.stderr)
        return 2
    app_value = environment.get(APP_VARIABLE)
    backup_value = environment.get(BACKUP_VARIABLE)
    if bool(app_value) != bool(backup_value):
        print(f'error: set both {APP_VARIABLE} and {BACKUP_VARIABLE} for isolated testing', file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    if app_value:
        app = Path(app_value).expanduser()
        backup_root = Path(backup_value).expanduser()
    else:
        app = patcher._INSTALLED_APP
        backup_root = Path.home() / 'Library/Application Support/KakaoTalkAdblock/backups'
    if arguments[0] == 'import-backup':
        try:
            destination = patcher.import_backup(
                app, Path(arguments[1]).expanduser(), backup_root, patcher.TARGET,
            )
        except patcher.PatchError as error:
            print(f'error: {error}', file=sys.stderr)
            return 1
        print(f'Verified original backup registered: {destination}')
        return 0
    return patcher.run_command(
        arguments[0], patcher._absolute(app), patcher._absolute(backup_root),
        target=patcher.TARGET, allow_installed=True,
    )
