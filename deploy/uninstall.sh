#!/bin/sh
# Stdlib-only removal still works when the installed virtualenv is broken.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec /usr/bin/python3 "$SCRIPT_DIR/manage.py" uninstall "$@"
