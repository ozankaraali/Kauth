#!/bin/sh
# Use the installed crypto environment; identities never appear in arguments.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PYTHON=/opt/karaali-provisioning/.venv/bin/python
if [ ! -x "$PYTHON" ]; then
    case "${1-}" in
        --help|-h) exec /usr/bin/python3 "$SCRIPT_DIR/manage.py" reset "$@" ;;
    esac
    printf '%s\n' 'Reset requires the installed Python environment; repair it with the trusted installer first.' >&2
    exit 1
fi
exec "$PYTHON" "$SCRIPT_DIR/manage.py" reset "$@"
