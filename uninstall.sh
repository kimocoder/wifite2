#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
script_path="$script_dir/$(basename -- "$0")"
active_venv=${WIFITE_UNINSTALL_VENV:-${VIRTUAL_ENV:-}}
poetry_env=${WIFITE_UNINSTALL_POETRY_ENV:-}

if [ -z "$poetry_env" ] && command -v poetry >/dev/null 2>&1; then
    poetry_env=$(cd "$script_dir" && poetry env info --path 2>/dev/null || true)
fi

uninstall_python_install() {
    python_path=$1
    if [ -x "$python_path" ] && "$python_path" -m pip show wifite2 >/dev/null 2>&1; then
        if ! "$python_path" -m pip uninstall -y wifite2; then
            "$python_path" -m pip uninstall -y --break-system-packages wifite2
        fi
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo env \
            WIFITE_UNINSTALL_VENV="$active_venv" \
            WIFITE_UNINSTALL_POETRY_ENV="$poetry_env" \
            "$script_path" "$@"
    fi
    printf '%s\n' 'Run this uninstaller as root (for example: sudo ./uninstall.sh).' >&2
    exit 1
fi

if [ -n "$active_venv" ]; then
    uninstall_python_install "$active_venv/bin/python"
fi
uninstall_python_install "$script_dir/.venv/bin/python"
uninstall_python_install "$script_dir/venv/bin/python"
if [ -n "$poetry_env" ]; then
    uninstall_python_install "$poetry_env/bin/python"
fi

if command -v dpkg-query >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    dpkg_status=$(dpkg-query -W -f='${db:Status-Status}' wifite 2>/dev/null || true)
    if [ "$dpkg_status" = 'installed' ]; then
        apt-get remove -y wifite
    fi
fi

if command -v python3 >/dev/null 2>&1; then
    uninstall_python_install "$(command -v python3)"
fi

printf '%s\n' 'Wifite application installs removed. Shared Python dependencies, virtual environments, this source checkout, and user data were left in place.'
