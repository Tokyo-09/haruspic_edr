#!/bin/sh
set -eu
setup_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Для Linux-мастера нужен Python 3.10 или новее.' >&2
    exit 1
fi
exec python3 -B "$setup_dir/installer/setup.py" "$@"
