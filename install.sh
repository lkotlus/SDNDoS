#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch hping3 curl git

if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$PATH"
fi

uv python install 3.12
uv venv venv --python 3.12 --seed --clear

./venv/bin/python3 -m pip install -r requirements.txt
