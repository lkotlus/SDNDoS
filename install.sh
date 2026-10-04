#!/bin/bash
set -euo pipefail

sudo apt install mininet openvswitch-switch

curl -LsSf https://astral.sh/uv/install.sh | sh
uv python install 3.12
uv venv venv --python 3.12 --seed

./venv/bin/python3 -m pip install -r requirements.txt
