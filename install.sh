#!/bin/bash
set -euo pipefail

apt install mininet openvswitch-switch python3-pip python3-venv
python3 -m venv venv
./venv/bin/python3 -m pip install -r requirements.txt
