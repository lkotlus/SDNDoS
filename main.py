import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from mininet.cli import CLI

from sdndos_network.hosts import create_network, start_servers

ROOT = Path(__file__).resolve().parent


def elevate_privileges():
    if os.geteuid() != 0:
        try:
            os.execvp(
                "sudo",
                [
                    "sudo",
                    sys.executable,
                    os.path.abspath(__file__),
                    *sys.argv[1:]
                ]
            )
        except OSError as e:
            print(f"Something went wrong while elevating privileges: {e}")
            sys.exit(1)


def start_controller(switch_path: str) -> subprocess.Popen:
    manager = Path(sys.executable).parent / "osken-manager"
    with open(ROOT / "controller.log", "w") as log:
        return subprocess.Popen(
            [str(manager), str(Path(switch_path).resolve())],
            stdout=log,
            stderr=subprocess.STDOUT,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoS-responding SDN testbed")
    parser.add_argument(
        "-s", "--num-servers", type=int, required=True,
        help="The number of internal servers running applications."
    )
    parser.add_argument(
        "-e", "--num-external", type=int, required=True,
        help="The number of external hosts to send traffic to the internal hosts."
    )
    parser.add_argument(
        "-S", "--switch", type=str, required=False,
        default="switch/switch.py",
        help="Path to the switch file you want to use."
    )
    args = parser.parse_args()

    elevate_privileges()

    osken = None
    topo = None
    procs = []

    try:
        osken = start_controller(args.switch)
        time.sleep(10)

        topo = create_network(args.num_servers, args.num_external)
        topo.net.start()

        procs = start_servers(topo.servers)
        CLI(topo.net)
    finally:
        for p in procs:
            p.terminate()

        if topo is not None:
            topo.net.stop()

        if osken is not None:
            osken.terminate()
            osken.wait()
