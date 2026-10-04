import argparse
import subprocess
import sys
import os

from mininet.cli import CLI

from sdndos_network.hosts import create_network, start_servers


def elevate_privileges():
    if os.geteuid() != 0:
        print("Mininet requires root:")
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
        except Exception as e:
            print(f"Something went wrong while elevating privileges: {e}")
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoS-responding SDN testbed")
    parser.add_argument(
        "-s",
        "--num-servers",
        type=int,
        required=True,
        help="The number of internal servers running applications."
    )
    parser.add_argument(
        "-e",
        "--num-external",
        type=int,
        required=True,
        help="The number of external hosts to send traffic to the internal hosts."
    )
    parser.add_argument(
        "-S",
        "--switch",
        type=str,
        required=False,
        default="switches/dumb_switch.py",
        help="Path to the switch file you want to use."
    )
    args = parser.parse_args()

    elevate_privileges()

    # Bind your variables
    osken = None
    topo = None
    procs = None

    try:
        osken = subprocess.Popen(["osken-manager", args.switch])

        topo = create_network(args.num_servers, args.num_external)
        topo.net.start()
        procs = []

        procs = start_servers(topo.servers)
        CLI(topo.net)
    finally:
        if osken is not None:
            osken.terminate()

        if topo is not None:
            topo.net.stop()

        if procs is not None:
            for p in procs:
                p.terminate()
