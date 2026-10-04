import argparse

from mininet.cli import CLI

from sdndos_network.hosts import create_network, start_servers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File watching and static analysis script.")
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
    #parser.add_argument(
    #    "-m",
    #    "--num-malicious",
    #    type=int,
    #    required=True,
    #    help="The number of malicious external hosts to send traffic to the internal hosts."
    #)
    #parser.add_argument(
    #    "-s",
    #    "--seed",
    #    type=int,
    #    required=False,
    #    default=1849212,
    #    help="Seed for random attacker selection"
    #)
    args = parser.parse_args()

    topo = create_network(args.num_servers, args.num_external)
    topo.net.start()
    procs = []

    try:
        procs = start_servers(topo.servers)
        CLI(topo.net)
    finally:
        for p in procs:
            p.terminate()
        topo.net.stop()
