import ipaddress
from dataclasses import dataclass
from subprocess import DEVNULL

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Host, OVSSwitch, RemoteController


@dataclass
class Topology:
    net: Mininet
    servers: list[Host]
    external: list[Host]


def create_network(
    num_srv: int,
    num_ext: int,
    controller_ip: str = "127.0.0.1",
    controller_port: int = 6653,
    link_bw: int = 10
)-> Topology:
    """
    Returns a Mininet object with the specified number of servers
    (num_srv) and external machines (num_ext).
    """
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)

    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port
    )

    servers = create_hosts(net, num_srv, 'i', "10.0.0.0", 24)
    external = create_hosts(net, num_ext, 'e', "10.1.0.0", 24)

    switch = net.addSwitch("s1", protocols="OpenFlow13")

    for group in servers, external:
        for host in group:
            net.addLink(host, switch, bw=link_bw)

    return Topology(net, servers, external)


def create_hosts(
    net: Mininet,
    n: int,
    prefix: str,
    net_ip: str,
    prefix_len: int
) -> list[Host]:
    """Returns a list of Hosts created in the network."""
    ip = ipaddress.ip_network(f"{net_ip}/{prefix_len}").network_address + 1

    return [
        net.addHost(f"{prefix}{i}", ip=str(ip+i))
        for i in range(n)
    ]


def start_servers(
    servers: list[Host],
    cmds: list[list[str]] | None = None
) -> list:
    """Starts all servers in the topology with the provided commands."""
    if cmds is None:
        cmds = [
            ["python3", "-m", "http.server", "80"]
            for _ in range(len(servers))
        ]

    return [
        servers[i].popen(cmds[i], stdout=DEVNULL, stderr=DEVNULL)
        for i in range(len(servers))
    ]
