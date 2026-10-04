import ipaddress

from mininet.net import Host, Mininet
from mininet.node import Controller, OVSKernelSwitch


def create_network(num_srv: int, num_ext: int, num_mal: int) -> Mininet:
    """
    Returns a Mininet object with the specified number of servers
    (num_srv), external machines (num_ext), and attackers (num_mal).
    """
    net = Mininet(controller=Controller, switch=OVSKernelSwitch)

    servers = create_hosts(net, num_srv, 'h', "10.0.0.0/24")
    external = create_hosts(net, num_ext, 'e', "10.1.0.0/24")
    malicious = create_hosts(net, num_mal, 'm', "10.2.0.0/24")

    switch = net.addSwitch("s1")

    for group in servers, external, malicious:
        for host in group:
            net.addLink(host, switch)

    return net


def create_hosts(net: Mininet, n: int, prefix: str, cidr: str) -> list[Host]:
    """
    Returns a list of Hosts created in the network.
    """
    ip = ipaddress.ip_address(cidr) + 1

    return [
        net.addHost(f"{prefix}{i}", ip=str(ip+i))
        for i in range(n)
    ]
