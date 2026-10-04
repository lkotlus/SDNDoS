### CYSE 610 Project
Using SDNs to automatically detect and respond to DoS attacks.

### Requirements
System packages:
- `mininet`
- `openvswitch-switch`
- `uv`
- `hping3`

### Installation
We currently only support Debian-based distributions of Linux.

```
$ ./install.sh
```

### Usage
After activating the virtual envrionment:

```
$ python3 main.py -h
usage: main.py [-h] -s NUM_SERVERS -e NUM_EXTERNAL [-S SWITCH]

DoS-responding SDN testbed

options:
  -h, --help            show this help message and exit
  -s NUM_SERVERS, --num-servers NUM_SERVERS
                        The number of internal servers running applications.
  -e NUM_EXTERNAL, --num-external NUM_EXTERNAL
                        The number of external hosts to send traffic to the internal hosts.
  -S SWITCH, --switch SWITCH
                        Path to the switch file you want to use.
```

For a basic run with 3 servers and 10 external hosts:
```
$ python3 main.py -s 3 -e 10
mininet> pingall
*** Ping: testing ping reachability
i0 -> i1 i2 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 
i1 -> i0 i2 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 
i2 -> i0 i1 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 
e0 -> i0 i1 i2 e1 e2 e3 e4 e5 e6 e7 e8 e9 
e1 -> i0 i1 i2 e0 e2 e3 e4 e5 e6 e7 e8 e9 
e2 -> i0 i1 i2 e0 e1 e3 e4 e5 e6 e7 e8 e9 
e3 -> i0 i1 i2 e0 e1 e2 e4 e5 e6 e7 e8 e9 
e4 -> i0 i1 i2 e0 e1 e2 e3 e5 e6 e7 e8 e9 
e5 -> i0 i1 i2 e0 e1 e2 e3 e4 e6 e7 e8 e9 
e6 -> i0 i1 i2 e0 e1 e2 e3 e4 e5 e7 e8 e9 
e7 -> i0 i1 i2 e0 e1 e2 e3 e4 e5 e6 e8 e9 
e8 -> i0 i1 i2 e0 e1 e2 e3 e4 e5 e6 e7 e9 
e9 -> i0 i1 i2 e0 e1 e2 e3 e4 e5 e6 e7 e8 
*** Results: 0% dropped (156/156 received)
```

If you want to manually test connectivity:
```
mininet> e0 ping -c 3 i1
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=4.76 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.856 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.121 ms

--- 10.0.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 0.121/1.912/4.760/2.035 ms
```

To launch an attack from an external host to a server:
```
mininet> e4 hping3 -S -p 80 -i u1000 -c 5000 i1
len=44 ip=10.0.0.2 ttl=64 DF id=0 sport=80 flags=SA seq=1622 win=42340 rtt=8.9 ms
len=44 ip=10.0.0.2 ttl=64 DF id=0 sport=80 flags=SA seq=1623 win=42340 rtt=7.8 ms
...
len=44 ip=10.0.0.2 ttl=64 DF id=0 sport=80 flags=SA seq=1630 win=42340 rtt=7.6 ms
len=44 ip=10.0.0.2 ttl=64 DF id=0 sport=80 flags=SA seq=1631 win=42340 rtt=6.4 ms

--- 10.0.0.2 hping statistic ---
5000 packets transmitted, 1632 packets received, 68% packet loss
round-trip min/avg/max = 0.0/11.3/1006.0 ms

mininet> e4 ping -c 3 i1
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.

--- 10.0.0.2 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2055ms

mininet> e4 ping -c 3 i0
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=7.29 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.850 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.116 ms

--- 10.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2019ms
rtt min/avg/max/mdev = 0.116/2.752/7.291/3.223 ms
```

A breakdown of the attack command:
- `hping3`: common tool for network testing
- `-S`: SYN
- `-p 80`: port 80
- `-i u1000`: interval of 1,000 microseconds (send 1,000,000 packets per second)
- `-c 5000`: send 5,000 packets
