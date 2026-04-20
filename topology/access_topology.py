"""Custom Mininet topology for the SDN access-control project."""

from __future__ import annotations

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


HOST_DEFINITIONS = [
    ("h1", "10.0.0.1/24", "00:00:00:00:00:01", "authorized"),
    ("h2", "10.0.0.2/24", "00:00:00:00:00:02", "authorized"),
    ("h3", "10.0.0.3/24", "00:00:00:00:00:03", "authorized"),
    ("h4", "10.0.0.4/24", "00:00:00:00:00:04", "unauthorized"),
    ("h5", "10.0.0.5/24", "00:00:00:00:00:05", "unauthorized"),
    ("h6", "10.0.0.6/24", "00:00:00:00:00:06", "unauthorized"),
]


def run_topology():
    print("*** Creating network")
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
        build=False,
    )

    print("*** Adding controller c0 at 127.0.0.1:6633")
    controller = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)

    print("*** Adding switch s1 with OpenFlow13")
    switch = net.addSwitch("s1", protocols="OpenFlow13")

    print("*** Adding hosts")
    for host_name, ip_address, mac_address, role in HOST_DEFINITIONS:
        print(f"    {host_name}: ip={ip_address} mac={mac_address} role={role}")
        host = net.addHost(host_name, ip=ip_address, mac=mac_address)
        net.addLink(host, switch)

    print("*** Building and starting network")
    net.build()
    controller.start()
    switch.start([controller])

    print("*** Network is ready")
    print("*** Authorized hosts: h1, h2, h3")
    print("*** Unauthorized hosts: h4, h5, h6")
    print("*** Use 'dump' in Mininet CLI to inspect interfaces")

    CLI(net)

    print("*** Stopping network")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run_topology()
