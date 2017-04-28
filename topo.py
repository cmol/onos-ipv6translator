#!/usr/bin/python

"""
This example shows how to create an empty Mininet object
(without a topology object) and add nodes to it manually.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def IPv6Net():
    net    = Mininet( controller=Controller)
    s1     = net.addSwitch('s1')
    h_out  = net.addHost('h_out', ip="10.0.0.7")
    h_in1  = net.addHost('h_in1' , ip="10.0.0.1")
    h_in2  = net.addHost('h_in2' , ip="10.0.0.2")
    net.addLink(s1, h_out)
    net.addLink(s1, h_in1)
    net.addLink(s1, h_in2)

    net.addController( 'c0', controller=RemoteController)

    net.start()
    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    IPv6Net()
