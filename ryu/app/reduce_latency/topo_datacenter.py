# -*- coding: utf-8 -*-

# TODO use BRITE to generate topology instead of manual define

from mininet.net import Mininet
from mininet.node import  OVSSwitch, UserSwitch, RemoteController,Ryu
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink ,OVSLink
from mininet.topo import Topo
import logging
import os


class CustomTopo(Topo):
    '''
    two_tier model
    n_core=3,n_edge=3,n_hosts=2
    '''

    def __init__(self):
        Topo.__init__( self )
        switches = list()
        hosts = list()

        # add Switches
        switches.append(self.addSwitch('s1'))
        switches.append(self.addSwitch('s2'))
        switches.append(self.addSwitch('s3'))
        switches.append(self.addSwitch('s4'))
        switches.append(self.addSwitch('s5'))
        switches.append(self.addSwitch('s6'))

        # add Hosts
        hosts.append(self.addHost('h1',mac='00:00:00:00:00:01'))
        hosts.append(self.addHost('h2',mac='00:00:00:00:00:02'))
        hosts.append(self.addHost('h3',mac='00:00:00:00:00:03'))
        hosts.append(self.addHost('h4',mac='00:00:00:00:00:04'))
        hosts.append(self.addHost('h5',mac='00:00:00:00:00:05'))
        hosts.append(self.addHost('h6',mac='00:00:00:00:00:06'))

        # addLink( self, node1, node2, port1=None, port2=None,key=None, **opts )
        # add Links between switches
        self.addLink(switches[0],switches[3], bw=100)
        self.addLink(switches[0],switches[4], bw=100)
        self.addLink(switches[0],switches[5], bw=100)
        self.addLink(switches[1],switches[3], bw=100)
        self.addLink(switches[1],switches[4], bw=100)
        self.addLink(switches[1],switches[5], bw=100)
        self.addLink(switches[2],switches[3], bw=100)
        self.addLink(switches[2],switches[4], bw=100)
        self.addLink(switches[2],switches[5], bw=100)

        # add Linkes between switches and hosts
        self.addLink(switches[3],hosts[0], bw=10)
        self.addLink(switches[3],hosts[1], bw=10)
        self.addLink(switches[4],hosts[2], bw=10)
        self.addLink(switches[4],hosts[3], bw=10)
        self.addLink(switches[5],hosts[4], bw=10)
        self.addLink(switches[5],hosts[5], bw=10)

class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        self.stp = True

topos = {'custom':(lambda: CustomTopo())}

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def main():
    topo = CustomTopo()
    net = Mininet(topo=topo,
                  link=TCLink,
                  switch=CustomSwitch,
                  controller=None,
                  cleanup=True)
    net.addController( name='controller',
                       controller=RemoteController,
                       ip=CONTROLLER_IP,
                       port=CONTROLLER_PORT)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    if os.getuid() != 0:
        logging.debug("You are NOT root")
    else:
        main()
