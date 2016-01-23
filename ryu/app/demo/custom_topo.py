# -*- coding: utf-8 -*-

# TODO use BRITE to generate topology instead of manual define

from mininet.net import Mininet
from mininet.node import  OVSSwitch, UserSwitch, RemoteController,Ryu
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
import logging
import os


class CustomTopo(Topo):

    def __init__(self):
        Topo.__init__( self )
        switches = list() # attention: must be switches not self.switches
        hosts = list()

        # s1 = self.addSwitch('s1')
        # s2 = self.addSwitch('s2')
        # s3 = self.addSwitch('s3')
        # s4 = self.addSwitch('s4')
        # s5 = self.addSwitch('s5')
        # s6 = self.addSwitch('s6')
        #
        # h1 = self.addHost('h1')
        # h2 = self.addHost('h2')
        # h3 = self.addHost('h3')
        # h4 = self.addHost('h4')
        # h5 = self.addHost('h5')
        # h6 = self.addHost('h6')
        #
        # self.addLink(s1,s2)
        # # self.addLink(s2,s3)
        # self.addLink(s3,s1)
        # self.addLink(s1,s4)
        # self.addLink(s2,s5)
        # self.addLink(s3,s6)
        #
        # self.addLink(s4,h1)
        # self.addLink(s4,h2)
        # self.addLink(s5,h3)
        # self.addLink(s5,h4)
        # self.addLink(s6,h5)
        # self.addLink(s6,h6)

        # add Switches
        switches.append(self.addSwitch('s1'))
        switches.append(self.addSwitch('s2'))
        switches.append(self.addSwitch('s3'))
        switches.append(self.addSwitch('s4'))
        switches.append(self.addSwitch('s5'))
        switches.append(self.addSwitch('s6'))

        # add Links between switches
        self.addLink(switches[0],switches[1])
        # self.addLink(switches[1],switches[2])
        self.addLink(switches[2],switches[0])
        self.addLink(switches[0],switches[3])
        self.addLink(switches[1],switches[4])
        self.addLink(switches[2],switches[5])

        # add Hosts
        hosts.append(self.addHost('h1'))
        hosts.append(self.addHost('h2'))
        hosts.append(self.addHost('h3'))
        hosts.append(self.addHost('h4'))
        hosts.append(self.addHost('h5'))
        hosts.append(self.addHost('h6'))

        # add Linkes between switches and hosts
        self.addLink(switches[3],hosts[0])
        self.addLink(switches[3],hosts[1])
        self.addLink(switches[4],hosts[2])
        self.addLink(switches[4],hosts[3])
        self.addLink(switches[5],hosts[4])
        self.addLink(switches[5],hosts[5])

class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        # self.name = 'CustomSwitch'
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        # self.stp = True


topos = {'custom':(lambda: CustomTopo())}

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633
#
# TODO mininet> sh ovs-vsctl set bridge s1 protocols=OpenFlow13
def main():
    logging.debug("Topo creating...")
    topo = CustomTopo()

    logging.debug("Mininet starting...")
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=None,
                  cleanup=True,
                  link=TCLink)
                      # switch=OVSSwitch,

    logging.debug("Controller adding...")
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
