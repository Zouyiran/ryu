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

# create a topo which is just a graph
class CustomTopo(Topo):

    def __init__(self):
        Topo.__init__( self )
        switches = list() # attention: must be switches not self.switches
        hosts = list()

        switches.append(self.addSwitch('s1'))
        switches.append(self.addSwitch('s2'))
        switches.append(self.addSwitch('s3'))
        switches.append(self.addSwitch('s4'))
        switches.append(self.addSwitch('s5'))
        switches.append(self.addSwitch('s6'))
        switches.append(self.addSwitch('s7'))
        switches.append(self.addSwitch('s8'))
        switches.append(self.addSwitch('s9'))
        switches.append(self.addSwitch('s10'))
        switches.append(self.addSwitch('s11'))
        switches.append(self.addSwitch('s12'))
        switches.append(self.addSwitch('s13'))
        switches.append(self.addSwitch('s14'))
        switches.append(self.addSwitch('s15'))
        switches.append(self.addSwitch('s16'))
        switches.append(self.addSwitch('s17'))
        switches.append(self.addSwitch('s18'))
        switches.append(self.addSwitch('s19'))
        switches.append(self.addSwitch('s20'))

        hosts.append(self.addHost('h1',mac='00:00:00:00:00:01'))
        hosts.append(self.addHost('h2',mac='00:00:00:00:00:02'))

        self.addLink(switches[0],switches[1])
        self.addLink(switches[1],switches[2])
        self.addLink(switches[2],switches[3])
        self.addLink(switches[3],switches[4])
        self.addLink(switches[4],switches[5])
        self.addLink(switches[5],switches[6])
        self.addLink(switches[6],switches[7])
        self.addLink(switches[7],switches[8])
        self.addLink(switches[8],switches[9])
        self.addLink(switches[9],switches[10])
        self.addLink(switches[10],switches[11])
        self.addLink(switches[11],switches[12])
        self.addLink(switches[12],switches[13])
        self.addLink(switches[13],switches[14])
        self.addLink(switches[14],switches[15])
        self.addLink(switches[15],switches[16])
        self.addLink(switches[16],switches[17])
        self.addLink(switches[17],switches[18])
        self.addLink(switches[18],switches[19])

        self.addLink(switches[0],hosts[0], bw=1)
        self.addLink(switches[19],hosts[1], bw=1)


#  create a custom switch extends OVSSwitch
class CustomSwitch(OVSSwitch):
    # class OVSSwitch( Switch ):
    # "Open vSwitch switch. Depends on ovs-vsctl."
        # def __init__( self, name, failMode='secure', datapath='kernel',
        #           inband=False, protocols=None,
        #           reconnectms=1000, stp=False, batch=False, **params ):
        # """name: name for switch
        #    failMode: controller loss behavior (secure|open)
        #    datapath: userspace or kernel mode (kernel|user)
        #    inband: use in-band control (False)
        #    protocols: use specific OpenFlow version(s) (e.g. OpenFlow13)
        #               Unspecified (or old OVS version) uses OVS default
        #    reconnectms: max reconnect timeout in ms (0/None for default)
        #    stp: enable STP (False, requires failMode=standalone)
        #    batch: enable batch startup (False)"""

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
    net.addController( controller=RemoteController,
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
