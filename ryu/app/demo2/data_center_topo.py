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
        hosts.append(self.addHost('h7',mac='00:00:00:00:00:07'))

# addLink( self, node1, node2, port1=None, port2=None,key=None, **opts )
        # add Links between switches
        self.addLink(switches[0],switches[1])
        # self.addLink(switches[1],switches[2])
        self.addLink(switches[2],switches[0])
        self.addLink(switches[0],switches[3])
        self.addLink(switches[1],switches[4])
        self.addLink(switches[2],switches[5])

        # add Linkes between switches and hosts
        self.addLink(switches[3],hosts[0], bw=1)
        self.addLink(switches[3],hosts[1], bw=1)
        self.addLink(switches[4],hosts[2], bw=1)
        self.addLink(switches[4],hosts[3], bw=1)
        self.addLink(switches[5],hosts[4], bw=1)
        self.addLink(switches[5],hosts[5], bw=1)
        self.addLink(switches[0],hosts[6], bw=1)

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

# mininet> sh ovs-vsctl set bridge s1 protocols=OpenFlow13
def main():
    topo = CustomTopo()
    net = Mininet(topo=topo,
                  link=TCLink,#"TCLink:Link with symmetric TC interfaces configured via opts"
                  switch=CustomSwitch,
                  controller=None,
                  cleanup=True)
    net.addController( name='controller',
                       controller=RemoteController,
                       ip=CONTROLLER_IP,
                       port=CONTROLLER_PORT)
# def setIP( self, ip, prefixLen=8, intf=None, **kwargs ):
# """Set the IP address for an interface.
#    intf: intf or intf name
#    ip: IP address as a string
#    prefixLen: prefix length, e.g. 8 for /8 or 16M addrs
#    kwargs: any additional arguments for intf.setIP"""
#     net.getNodeByName("h1").setIP(ip='172.16.40.11',prefixLen=24)
#     net.getNodeByName("h2").setIP(ip='172.16.40.12',prefixLen=24)
#     net.getNodeByName("h3").setIP(ip='172.16.50.11',prefixLen=24)
#     net.getNodeByName("h4").setIP(ip='172.16.50.12',prefixLen=24)
#     net.getNodeByName("h5").setIP(ip='172.16.60.11',prefixLen=24)
#     net.getNodeByName("h6").setIP(ip='172.16.60.12',prefixLen=24)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    if os.getuid() != 0:
        logging.debug("You are NOT root")
    else:
        main()
