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
import time

'''
can be used
'''

# create a topo which is just a graph
class CustomTopo(Topo):
    '''
    two_tier topology:
    n_core=4, n_edge=4, host=2(total:8)
    '''

    def __init__(self):
        Topo.__init__( self )
        switches = list() # attention: must be switches not self.switches
        hosts = list()

        # add core_switches
        switches.append(self.addSwitch('s1'))
        switches.append(self.addSwitch('s2'))
        switches.append(self.addSwitch('s3'))
        switches.append(self.addSwitch('s4'))
        # add edge_switches
        switches.append(self.addSwitch('s5'))
        switches.append(self.addSwitch('s6'))
        switches.append(self.addSwitch('s7'))
        switches.append(self.addSwitch('s8'))
        # add Hosts
        hosts.append(self.addHost('h1',mac='00:00:00:00:00:01'))
        hosts.append(self.addHost('h2',mac='00:00:00:00:00:02'))
        hosts.append(self.addHost('h3',mac='00:00:00:00:00:03'))
        hosts.append(self.addHost('h4',mac='00:00:00:00:00:04'))
        hosts.append(self.addHost('h5',mac='00:00:00:00:00:05'))
        hosts.append(self.addHost('h6',mac='00:00:00:00:00:06'))
        hosts.append(self.addHost('h7',mac='00:00:00:00:00:07'))
        hosts.append(self.addHost('h8',mac='00:00:00:00:00:08'))

        # add Links between switches
        self.addLink(switches[0],switches[4], bw=100)
        self.addLink(switches[0],switches[5], bw=100)
        self.addLink(switches[0],switches[6], bw=100)
        self.addLink(switches[0],switches[7], bw=100)
        self.addLink(switches[1],switches[4], bw=100)
        self.addLink(switches[1],switches[5], bw=100)
        self.addLink(switches[1],switches[6], bw=100)
        self.addLink(switches[1],switches[7], bw=100)
        self.addLink(switches[2],switches[4], bw=100)
        self.addLink(switches[2],switches[5], bw=100)
        self.addLink(switches[2],switches[6], bw=100)
        self.addLink(switches[2],switches[7], bw=100)
        self.addLink(switches[3],switches[4], bw=100)
        self.addLink(switches[3],switches[5], bw=100)
        self.addLink(switches[3],switches[6], bw=100)
        self.addLink(switches[3],switches[7], bw=100)

        # add Linkes between switches and hosts
        self.addLink(switches[4],hosts[0], bw=10)
        self.addLink(switches[4],hosts[1], bw=10)
        self.addLink(switches[5],hosts[2], bw=10)
        self.addLink(switches[5],hosts[3], bw=10)
        self.addLink(switches[6],hosts[4], bw=10)
        self.addLink(switches[6],hosts[5], bw=10)
        self.addLink(switches[7],hosts[6], bw=10)
        self.addLink(switches[7],hosts[7], bw=10)

#  create a custom switch extends OVSSwitch
class CustomSwitch(OVSSwitch):
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

#     net.getNodeByName("h1").setIP(ip='172.16.40.11',prefixLen=24)
#     net.getNodeByName("h2").setIP(ip='172.16.40.12',prefixLen=24)
#     net.getNodeByName("h3").setIP(ip='172.16.50.11',prefixLen=24)
#     net.getNodeByName("h4").setIP(ip='172.16.50.12',prefixLen=24)
#     net.getNodeByName("h5").setIP(ip='172.16.60.11',prefixLen=24)
#     net.getNodeByName("h6").setIP(ip='172.16.60.12',prefixLen=24)
#     net.getNodeByName("h7").setIP(ip='172.16.70.11',prefixLen=24)
#     net.getNodeByName("h8").setIP(ip='172.16.70.12',prefixLen=24)

    net.start()
    time.sleep(2)
    # traffic(net)
    CLI(net)
    net.stop()

# iperf( self, hosts=None, l4Type='TCP', udpBw='10M', fmt=None,seconds=5, port=5001)
def traffic(net):
    hosts = [net.getNodeByName('h1'), net.getNodeByName('h2')]
    net.iperf(hosts=hosts, l4Type='TCP',seconds=10)


if __name__ == '__main__':
    setLogLevel('info')
    if os.getuid() != 0:
        logging.debug("You are NOT root")
    else:
        main()
