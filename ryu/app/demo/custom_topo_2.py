# -*- coding: utf-8 -*-

# TODO use BRITE to generate topology instead of manual define

from mininet.net import Mininet
from mininet.node import  OVSSwitch, UserSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
import logging
import os


class CustomTopo(Topo):

    def __init__(self, **params):
        super(CustomTopo, self).__init__(**params)
        switches = list() # attention: must be switches not self.switches
        hosts = list()

        # add Switches
        switches.append(self.addSwitch('s1'))
        switches.append(self.addSwitch('s2'))
        switches.append(self.addSwitch('s3'))

        # add Links between switches
        self.addLink(switches[0],switches[1],bw=10)
        self.addLink(switches[1],switches[2],bw=10)
        # self.addLink(switches[2],switches[0],bw=10)

        # # add Hosts
        # hosts.append(self.addHost('h1',mac='00:00:00:00:00:01'))
        # hosts.append(self.addHost('h2',mac='00:00:00:00:00:02'))
        # hosts.append(self.addHost('h3',mac='00:00:00:00:00:03'))
        # hosts.append(self.addHost('h4',mac='00:00:00:00:00:04'))
        # hosts.append(self.addHost('h5',mac='00:00:00:00:00:05'))
        # hosts.append(self.addHost('h6',mac='00:00:00:00:00:06'))

        # # add Linkes between switches and hosts
        # self.addLink(switches[3],hosts[0],bw=1)
        # self.addLink(switches[3],hosts[1],bw=1)
        # self.addLink(switches[4],hosts[2],bw=1)
        # self.addLink(switches[4],hosts[3],bw=1)
        # self.addLink(switches[5],hosts[4],bw=1)
        # self.addLink(switches[5],hosts[5],bw=1)

class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        # self.name = 'CustomSwitch'
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        # self.stp = True



CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

'''
    def __init__( self, topo=None, switch=OVSKernelSwitch, host=Host,
                  controller=DefaultController, link=Link, intf=Intf,
                  build=True, xterms=False, cleanup=False, ipBase='10.0.0.0/8',
                  inNamespace=False,
                  autoSetMacs=False, autoStaticArp=False, autoPinCpus=False,
                  listenPort=None, waitConnected=False ):
'''

# TODO mininet> sh ovs-vsctl set bridge s1 protocols=OpenFlow13
def main():
    logging.debug("Topo creating...")
    topo = CustomTopo()

    logging.debug("Mininet starting...")
    net = Mininet(topo=topo,
                  switch=CustomSwitch,
                  host=None,
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