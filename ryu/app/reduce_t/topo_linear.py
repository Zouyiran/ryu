# -*- coding: utf-8 -*-

import logging
import os
import random
from mininet.net import Mininet
from mininet.node import  OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import  TCLink
from mininet.topo import Topo

'''
linear topology with 2 hosts
'''

class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'

class CustomTopo(Topo):

    def __init__(self,switch_num):
        Topo.__init__( self )
        switches = list()
        hosts = list()
        self.switch_num = switch_num

        for switch in range(self.switch_num):
            switch_name = 's'+str(switch+1)
            switches.append(self.addSwitch(switch_name))

        '''
        (1) each switch take a host, total 16 hosts
        '''
        # for host in range(self.switch_num):
        #     host_name = 'h'+str(host+1)
        #     if host != 15:
        #         host_mac = '00:00:00:00:00:0'+hex(host+1)[-1]
        #     else:
        #         host_mac = '00:00:00:00:00:10'
        #     hosts.append(self.addHost(host_name,mac=host_mac))
        # self.addLink(switches[0],hosts[0],delay=str(1)+"ms",bw=100)
        # for i in range(self.switch_num-1):
        #     delay = random.randint(1,1)
        #     self.addLink(switches[i],switches[i+1],delay=str(delay)+"ms",bw=1000)
        #     delay = random.randint(1,1)
        #     self.addLink(switches[i+1],hosts[i+1],delay=str(delay)+"ms",bw=100)

        '''
        (2) only 2 hosts
        '''
        hosts.append(self.addHost('h1',mac='00:00:00:00:00:01'))
        hosts.append(self.addHost('h2',mac='00:00:00:00:00:02'))
        for count in range(self.switch_num): #
            if count == self.switch_num - 1:
                delay = random.randint(1,1)
                self.addLink(switches[0],hosts[0],delay=str(delay)+"ms",bw=100) #
                delay = random.randint(1,1)
                self.addLink(switches[self.switch_num-1],hosts[1],delay=str(delay)+"ms",bw=100) #
            else:
                delay = random.randint(1,1)
                self.addLink(switches[count],switches[count+1],delay=str(delay)+"ms",bw=1000) #,delay=str(delay)+"ms"

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def main(n_switches):
    topo = CustomTopo(n_switches)
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
        main(6)
