# -*- coding: utf-8 -*-
from mininet.net import Mininet
from mininet.node import  OVSSwitch, UserSwitch, RemoteController,Ryu
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink ,OVSLink
from mininet.topo import Topo
import logging
import os
import random
import time


class CustomTopo(Topo):

    def __init__(self,switch_num):
        Topo.__init__( self )
        switches = list()
        hosts = list()
        self.switch_num = switch_num

        for switch in range(self.switch_num): # [0,1,2,3,4,5,6,7,8,9]
            switch_name = 's'+str(switch+1)
            switches.append(self.addSwitch(switch_name))

        hosts.append(self.addHost('h1',mac='00:00:00:00:00:01'))
        hosts.append(self.addHost('h2',mac='00:00:00:00:00:02'))

        for count in range(self.switch_num): #
            if count == self.switch_num - 1:
                delay = random.randint(1,1)
                self.addLink(switches[0],hosts[0],delay=str(delay)+"ms") #
                delay = random.randint(1,1)
                self.addLink(switches[self.switch_num-1],hosts[1],delay=str(delay)+"ms") #
            else:
                delay = random.randint(1,1)
                self.addLink(switches[count],switches[count+1],delay=str(delay)+"ms") #,delay=str(delay)+"ms"


#  create a custom switch extends OVSSwitch
class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        # self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        # self.stp = True

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def main(n_switches, count_ping):
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
    time.sleep(10)

    hosts = [net.getNodeByName('h1'),net.getNodeByName('h2')]
    rtt_list = list()
    for count in range(1,count_ping+1):
        all_res = net.pingFull(hosts)
        res = all_res[0] # h1 -> h2 rtt
        src, dest, ping_outputs = res
        sent, received, rttmin, rttavg, rttmax, rttdev = ping_outputs
        if sent == received:
            rtt_latency = rttavg
        else:
            rtt_latency = 0
        rtt_list.append(rtt_latency)
    print(rtt_list)

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    if os.getuid() != 0:
        logging.debug("You are NOT root")
    else:
        main(10,10)
