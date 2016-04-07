# -*- coding: utf-8 -*-

import networkx as nx
import matplotlib.pyplot as plt
import fnss
import random
from mininet.topo import Topo
from mininet.node import  OVSSwitch
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.node import RemoteController
from mininet.cli import CLI

# topo = fnss.waxman_1_topology(n=50,alpha=0.6,beta=0.3)

class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        self.stp = True

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def main():
    # topo = fnss.two_tier_topology(2,4,2)
    topo = fnss.fat_tree_topology(4)
    fnss.set_weights_constant(topo,1)
    fnss.set_delays_constant(topo, 1, 'ms')
    fnss.set_capacities_edge_betweenness(topo,[10,100,1000],'Mbps')
    fnss.write_topology(topo,'topo.xml')


    nodes_label = nx.get_node_attributes(topo,'type')
    label_simple = dict()
    for each in nodes_label:
        label_simple[each] = nodes_label[each][0]
    nx.draw(topo,labels=label_simple, pos=nx.spring_layout(topo))
    # nx.draw_networkx_labels(topo,labels=label_simple,pos=nx.spring_layout(topo))
    plt.show()

    topo = fnss.read_topology('topo.xml') # return fnss.Topology
    # nx.draw(topo)
    # plt.savefig('fattree.png')
    # plt.show()
    mn_topo = fnss.to_mininet(topo,relabel_nodes=True)
    net = Mininet(topo=mn_topo,
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

if __name__ == "__main__":
    main()