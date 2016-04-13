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
from mininet.node import RemoteController,Host
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

def main(n):
    # topo = fnss.fat_tree_topology(4) #topo = fnss.waxman_1_topology(n=50,alpha=0.6,beta=0.3)
    # fnss.set_weights_constant(topo,1)
    # fnss.set_delays_constant(topo, 1, 'ms')
    # fnss.set_capacities_edge_betweenness(topo,[100,500,1000],'Mbps')
    # fnss.write_topology(topo,'topo_ft.xml')
    #
    # nodes_label = nx.get_node_attributes(topo,'layer')
    # print nodes_label
    # label_simple = dict()
    # for each in nodes_label:
    #     if nodes_label[each] == 'leaf':
    #         label_simple[each] = 'L'
    #     elif nodes_label[each] == 'edge':
    #         label_simple[each] = 'E'
    #     elif nodes_label[each] == 'aggregation':
    #         label_simple[each] = 'A'
    #     else:
    #         label_simple[each] = 'C'
    #         # label_simple[each] = nodes_label[each][0]
    # nx.draw(topo,labels=label_simple,node_color='w',pos=nx.spring_layout(topo),node_size=400,label_size=16)
    # plt.show()

    # topo = nx.powerlaw_cluster_graph(n,2,0.08)
    # nodes = topo.nodes()
    # # labels = dict()
    # # for i in nodes:
    # #     neighbors = topo.adj[i]
    # #     if len(neighbors) == 2:
    # #         labels[i] ='E'
    # #     else:
    # #         labels[i] ='S'
    # fnss.set_weights_constant(topo,1)
    # fnss.set_delays_constant(topo, 1, 'ms')
    # fnss.set_capacities_edge_betweenness(topo,[100,500,1000],'Mbps')
    # fnss.write_topology(topo,'topo_'+str(n)+'.xml')
    # nx.draw(topo, node_color='black',pos=nx.spring_layout(topo),node_size=200)
    # plt.show()

    topo = fnss.read_topology('topo_'+'ft'+'.xml') # return fnss.Topology
    # nodes = topo.nodes()
    # edges = topo.edges()
    # print 'nodes num:',len(nodes)
    # print 'edges num:',len(edges)
    # access_nodes = list()
    # for i in nodes:
    #     topo.add_node(i,{'type':'switch'})
    #     neighbors = topo.adj[i]
    #     if len(neighbors) == 2:
    #         access_nodes.append(i)
    # print 'access_nodes num:',len(access_nodes)
    mn_topo = fnss.to_mininet(topo,relabel_nodes=True)
    # count = 0
    # for i in access_nodes:
    #     count += 1
    #     name = 'h'+str(count)
    #     mn_topo.addHost(name=name) # self, name, cls=None, **params
    #     mn_topo.addLink(node1=name,node2='s'+str(i),bw=10) # self, node1, node2, port1=None, port2=None, cls=None, **params
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
    main(200)