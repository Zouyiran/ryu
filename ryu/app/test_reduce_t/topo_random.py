# -*- coding: utf-8 -*-

import fnss
import networkx as nx
import matplotlib.pyplot as plt
from mininet.node import  OVSSwitch
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController,Host
from mininet.cli import CLI


class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def generate_topo(n):
    topo = nx.powerlaw_cluster_graph(n,2,0.08)
    # topo = fnss.waxman_1_topology(n=50,alpha=0.6,beta=0.3)
    # topo = fnss.fat_tree_topology(n)
    fnss.set_weights_constant(topo,1)
    fnss.set_delays_constant(topo, 1, 'ms')
    fnss.set_capacities_edge_betweenness(topo,[100,500,1000],'Mbps')
    fnss.write_topology(topo,'topo_pl.xml')

def plot_topo(topo, topo_type):
    labels = dict()
    if topo_type == 'ft':
        '''
        plot the fat-tree topology
        '''
        nodes_label = nx.get_node_attributes(topo,'layer')
        for each in nodes_label:
            if nodes_label[each] == 'leaf':
                labels[each] = 'L'
            elif nodes_label[each] == 'edge':
                labels[each] = 'E'
            elif nodes_label[each] == 'aggregation':
                labels[each] = 'A'
            else:
                labels[each] = 'C'
    elif topo_type == 'pl':
        '''
        plot the power-law topology
        '''
        nodes = topo.nodes()
        count = 0
        for i in nodes:
            neighbors = topo.adj[i]
            if len(neighbors) == 2:
                labels[i] ='E'
                count += 1
            else:
                labels[i] ='S'
        print 'access nodes count:',count
    nx.draw(topo,labels=labels,node_color='w',pos=nx.spring_layout(topo),linewidths=1, node_size=300)
    # nx.draw_networkx_nodes(topo,labels=labels,node_color='w',pos=nx.spring_layout(topo),linewidths=2,node_size=500)
    # nx.draw_networkx_edges()
    plt.show()


def addition_for_pl(topo):
    '''
    if the topo is power-law topology then:
    add_node(i,{'type':'switch'})
    only do above, it can call fnss.to_mininet()
    '''
    nodes = topo.nodes()
    for i in nodes:
        topo.add_node(i,{'type':'switch'})
    return topo

def add_hosts_for_pl(topo, mn_topo):
    '''
    if the topo is power-law topology then:
    add hosts
    '''
    access_nodes = list()
    nodes = topo.nodes()
    for i in nodes:
        neighbors = topo.adj[i]
        if len(neighbors) == 2:
            access_nodes.append(i)
    count = 0
    for i in access_nodes:
        count += 1
        name = 'h'+str(count)
        mn_topo.addHost(name=name) # self, name, cls=None, **params
        mn_topo.addLink(node1=name,node2='s'+str(i),bw=10) # self, node1, node2, port1=None, port2=None, cls=None, **params


def main(n):
    # generate_topo(n)
    topo = fnss.read_topology('topo_'+'ft'+'.xml') # return fnss.Topology
    # plot_topo(topo,'pl')
    # addition_for_pl(topo)
    mn_topo = fnss.to_mininet(topo,relabel_nodes=True)
    # add_hosts_for_pl(topo,mn_topo)
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
    main(50)