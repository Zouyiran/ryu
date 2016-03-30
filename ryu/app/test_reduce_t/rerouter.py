#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import time
import networkx as nx

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

from command_sender import CommandSender

'''
re-route for elephant flow
build BIH
# get ports stats of the switch
# GET /stats/port/<dpid>
{
  "2": [
    {
      "tx_dropped": 0,
      "rx_packets": 0,
      "rx_crc_err": 0,
      "tx_bytes": 0,
      "rx_dropped": 0,
      "port_no": "LOCAL",
      "rx_over_err": 0,
      "rx_frame_err": 0,
      "rx_bytes": 0,
      "tx_errors": 0,
      "duration_nsec": 936000000,
      "collisions": 0,
      "duration_sec": 138,
      "rx_errors": 0,
      "tx_packets": 0
    },
    {
      "tx_dropped": 0,
      "rx_packets": 231,
      "rx_crc_err": 0,
      "tx_bytes": 25028,
      "rx_dropped": 0,
      "port_no": 1,
      "rx_over_err": 0,
      "rx_frame_err": 0,
      "rx_bytes": 25319,
      "tx_errors": 0,
      "duration_nsec": 940000000,
      "collisions": 0,
      "duration_sec": 138,
      "rx_errors": 0,
      "tx_packets": 231
    },
    {
      "tx_dropped": 0,
      "rx_packets": 236,
      "rx_crc_err": 0,
      "tx_bytes": 25370,
      "rx_dropped": 0,
      "port_no": 2,
      "rx_over_err": 0,
      "rx_frame_err": 0,
      "rx_bytes": 27029,
      "tx_errors": 0,
      "duration_nsec": 940000000,
      "collisions": 0,
      "duration_sec": 138,
      "rx_errors": 0,
      "tx_packets": 232
    }
  ]
}

# get ports description of the switch
# GET /stats/portdesc/<dpid>
{
  "4": [
    {
      "hw_addr": "42:a5:42:29:4e:45",
      "curr": 0,
      "supported": 0,
      "max_speed": 0,
      "advertised": 0,
      "peer": 0,
      "port_no": "LOCAL",
      "curr_speed": 0,
      "name": "s4",
      "state": 1,
      "config": 1
    },
    {
      "hw_addr": "3e:4c:ac:3d:87:99",
      "curr": 2112,
      "supported": 0,
      "max_speed": 0,
      "advertised": 0,
      "peer": 0,
      "port_no": 1,
      "curr_speed": 10000000,
      "name": "s4-eth1",
      "state": 0,
      "config": 0
    },
    {
      "hw_addr": "66:38:14:db:56:4b",
      "curr": 2112,
      "supported": 0,
      "max_speed": 0,
      "advertised": 0,
      "peer": 0,
      "port_no": 2,
      "curr_speed": 10000000,
      "name": "s4-eth2",
      "state": 0,
      "config": 0
    }
  ]
}
'''

# class ReRouter(app_manager.RyuApp):
#     '''
#     only collect access switches
#     '''
#
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
#
#     def __init__(self, *args, **kwargs):
#         super(ReRouter, self).__init__(*args, **kwargs)
#         self.flowSender = CommandSender.get_instance()
#         self.bih = list()

class ReRouter(object):
    '''
    only collect access switches
    '''


    def __init__(self, g):
        super(ReRouter, self).__init__()
        self.bih = list()
        self.g = g

    # def request_stats_port(self, dpid):
    #     res = self.flowSender.get_stats_port(dpid)
    #     return res.json() # dict

    def create_bw_g(self,matrix):#(u,v,bw)
        if matrix:
            nodes = matrix.keys()
            g = nx.Graph()
            g.add_nodes_from(nodes)
            for i in nodes:
                for j in nodes:
                    if i != j and matrix[i][j] != float('inf'):
                        g.add_edge(i,j,weight=matrix[i][j])

    def build_BIH(self, bw_list):# beta_list=[B, 2B/3, B/3, 0]
        for bw in bw_list:
           print("build_BIH bw:", bw)
           big = self._build_BIG(bw)
           self.bih.append(big)

    def _build_BIG(self, bw):
        big = set() # the element is Graph
        g_nodes = self.g.nodes()
        for i in g_nodes:
            flag = False
            for bi in big:
                bi_nodes = bi.nodes()
                if i in bi_nodes:
                    flag = True
                    break
            if not flag:
                bi = self._get_BI(bw,i)
                big.add(bi)
        res = set()
        for bi in big:
            bi_edges = bi.edges()
            if len(bi_edges) > 0:
                res.add(bi)
        return res

    def _get_BI(self, bw, node):
        bi = nx.Graph()
        queue = list() # satisfy bw requirement
        book = list() # mark in bi
        head = 0
        tail = 0
        queue.append(node)
        tail += 1
        book.append(node)
        while head < tail:
            cur = queue[head]
            neighbors = self.g.adj[cur]
            for i in neighbors:
                weight = neighbors[i]['weight']
                if i not in book and weight >= bw:
                    queue.append(i)
                    tail += 1
                    bi.add_edge(cur,i,{'weight':weight})
                    book.append(i)
            head += 1
        bi_all = self.g.subgraph(bi.nodes())
        bi_all_edges = nx.get_edge_attributes(bi_all,'weight') #{(1,2):10,}
        bi_edges = bi.edges()
        for edge in bi_all_edges:
            if edge not in bi_edges:
                the_bw = bi_all_edges[edge]
                if the_bw >= bw:
                    bi.add_edge(edge[0],edge[1],{'weight':the_bw})
                    bi.add_edge(edge[1],edge[0],{'weight':the_bw})
        return bi

    def re_route(self, u, v): # u --> v
        start = time.clock()
        route = None
        level = 0
        for big in self.bih: # from high-level to low-level
            level += 1
            for bi in big:
                bi_nodes = bi.nodes()
                bi_edges = bi.edges()
                if u in bi_nodes and v in bi_nodes:
                    print("....re_route")
                    print "get route at level_num:",level
                    print("bi_node_num:",len(bi_nodes))
                    print("bi_edge_num:",len(bi_edges))
                    route = nx.shortest_path(bi,u,v)
                    cost = time.clock()-start
                    print "cost_re:", cost
                    return route
        if nx.has_path(self.g,u,v):
            print("....re_shortest_path")
            route = nx.shortest_path(self.g,u,v)
        cost = time.clock()-start
        print "cost_re:", cost
        return route

    def di_route(self, u, v, bw):
        start = time.clock()
        route = None
        if nx.has_path(self.g,u,v):
            wb = nx.get_edge_attributes(self.g,'weight')
            routes = nx.all_shortest_paths(self.g,u,v) # generator
            flag = True
            for r in routes:
                num = len(r)
                for i in range(num-1):
                    if wb.has_key((r[i],r[i+1])) and wb[(r[i],r[i+1])] < bw:
                        flag = False
                        break
                    elif wb.has_key((r[i+1],r[i])) and wb[(r[i+1],r[i])] < bw:
                        flag = False
                        break
                if flag:
                    print("....di_route")
                    route = r
                    break
                else:
                    continue
            if route is None:
                print("....di_shortest_path")
                route = nx.shortest_path(self.g,u,v)
        cost = time.clock()-start
        print "cost_di:", cost
        return route
    
def test_manual():
     g = nx.Graph()
     nodes = [1,2,3,4,5,6,7]
     edges = [(1,2),(1,3),(1,5),(2,3),(2,7),(3,6),(4,5),(6,7)]
     weight = [2,5,9,7,3,5,10,2]
     g.add_nodes_from(nodes)
     num = len(edges)
     for i in range(num):
         g.add_edge(edges[i][0],edges[i][1], {'weight':weight[i]})
         g.add_edge(edges[i][1],edges[i][0], {'weight':weight[i]})
     return g

def test_er(nodes):
    bws = [1,2,3,4,5,6,7,8,9,10]
    network = nx.erdos_renyi_graph(nodes,0.4) # (n, alpha=0.4, beta=0.1, L=None, domain=(0, 0, 1, 1)):
    g = nx.Graph()
    g.add_nodes_from(network.nodes())
    for link in network.edges():
        bw = bws[random.randint(0,9)]
        g.add_edge(link[0],link[1],{'weight':bw})
        g.add_edge(link[1],link[0],{'weight':bw})
    return g


def test_wax(nodes):
    bws = [1,2,3,4,5,6,7,8,9,10]
    network = nx.waxman_graph(nodes) # (n, alpha=0.4, beta=0.1, L=None, domain=(0, 0, 1, 1)):
    g = nx.Graph()
    g.add_nodes_from(network.nodes())
    for link in network.edges():
        bw = bws[random.randint(0,9)]
        g.add_edge(link[0],link[1],{'weight':bw})
        g.add_edge(link[1],link[0],{'weight':bw})
    return g


def main(nodes):
    g = test_er(nodes)
    print("erdos_renyi")
    # print("waxmam")
    g_nodes = g.nodes()
    print("erdos_renyi_nodes:",len(g_nodes))
    # print("waxmax_nodes:",len(g_nodes))
    g_edges = g.edges()
    print("erdos_renyi_edges:",len(g_edges))
    # print("waxman_edges:",len(g_edges))
    print('...............network.............')
    print("-->nodes:")
    print(g.nodes())
    print("-->edges:")
    links = g.edges()
    weights = nx.get_edge_attributes(g,'weight')
    for i in links:
        print(i, weights[(i[0],i[1])])
    print('...............network.............')


    re = ReRouter(g)
    bw_level = [7,5,2]
    re.build_BIH(bw_level)
    print('............BIH................')
    for i in range(len(re.bih)):
        print "------------level:",bw_level[i]
        for bi in re.bih[i]:
            print("-----bi:")
            print("node:")
            print(bi.nodes())
            print("edges:")
            print(bi.edges())
    print('............BIH................')
    res = re.re_route(1,4)
    res_2 = re.di_route(1,4,7)
    print('............result................')
    print('res:',res)
    print('res_2:',res_2)
    print('............result................')


if __name__ == "__main__":
    nodes = [7]
    # nodes = [30,100,300,500,700,1000]
    for i in nodes:
        print(">>>>>>>>>>>>nodes<<<<<<<<<<<<<:",i)
        main(i)

















