#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
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
           big =  self._build_BIG( bw)
           self.bih.append(big)

    def _build_BIG(self, bw):
        big = set() # the element is Graph
        nodes = self.g.nodes()
        flag = False
        for i in nodes:
            for bi in big:
                if bi:
                    if i in bi.nodes():
                        flag = True
                        break
            if flag:
                continue
            else:
                bi = self._get_BI(bw,i)
                big.add(bi)
        res = set()
        for bi in big:
            bi_nodes = bi.nodes()
            count = 0
            for _ in bi_nodes:
                count += 1
                if count == 2:
                    res.add(bi)
                    break
        return res


    def _get_BI(self, bw, node):
        bi = nx.Graph()
        queue = list() # satisfy bw requirement
        book = list() # in bi
        head = 0
        tail = 0
        queue.append(node)
        tail += 1
        book.append(node)
        while head < tail:
            cur = queue[head]
            neighbors = self.g.adj[cur]
            for i in neighbors:
                if i not in book and neighbors[i]['weight'] >= bw:
                    queue.append(i)
                    tail += 1
                    bi.add_node(i)
                    bi.add_edge(cur,i,{'weight':neighbors[i]['weight']})
                    book.append(i)
            head += 1
        return bi


    def re_route(self, g, u, v): # u --> v
        route = None
        for big in self.bih: # from high-level to low-level
            for bi in big:
                bi_nodes = bi.nodes()
                if u in bi_nodes and v in bi_nodes:
                    route = nx.shortest_path(bi,u,v)
                    return route
        if nx.has_path(g,u,v):
            print("di_route")
            route = nx.shortest_path(g,u,v)
        return route

    def di_route(self, g, u, v, bw):
        route = None
        if nx.has_path(g,u,v):
            routes = nx.all_simple_paths(g,u,v)
            flag = True
            for r in routes:
                for i in range(len(r)-1):
                    if nx.get_edge_attributes(g,'weight')[(r[i],r[i+1])] < bw:
                        flag = False
                        break
                if flag:
                    route = r
                    break
                else:
                    continue
            if route is None:
                route = nx.shortest_path(g,u,v)
        return route
    
def test():
     g = nx.Graph()
     nodes = [1,2,3,4,5]
     edges = [(1,2),(1,3),(1,5),(2,3),(2,4)]
     weight = [2,4,9,5,7]
     g.add_nodes_from(nodes)
     num = len(edges)
     for i in range(num):
         g.add_edge(edges[i][0],edges[i][1], {'weight':weight[i]})
     return g 


def main(nodes):
    bws = [1,2,3,4,5,6,7,8,9,10]
    # g = test()
    network = nx.waxman_graph(nodes) # (n, alpha=0.4, beta=0.1, L=None, domain=(0, 0, 1, 1)):
    g = nx.Graph()
    g.add_nodes_from(network.nodes())
    for link in network.edges():
        bw = bws[random.randint(0,9)]
        g.add_edge(link[0],link[1],weight=bw)
        g.add_edge(link[1],link[0],weight=bw)

    print("-->nodes:")
    print(g.nodes())
    print("-->edges:")
    links = g.edges()
    weights = nx.get_edge_attributes(g,'weight')
    for i in links:
        print(i, weights[(i[0],i[1])])

    re = ReRouter(g)
    re.build_BIH([7,3])
    for big in re.bih:
        print("---big:")
        for bi in big:
            print("bi:")
            print("node:")
            print(bi.nodes())
            print("edges:")
            print(bi.edges())
    res = re.re_route(g,4,5)
    print('res:',res)


if __name__ == "__main__":
    main(200)

















