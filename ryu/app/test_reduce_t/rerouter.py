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
        start = time.clock()
        for bw in bw_list: # [7,5,2]
           big = self._build_BIG(bw)
           self.bih.append(big)
        cost = time.clock()-start
        print 'build_cost:',cost

    def _build_BIG(self, bw):
        big = list() # the element is Graph
        g_nodes = self.g.nodes()
        for i in g_nodes:
            is_bi_node = False  #####!!!
            for bi in big:
                bi_nodes = bi.nodes()
                if i in bi_nodes:
                    is_bi_node = True
                    break
            if not is_bi_node:
                bi = self._get_BI(bw,i)
                big.append(bi)
        res = list()
        for bi in big:
            bi_edges = bi.edges()
            if len(bi_edges) > 0:
                res.append(bi)
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

    def re_route(self, u, v, bi=None): # u --> v
        start = time.clock()
        route = None
        level = 0
        if bi is None:
            for big in self.bih: # from high-level to low-level
                level += 1
                for bi in big:
                    bi_nodes = bi.nodes()
                    # print("bi_nodes:",bi_nodes)
                    bi_edges = bi.edges()
                    # print("bi_edges:",bi_edges)
                    if u in bi_nodes and v in bi_nodes:
                        print("....re_route")
                        print "get route at level_num:",level
                        print("bi_node_num:",len(bi_nodes))
                        print("bi_edge_num:",len(bi_edges))
                        route = nx.shortest_path(bi,u,v)
                        cost = time.clock()-start # cost_t = time.time()-start_t
                        print "cost_re:", cost
                        return route
            if nx.has_path(self.g,u,v):
                print("....re_shortest_path")
                route = nx.shortest_path(self.g,u,v)
            cost = time.clock()-start
            print "cost_re:", cost
            return route
        else:
            bi_nodes = bi.nodes()
            print("bi_node_num:",len(bi_nodes))
            bi_edges = bi.edges()
            print("bi_edge_num:",len(bi_edges))
            route = nx.shortest_path(bi,u,v)
            cost = time.clock()-start # cost_t = time.time()-start_t
            print "cost_ree:", cost
            return route

    def di_route(self, u, v):
        start = time.clock()
        route = None
        if nx.has_path(self.g,u,v):
            print("....di_route")
            bw = nx.get_edge_attributes(self.g,'weight')
            routes = nx.all_shortest_paths(self.g,u,v) # generator
            high_bw = 0
            for r in routes:
                if bw.has_key((r[0],r[1])):
                    min_bw = bw[(r[0],r[1])]
                else:
                    min_bw = bw[(r[1],r[0])]
                num = len(r)
                for i in range(1,num-1):
                    if bw.has_key((r[i],r[i+1])) and min_bw>bw[(r[i],r[i+1])]:
                        min_bw = bw[(r[i],r[i+1])]
                    elif bw.has_key((r[i+1],r[i])) and min_bw>bw[(r[i+1],r[i])]:
                        min_bw = bw[(r[i+1],r[i])]
                if min_bw > high_bw:
                    high_bw = min_bw
                    route = r
        cost = time.clock()-start
        print "cost_di:", cost
        return route
    
def topo_manual():
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

def topo_er(nodes):
    bws = [1,2,3,4,5,6,7,8,9,10]
    network = nx.erdos_renyi_graph(nodes,0.009) # (n, alpha=0.4, beta=0.1, L=None, domain=(0, 0, 1, 1)):
    g = nx.Graph()
    g.add_nodes_from(network.nodes())
    for link in network.edges():
        bw = random.choice(bws)
        g.add_edge(link[0],link[1],{'weight':bw})
        g.add_edge(link[1],link[0],{'weight':bw})
    return g

def topo_wax(nodes):
    bws = [1,2,3,4,5,6,7,8,9,10]
    network = nx.waxman_graph(nodes,0.45,0.15) # (n, alpha=0.4, beta=0.1, L=None, domain=(0, 0, 1, 1)):
    g = nx.Graph()
    g.add_nodes_from(network.nodes())
    for link in network.edges():
        bw = random.choice(bws)
        g.add_edge(link[0],link[1],{'weight':bw})
        g.add_edge(link[1],link[0],{'weight':bw})
    return g

def main(nodes, test): # test is 1 or 2
    #generate topo
    g = topo_er(nodes)
    g_nodes = g.nodes()
    print("topo_nodes:",len(g_nodes))
    g_edges = g.edges()
    print("topo_edges:",len(g_edges))
    # print('...............network.............')
    # print("-->nodes:")
    # print(g.nodes())
    # print("-->edges:")
    # links = g.edges()
    # weights = nx.get_edge_attributes(g,'weight')
    # for i in links:
    #     print(i, weights[(i[0],i[1])])
    # print('...............network.............')

    # create re obj
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

    print('............ROUTE................')
    if test == 1:
        test_1(re)
    elif test == 2:
        test_2(re)
    print('............ROUTE................')

def test_1(re):
    res_re = re.re_route(1,18)
    res_di = re.di_route(1,18)
    print('route_re:',res_re)
    print('route_di:',res_di)

def test_2(re):
    level = len(re.bih) # bih is a list
    big = re.bih[0] # big is a set
    # bi  = random.choice(big)

    bi = big[0]
    max_n = len(bi)
    for i in range(1,len(big)):
        n = len(big[i])
        if n > max_n:
            bi = big[i]
            max_n = n

    nodes = bi.nodes()
    print("select u and v from nodes::::",nodes)
    nodes_num = len(nodes)
    if nodes_num > 1:
        u = random.choice(nodes)
        v = u
        while v == u:
            v = random.choice(nodes)
        res_re = re.re_route(u,v)
        res_ree = re.re_route(u,v,bi)
        res_di = re.di_route(u,v)
        print('route_re:',res_re)
        print('route_ree:',res_ree)
        print('route_di:',res_di)

def test_3(nodes):
    #generate er topo
    er = topo_er(nodes)
    er_nodes = er.nodes()
    print("er_nodes:",len(er_nodes))
    er_edges = er.edges()
    print("er_edges:",len(er_edges))

    # print('...............er network.............')
    # print("-->nodes:")
    # print(er.nodes())
    # print("-->edges:")
    # links = er.edges()
    # weights = nx.get_edge_attributes(er,'weight')
    # for i in links:
    #     print(i, weights[(i[0],i[1])])
    # print('...............er network.............')

    re = ReRouter(er)
    bw_level = [7,5,2]
    re.build_BIH(bw_level)
    print('............er BIH................')
    for i in range(len(re.bih)):
        print "------------level:",bw_level[i],'bi count:',len(re.bih[i])
    print('............er BIH................')
    # print('............er BIH................')
    # for i in range(len(re.bih)):
    #     print "------------level:",bw_level[i]
    #     for bi in re.bih[i]:
    #         print("-----bi:")
    #         print("node:")
    #         print(bi.nodes())
    #         print("edges:")
    #         print(bi.edges())
    # print('............er BIH................')

    #generate wax topo
    wax = topo_wax(nodes)
    wax_nodes = wax.nodes()
    print("wax_nodes:",len(wax_nodes))
    wax_edges = wax.edges()
    print("wax_edges:",len(wax_edges))

    # print('...............wax network.............')
    # print("-->nodes:")
    # print(wax.nodes())
    # print("-->edges:")
    # links = wax.edges()
    # weights = nx.get_edge_attributes(wax,'weight')
    # for i in links:
    #     print(i, weights[(i[0],i[1])])
    # print('...............wax network.............')

    re = ReRouter(wax)
    bw_level = [7,5,2]
    re.build_BIH(bw_level)
    print('............wax BIH................')
    for i in range(len(re.bih)):
        print "------------level:",bw_level[i],'bi count:',len(re.bih[i])
    print('............wax BIH................')
    # print('............wax BIH................')
    # for i in range(len(re.bih)):
    #     print "------------level:",bw_level[i]
    #     for bi in re.bih[i]:
    #         print("-----bi:")
    #         print("node:")
    #         print(bi.nodes())
    #         print("edges:")
    #         print(bi.edges())
    # print('............wax BIH................')

if __name__ == "__main__":
    # nodes = [30,50,70,100,200,300,400,500,600,700] #
    # for i in nodes:
    #     print(">>>>>>>>>>>>nodes<<<<<<<<<<<<<:",i)
    #     test_3(i)

    # nodes = [30,50,70,100,300,500,700,1000]
    nodes = [700]
    for i in nodes:
        print(">>>>>>>>>>>>nodes<<<<<<<<<<<<<:",i)
        main(i,1)

















