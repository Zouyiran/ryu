# -*- coding: utf-8 -*-

import copy
import random
import networkx as nx
from ryu.ofproto import ofproto_v1_3


class PathCalculator(object):
    '''
    PathCalculator

    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self):
        super(PathCalculator, self).__init__()
        self.name = 'PathCalculator'
        # {
        # (dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid],...],
        # (dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid],...],
        # ...}
        # just shortest path between edge_switches not contain interior_switches
        self.path_table = dict()
        self.pre_path_table = dict()

        self.mpls_to_path = dict()

        self.LABEL = 0
        self.LABEL_BE_USED = set()
        self.LABEL_RECYCLE = set()

    def get_path_table(self, matrix, dpids_to_access_port): # just get shortest path between edge_switches
        if matrix:
            dpids = matrix.keys()
            g = nx.DiGraph()
            g.add_nodes_from(dpids)
            for i in dpids:
                for j in dpids:
                    if matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
            edge_dpids = []
            for each_dpid in dpids_to_access_port:
                if len(dpids_to_access_port[each_dpid]) != 0:# get edge_switches
                    edge_dpids.append(each_dpid)
            return self.__graph_to_path(g, edge_dpids)

    def __graph_to_path(self,g, edge_dpids): # {(i,j):[[],[],...],(i,j):[[],[],[],..],...}
        path_table = dict()
        for i in edge_dpids:
            for j in edge_dpids:
                if i != j:
                    path_table[(i,j)] = list()
                    try:
                        nx.shortest_path(g,i,j)
                    except nx.exception.NetworkXNoPath:
                        continue
                    for each in nx.all_shortest_paths(g,i,j):# nx.all_simple_paths(g,i,j)
                        path_table[(i,j)].append(each)
        return path_table # just return shortest path between edge_switches

    def get_traffic(self, src_dpid, dst_dpid):
        traffic = []
        all_traffic = self.path_table[(src_dpid,dst_dpid)]
        if all_traffic:
            i = random.randint(0,len(all_traffic)-1) # randomly select a path
            traffic = all_traffic[i]
        return traffic

#---------------------Print_to_debug------------------------
    def _show_path_table(self):
        print "---------------------path_table---------------------"
        for pair in self.path_table.keys():
            print("pair:",pair)
            for each in self.path_table[pair]:
                print each,
            print""