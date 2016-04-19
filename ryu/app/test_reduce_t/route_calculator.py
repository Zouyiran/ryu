# -*- coding: utf-8 -*-

import copy
import random
import networkx as nx


class RouteCalculator(object):
    '''
    PathCalculator:
    1) mpls pre-install path
    2) elephant flow re-route
    3) general shortest path select

    '''

    # singletone
    _instance = None

    def __init__(self):
        super(RouteCalculator, self).__init__()
        self.name = 'PathCalculator'
        # {
        # (dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid],...],
        # (dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid],...],
        # ...}
        # just shortest path between edge_switches not contain interior_switches
        self.path_table = dict() # for mpls path pre-install
        self.pre_path_table = dict()

        self.route_table = dict()
        self.pre_route_table = dict()

    @staticmethod
    def get_instance():
        if not RouteCalculator._instance:
            RouteCalculator._instance = RouteCalculator()
        return RouteCalculator._instance

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
    def __graph_to_path(self, g, edge_dpids): # {(i,j):[],(i,j):[],...}
        path_table = dict()
        for i in edge_dpids:
            for j in edge_dpids:
                if i != j:
                    path = []
                    try:
                        temp = nx.shortest_path(g,i,j)
                        if len(temp) > 4: # 2
                            path = temp
                    except nx.exception.NetworkXNoPath:
                        pass
                    path_table[(i,j)] = path
        return path_table

    def get_route_table(self, matrix, dpids_to_access_port):
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
            return self.__graph_to_route(g, edge_dpids)
    def __graph_to_route(self, g, edge_dpids): # {(i,j):[],(i,j):[],...}
        route_table = dict()
        for i in edge_dpids:
            for j in edge_dpids:
                if i != j:
                    route = []
                    try:
                        route = nx.shortest_path(g,i,j)
                    except nx.exception.NetworkXNoPath:
                        pass
                    route_table[(i,j)] = route
        return route_table # just return shortest path between edge_switches

    def get_path(self, src_dpid, dst_dpid):
        path = None
        if src_dpid != dst_dpid:
            path = self.path_table[(src_dpid,dst_dpid)] # []
        return path

    def get_route(self, src_dpid, dst_dpid):
        route = None
        if src_dpid != dst_dpid:
            route = self.route_table[(src_dpid,dst_dpid)] # []
        return route

    def re_route(self):
        pass

#---------------------Print_to_debug------------------------
    def show_path_table(self):
        print "---------------------path_table---------------------"
        for pair in self.path_table.keys():
            print("pair:",pair)
            for each in self.path_table[pair]:
                print each,
            print""