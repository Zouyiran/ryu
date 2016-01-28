# -*- coding: utf-8 -*-

import copy
import logging
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0, ofproto_protocol
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu import utils
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_all_switch, get_link,get_all_link,get_all_host,get_host

from flow_dispatcher import FlowDispatcher


class PathFinder(object):
    '''
    Path Finder:
    find topology and get ovs information
    '''

    def __init__(self):
        # {dpid:{mac:port,mac:port,...},dpid:{mac:port,mac:port,...},...}
        self.dpid_mac_to_port = dict()
        # [dpid,dpid,...]
        self.dpids = list()

        self.hostmac_to_dpid = dict()
        self.hostmac_to_port = dict()
        # [hostmac, hostmac,...]
        self.hosts = list()

        #{(src_dpid,dst_dpid):(src_port,dst_port),():(),...}
        self.links_dpid_to_port = dict()
        # [(src_dpid,dst_dpid),(src_dpid,dst_dpid),...]
        self.links = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        # {(dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid]], (dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid]]}
        self.path_table = dict()

        self.SLEEP_PERIOD = 5 #seconds

        self.PRIORITY = OFP_DEFAULT_PRIORITY

        self.flowDispatcher = FlowDispatcher()

    def find(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self._update_topology()
            self._update_hosts() # TODO
            # when adjacency matrix is update,then update the path_table
            if self.pre_adjacency_matrix != self.adjacency_matrix:
                logging.info('discover_topology thread: TOPO  UPDATE...')
                self.path_table = self._get_path_table(self.adjacency_matrix)
                self.pre_install_flow(self.path_table)

    def pre_install_flow(self, path_table):
        for pair in path_table.keys():
            paths = path_table[pair] # [[],[],[],...]
            path_num = len(paths)
            if path_num == 0: # unreachable
                pass
            elif path_num == 1: # have only one path
                path = paths[0]
                mpls_label_str = ''
                for i in path:
                    mpls_label_str += str(i)
                if len(path) == 2:
                    pass
                else:
                    for i in range(1,len(path)-1):
                        dpid = path[i]
                        priority = self.PRIORITY
                        port_pair_1 = self.links_dpid_to_port[(path[i-1],path[i])]
                        in_port = port_pair_1[1]
                        port_pair_2 = self.links_dpid_to_port[(path[i],path[i+1])]
                        out_port = port_pair_2[0]
                        match = {
                                "dl_type":ether_types.ETH_TYPE_MPLS,
                                "in_port":in_port,
                                "mpls_label":int(mpls_label_str),
                                "mpls_tc":5,
                                "mpls_bos":1
                                }
                        actions = [{"type":"OUTPUT","port":out_port}]
                        self.flowDispatcher.add_flow_rest(dpid, priority, match, actions)
            else: # have several paths
                path = paths[0]
                mpls_label_str = ''
                for i in path:
                    mpls_label_str += str(i)
                if len(path) == 2:
                    pass
                else:
                    for i in range(1,len(path)-1):
                        dpid = path[i]
                        priority = self.PRIORITY
                        port_pair_1 = self.links_dpid_to_port[(path[i-1],path[i])]
                        in_port = port_pair_1[1]
                        port_pair_2 = self.links_dpid_to_port[(path[i],path[i+1])]
                        out_port = port_pair_2[0]
                        match = {
                                "dl_type":ether_types.ETH_TYPE_MPLS,
                                "in_port":in_port,
                                "mpls_label":int(mpls_label_str),
                                "mpls_tc":5,
                                "mpls_bos":1
                                }
                        actions = [{"type":"OUTPUT","port":out_port}]
                        self.flowDispatcher.add_flow_rest(dpid, priority, match, actions)



    def _update_topology(self):
        switch_list = get_all_switch(self)
        if switch_list:
            self.dpid_mac_to_port = self._get_switches_mac_to_port(switch_list)
            self.dpids = self._get_switches(switch_list) # dpid
        link_dict = get_all_link(self)
        if link_dict:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)
            self.links = self._get_links(self.links_dpid_to_port) #(src.dpid,dst.dpid)
        if self.dpids and self.links:
            self.adjacency_matrix = self._get_adjacency_matrix(self.dpids, self.links)

    def _update_hosts(self):
        host_obj  = get_all_host(self)
        if host_obj:
            self.hostmac_to_dpid, self.hostmac_to_port = self._get_hosts_to_dpid_and_port(host_obj)
            self.hosts = self._get_hosts(host_obj) # mac

    def _get_path_table(self, matrix):
        if matrix:
            g = nx.Graph()
            g.add_nodes_from(self.dpids)
            for i in self.dpids:
                for j in self.dpids:
                    if matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
            return self.__graph_to_path(g)

    def __graph_to_path(self,g):
        all_shortest_paths = dict()
        for i in g.nodes():
            for j in g.nodes():
                if i == j:
                    continue
                all_shortest_paths[(i,j)] = list()
                for each in nx.all_shortest_paths(g,i,j):
                    try:
                        all_shortest_paths[(i,j)].append(each)
                    except nx.NetworkXNoPath:
                        print("CATCH EXCEPTION: nx.NetworkXNoPath")
        return all_shortest_paths

    # def _get_traffic_table(self, path_table):
    #     traffic_table = dict()
    #     for src_host in self.hosts: # mac
    #         for dst_host in self.hosts: # mac
    #             if src_host == dst_host:
    #                 continue
    #             src_dpid = self.hostmac_to_dpid[src_host]
    #             dst_dpid = self.hostmac_to_dpid[dst_host]
    #             if src_dpid == dst_dpid: # belongs to a same dpid
    #                 traffic_table[(src_host, dst_host)]  = [src_dpid]
    #             elif (src_dpid, dst_dpid) in path_table.keys():
    #                 traffic_table[(src_host, dst_host)]  = path_table[(src_dpid, dst_dpid)][0]
    #             else: # unreachable
    #                 traffic_table[(src_host, dst_host)]  = []
    #     return traffic_table

    def _get_switches_mac_to_port(self,switch_list):
        table = dict()
        for switch in switch_list:
            dpid = switch.dp.id
            # print("_get_switches_mac_to_port -> dpid:",dpid)
            table.setdefault(dpid,{})
            ports = switch.ports
            for port in ports:
                table[dpid][port.hw_addr] =  port.port_no
        return table

    def _get_switches(self,switch_list):
        dpid_list = list()
        for switch in switch_list:
            dpid_list.append(switch.dp.id)
        return dpid_list #[dpid,dpid, dpid,...]

    def _get_links_dpid_to_port(self,link_dict):
        table = dict()
        for link in link_dict.keys():
            src = link.src #ryu.topology.switches.Port
            dst = link.dst
            table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
        return table

    def _get_links(self,link_ports_table):
        return link_ports_table.keys() #[(src.dpid,dst.dpid),(src.dpid,dst.dpid),...]

    def _get_adjacency_matrix(self,switches,links):
        graph = dict()
        for src in switches:
            graph[src] = dict()
            for dst in switches:
                graph[src][dst] = float('inf')
                if src == dst:
                    graph[src][dst] = 0
                elif (src, dst) in links:
                    graph[src][dst] = 1
        return graph

    def _get_hosts_to_dpid_and_port(self,host_list):
        hostmac_to_dpid = dict()
        hostmac_to_port = dict()
        for host in host_list:
            host_mac = host.mac
            host_port = host.port
            hostmac_to_port[host_mac] = host_port.port_no
            dpid = host_port.dpid
            hostmac_to_dpid[host_mac] = dpid
        return  hostmac_to_dpid, hostmac_to_port

    def _get_hosts(self, host_list):
        table = list()
        for each in host_list:
            table.append(each.mac) #[mac,mac,mac,...]
        return table

#---------------------print_to_debug------------------------
    def _show_matrix(self):
        switch_num = len(self.adjacency_matrix)
        print "---------------------adjacency_matrix---------------------"
        print '%10s' % ("switch"),
        for i in range(1, switch_num + 1):
            print '%10d' % i,
        print ""
        for i in self.adjacency_matrix.keys():
            print '%10d' % i,
            for j in self.adjacency_matrix[i].values():
                print '%10.0f' % j,
            print ""

    def _show_path_table(self):
        print "---------------------path_table---------------------"
        for pair in self.path_table.keys():
            print("pair:",pair)
            for each in self.path_table[pair]:
                print each,
            print""

    # def _show_traffic_table(self):
    #     print "---------------------traffic_table---------------------"
    #     for pair in self.traffic_table.keys():
    #         print("pair:",pair)
    #         print self.traffic_table[pair]

    def _show_host(self):
        print "---------------------show_host---------------------"
        for each in self.hostmac_to_dpid:
            print("each:",each,"->","dpid:",self.hostmac_to_dpid[each])
        for each in self.hostmac_to_port:
            print("each:",each,"->","port:",self.hostmac_to_port[each])
