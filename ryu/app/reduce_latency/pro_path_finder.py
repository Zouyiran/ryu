# -*- coding: utf-8 -*-

import copy
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.topology.api import get_all_switch, get_all_link, get_all_host

from flow_sender import FlowSender


class PathFinder(app_manager.RyuApp):
    '''
    topo_aware thread aware the topology --then--> generate adjacency_matrix
    according to adjacency_matrix --calculate--> path_table ( only find paths between edge switches)
    if path_table changed --then-->  pre-install(add or delete) mpls flow entries
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PathFinder, self).__init__(*args, **kwargs)
        self.name = 'PathFinder'
        self.flowSender = FlowSender()

        # {dpid:{port:mac,port:mac,...},dpid:{port:mac,port:mac,...},...} only switches'mac
        self.dpids_port_to_mac = dict()
        # [dpid,dpid,...]
        self.dpids = list()
        self.access_dpids = list()

        # {dpid:dp, dpid:dp, dpid:dp,...}
        self.dpid_to_dp = dict()

        # {dpid:[1],dpid:[1,2],dpid:[4],...}
        self.dpids_to_access_port = dict()

        #{(src_dpid,dst_dpid):(src_port,dst_port),():(),...}
        self.links_dpid_to_port = dict()
        # [(src_dpid,dst_dpid),(src_dpid,dst_dpid),...]
        self.links = list()

        # {(dpid,port):host_mac,(dpid,port):host_mac,...} only hosts'mac
        self.dpids_port_to_host = dict()
        #[host_mac,host_mac,host_mac,...]
        self.hosts = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

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

        self.SLEEP_PERIOD = 10 #seconds

        hub.spawn(self._discover)

    # install table-miss flow entry for each switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # add miss entry
        self.flowSender.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.dpid_to_dp:
                self.logger.info('register datapath: %04x', datapath.id)
                self.dpid_to_dp[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.dpid_to_dp:
                self.logger.info('un register datapath: %04x', datapath.id)
                del self.dpid_to_dp[datapath.id]

    def _discover(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self.update_topology()

            if self.pre_adjacency_matrix != self.adjacency_matrix:
                self.logger.info('***********network_aware thread: adjacency_matrix CHANGED***********')
                self.pre_path_table = copy.deepcopy(self.pre_path_table)
                self.path_table = self.get_path_table(self.adjacency_matrix,self.dpids_to_access_port)

                if self.pre_path_table != self.path_table:
                    self.logger.info('***********network_aware thread: path_table CHANGED***********')
                    # delete old mpls_path, add new mpls_path
                    self.pre_setup_flows(self.pre_path_table,self.path_table)

                    # #print for debug
                    # self._show_dpids()
                    # self._show_links()
                    # self._show_dpid_port_to_mac()
                    # self._show_links_dpid_to_port()
                    # self._show_matrix()
                    # self._show_path_table()
    #unused
    def _install_arp_entry(self):
        for dpid in self.dpids_to_access_port:
            if len(self.dpids_to_access_port[dpid]) == 0:# edge switch
                datapath = self.dpid_to_dp[dpid]
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                # add arp flood entry
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_dst='00:00:00:00:00:00')
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                self.flowSender.add_flow(datapath, 0, match, actions)

    def update_topology(self):
        switch_list = get_all_switch(self)
        if len(switch_list) != 0:
            self.dpids_port_to_mac = self._get_dpids_port_to_mac(switch_list)
            self.dpids = self._get_dpids(switch_list) #[dpid,dpid,dpid,...]
        link_dict = get_all_link(self)
        if len(link_dict) != 0:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)
            self.links = self._get_links(self.links_dpid_to_port) #[(src.dpid,dst.dpid),(src.dpid,dst.dpid),...]
        if self.dpids_port_to_mac and self.links_dpid_to_port:
            self.dpids_to_access_port = self._get_access_port(self.links_dpid_to_port, self.dpids_port_to_mac)
            self.access_dpids = self.get_access_dpids(self.dpids_to_access_port)
        if self.dpids and self.links:
            self.adjacency_matrix = self._get_adjacency_matrix(self.dpids, self.links)

    def _get_dpids_port_to_mac(self,switch_list):
        table = dict()
        for switch in switch_list:
            dpid = switch.dp.id
            table.setdefault(dpid,{})
            ports = switch.ports
            for port in ports:
                table[dpid][port.port_no] =  port.hw_addr
        return table

    def _get_dpids(self,switch_list):
        dpid_list = list()
        for switch in switch_list:
            dpid_list.append(switch.dp.id)
        return dpid_list

    def _get_links_dpid_to_port(self,link_dict):
        table = dict()
        for link in link_dict.keys():
            src = link.src #ryu.topology.switches.Port
            dst = link.dst
            table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
        return table

    def _get_links(self,link_ports_table):
        return link_ports_table.keys()

    def _get_access_port(self,links_dpid_to_port, dpids_port_to_mac):
        table = dict()
        for dpid in dpids_port_to_mac.keys():
            table.setdefault(dpid,[])
            all_ports = self.dpids_port_to_mac[dpid].keys()
            interior_ports = []
            for dpid_pair in links_dpid_to_port.keys():
                if dpid_pair[0] == dpid:
                    port = links_dpid_to_port[dpid_pair][0]
                    if port not in interior_ports:
                        interior_ports.append(port)
                elif dpid_pair[1] == dpid:
                    port = links_dpid_to_port[dpid_pair][1]
                    if port not in interior_ports:
                        interior_ports.append(port)
            for each_port in all_ports:
                if each_port not in interior_ports:
                    table[dpid].append(each_port)
        return table # {dpid:[1],dpid:[1,2],dpid:[4],...}

    def get_access_dpids(self, dpids_to_access_port):
        access_dpids = list()
        for dpid in dpids_to_access_port.keys():
            if len(dpids_to_access_port[dpid]) != 0:
                access_dpids.append(dpid)
        return access_dpids

    def _get_adjacency_matrix(self,dpids,links):
        graph = dict()
        for src in dpids:
            graph[src] = dict()
            for dst in dpids:
                graph[src][dst] = float('inf')
                if src == dst:
                    graph[src][dst] = 0
                elif (src, dst) in links:
                    graph[src][dst] = 1
        return graph

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

    def delete_pre_install_flow(self,mpls_to_path):
        print("...................DELETE pre-install flow..................")
        for each_mpls in mpls_to_path.keys():
            self.__delete_flow(each_mpls,mpls_to_path[each_mpls])

    # delete old mpls_path, add new mpls_path
    def pre_setup_flows(self,pre_path_table, path_table):
        print("...................pre-install flow..................")
        if len(pre_path_table) == 0 and len(path_table) != 0: # initial
            print("...................initial flows..................")
            self.LABEL = 0
            self.LABEL_BE_USED.clear()
            self.LABEL_RECYCLE.clear()
            for path_pair in path_table.keys():
                paths = path_table[path_pair]
                path_num = len(paths)
                if path_num > 0:
                    for path in paths:
                        n = len(path)
                        if n > 2:
                            self.mpls_to_path[self.LABEL] = path
                            self.LABEL_BE_USED.add(self.LABEL) # record its mpls label
                            self.__add_flow(path,self.LABEL)
                            self.LABEL += 1
        else: # network change
            print("...................network changed flows..................")
            delete_path_table = dict()
            for dpid_pair in self.pre_path_table:
                if dpid_pair not in self.path_table:
                    delete_path_table[dpid_pair] = self.pre_path_table[dpid_pair]
                elif self.pre_path_table[dpid_pair] != self.path_table[dpid_pair]:
                    delete_path_table[dpid_pair] = list()
                    for each_path in self.pre_path_table[dpid_pair]:
                        if each_path not in self.path_table[dpid_pair]:
                            delete_path_table[dpid_pair].append(each_path)
            for dpid_pair in delete_path_table:
                paths = delete_path_table[dpid_pair]
                path_num = len(paths)
                if path_num > 0:
                    for path in paths:
                        n = len(path)
                        if n > 2:
                            for label in self.mpls_to_path:
                                if self.mpls_to_path[label] == path:
                                    self.LABEL_BE_USED.remove(label)
                                    self.LABEL_RECYCLE.add(label)
                                    del self.mpls_to_path[label]
                                    self.__delete_flow(path,label)
                                    break
            add_path_table = dict()
            for dpid_pair in self.path_table:
                if dpid_pair not in self.pre_path_table:
                    add_path_table[dpid_pair] = self.path_table[dpid_pair]
                elif self.pre_path_table[dpid_pair] != self.path_table[dpid_pair]:
                    add_path_table[dpid_pair] = list()
                    for each_path in self.path_table[dpid_pair]:
                        if each_path not in self.pre_path_table[dpid_pair]:
                            add_path_table[dpid_pair].append(each_path)
            for dpid_pair in add_path_table:
                paths = add_path_table[dpid_pair]
                path_num = len(paths)
                if path_num > 0:
                    for path in paths:
                        n = len(path)
                        if n > 2:
                            if self.LABEL_RECYCLE:
                                label = self.LABEL_RECYCLE.pop()
                                self.mpls_to_path[label] = path
                                self.LABEL_BE_USED.add(label)
                                self.__add_flow(path,label)
                            else:
                                self.mpls_to_path[self.LABEL] = path
                                self.LABEL_BE_USED.add(self.LABEL)
                                self.__add_flow(path,self.LABEL)
                                self.LABEL += 1

    def __delete_flow(self, path, label):
        n = len(path)
        if n >2:
            for i in range(1,n-1):
                dpid = path[i]
                priority = OFP_DEFAULT_PRIORITY # 32768 or 0x8000
                match = {
                        "dl_type":ether_types.ETH_TYPE_MPLS,
                        "mpls_label":label,
                        }
                self.flowSender.delete_flow_rest(dpid, priority, match)

    def __add_flow(self, path, label):
        n = len(path)
        if n >2:
            for i in range(1,n-1):
                dpid = path[i]
                priority = OFP_DEFAULT_PRIORITY # 32768 or 0x8000
                in_port = self.links_dpid_to_port[(path[i-1],path[i])][1]
                out_port = self.links_dpid_to_port[(path[i],path[i+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_MPLS,
                        "in_port":in_port,
                        "mpls_label":label,
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
                self.flowSender.add_flow_rest_1(dpid, priority, match, actions)


#---------------------Print_to_debug------------------------
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

    def _show_dpids(self):
        print "---------------------dpids---------------------"
        for each in self.dpids:
            print each,
        print""

    def _show_hosts(self):
        print "---------------------!hosts!---------------------"
        for each in self.hosts:
            print each,
        print""

    def _show_links(self):
        print "----------------------links--------------------"
        for each in self.links:
            print each,
        print""

    def _show_dpid_port_to_mac(self):
        print "----------------------dpid_port_to_mac--------------------"
        for dpid in self.dpids_port_to_mac.keys():
            print "dpid:",dpid
            for port in self.dpids_port_to_mac[dpid].keys():
                print "port:",port,"->","mac",self.dpids_port_to_mac[dpid][port]
        print""

    def _show_dpid_port_to_host(self):
        print "----------------------!dpid_port_to_host!--------------------"
        for sw in self.dpids_port_to_host.keys():
            print "(sw_dpid:",sw[0],",","sw_port:",sw[1],") ->","host_mac:",self.dpids_port_to_host[sw]
        print""

    def _show_links_dpid_to_port(self):
        print "----------------------links_dpid_to_port--------------------"
        for each in self.links_dpid_to_port:
            print "link_dpid:",each,"->","link_port:",self.links_dpid_to_port[each]
        print""
