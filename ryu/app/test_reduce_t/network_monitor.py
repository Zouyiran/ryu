# -*- coding: utf-8 -*-

import copy
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.topology.api import get_all_switch, get_all_link, get_all_host

from command_sender import CommandSender

class NetworkMonitor(app_manager.RyuApp):
    '''
    topo_aware thread aware the topology --then--> generate adjacency_matrix
    according to adjacency_matrix --calculate--> path_table ( only find paths between edge switches)
    if path_table changed --then-->  pre-install(add or delete) mpls flow entries
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkMonitor, self).__init__(*args, **kwargs)
        self.name = 'NetworkMonitor'
        self.commandSender = CommandSender()

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

        self.dpid_ip_to_port = dict() # {dpid:{host_ip:port,host_ip:port,...},...}
        self.access_table = dict() # {(dpid,port):ip,(dpid,port):ip,...}

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
                self.commandSender.add_flow(datapath, 0, match, actions)

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
