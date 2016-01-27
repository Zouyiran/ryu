# -*- coding: utf-8 -*-

import logging
import struct
import copy
from operator import attrgetter
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

from config import *

import json

import requests




class PathFinder(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PathFinder, self).__init__(*args, **kwargs)


        self.mac_to_port = dict()
        self.dpid_mac_to_port = dict()
        self.hostmac_to_dpid = dict()
        self.hostmac_to_port = dict()
        self.links_dpid_to_port = dict()

        self.dpids = list()
        self.links = list()
        self.hosts = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        # table means: a dict
        self.path_table = dict()
        self.pre_path_table = dict()
        self.differ_path_table = dict()

        self.traffic_table = dict()

        self.id_to_dp = dict()

        #start a topology discover thread
        self.discover_thread = hub.spawn(self.discover_topology)

        self.SLEEP_PERIOD = 10 #seconds
        self.PRIORITY = OFP_DEFAULT_PRIORITY

    def _get_traffic_table(self, path_table):
        traffic_table = dict()
        for src_host in self.hosts: # mac
            for dst_host in self.hosts: # mac
                if src_host == dst_host:
                    continue
                src_dpid = self.hostmac_to_dpid[src_host]
                dst_dpid = self.hostmac_to_dpid[dst_host]
                if src_dpid == dst_dpid: # belongs to a same dpid
                    traffic_table[(src_host, dst_host)]  = [src_dpid]
                elif (src_dpid, dst_dpid) in path_table.keys():
                    traffic_table[(src_host, dst_host)]  = path_table[(src_dpid, dst_dpid)][0]
        return traffic_table

    def install_flows(self, traffic_table):
        uri = "/stats/flowentry/add"
        self.PRIORITY  += 1
        for traffic in traffic_table.keys():
            if len(traffic_table[traffic]) == 1:# belongs to a same dpid
                dpid = traffic_table[traffic][0]
                in_port = self.hostmac_to_port[traffic[0]]
                print("in_port:",in_port)
                out_port = self.hostmac_to_port[traffic[1]]
                print("out_port:",out_port)
                data = {"dpid":dpid,
                        "table_id":0,
                        "idle_timeout":100,
                        "hard_timeout":100,
                        "priority":11111,
                        "match":{
                            "in_port":in_port
                        },
                        "actions":[{"type":"OUTPUT",
                                    "port":out_port}]
                        }
                json_data = json.dumps(data)
                requests.post(url=IP+uri,data =str(data))
            else:
                pass

    def discover_topology(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self._update_topology()
            if self.pre_adjacency_matrix != self.adjacency_matrix:
                self.logger.info('discover_topology thread: topo update...')
                self.path_table = self._get_path_table()
                self.traffic_table = self._get_traffic_table(self.path_table)
                self.install_flows(self.traffic_table)
            else:
                self.logger.info('discover_topology thread: topo NOT update...')

    def _update_topology(self):
        switch_list = get_all_switch(self)
        if switch_list:
            self.dpid_mac_to_port = self._get_switches_mac_to_port(switch_list)
            self.dpids = self._get_switches(switch_list) # dpid
            # print(self.dpids)

        host_list = get_all_host(self)
        if host_list:
            self.hostmac_to_dpid, self.hostmac_to_port = self._get_hosts_to_dpid_and_port(host_list)
            self.hosts = self._get_hosts(host_list) # mac
            # print(self.hosts)

        link_dict = get_all_link(self)
        if link_dict:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)
            self.links = self._get_links(self.links_dpid_to_port) #(src.dpid,dst.dpid)

        if self.dpids and self.links:
            self.adjacency_matrix = self._get_adjacency_matrix(self.dpids, self.links)
            self._show()

    def _get_path_table(self):
        if self.adjacency_matrix:
            g = nx.Graph()
            g.add_nodes_from(self.dpids)
            for i in self.dpids:
                for j in self.dpids:
                    if self.adjacency_matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
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

    def _get_differ_path_table(self):
        # differ_path_table = list()
        # if self.pre_path_table is None:
        #     differ_path_table = self.path_table
        # elif self.path_table is None:
        #     return list()
        # elif self.path_table != self.pre_path_table: # find the different path
        #     for each in self.path_table:
        #         if each not in self.pre_path_table:
        #             differ_path_table.append(each)
        return self.path_table


    def add_flow(self, datapath, idle_timeout, hard_timeout, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _of_state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.id_to_dp:
                self.logger.info('register datapath: %04x', datapath.id)
                self.id_to_dp[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.id_to_dp:
                self.logger.info('un register datapath: %04x', datapath.id)
                del self.id_to_dp[datapath.id]




    def _show(self):
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

    def _get_hosts_to_dpid_and_port(self,host_list):
        dpid_to_hostmac_to_port = dict()
        hostmac_to_dpid = dict()
        hostmac_to_port = dict()
        for host in host_list:
            host_mac = host.mac
            host_port = host.port
            hostmac_to_port[host_mac] = host_port.port_no
            dpid = host_port.dpid
            hostmac_to_dpid[host_mac] = dpid
            # dpid_to_host_to_port.setdefault(dpid,{})
            # dpid_to_host_to_port[dpid][host_mac] = host_port.port_no
        return  hostmac_to_dpid, hostmac_to_port

    def _get_hosts(self, host_list):
        table = list()
        for each in host_list:
            table.append(each.mac) #[mac,mac,mac,...]
        return table

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

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     if ev.msg.msg_len < ev.msg.total_len:
    #         self.logger.info("packet truncated: only %s of %s bytes",
    #                           ev.msg.msg_len, ev.msg.total_len)
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match['in_port']
    #
    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #
    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         self.logger.info(" ETH_TYPE_LLDP:0x%08x", ether_types.ETH_TYPE_LLDP)
    #         return
    #
    #     dst = eth.dst
    #     src = eth.src
    #     dpid = datapath.id
    #     self.mac_to_port.setdefault(dpid, {})
    #     self.mac_to_port[dpid][src] = in_port
    #
    #     if dst in self.mac_to_port[dpid]:
    #         out_port = self.mac_to_port[dpid][dst]
    #     else:
    #         out_port = ofproto.OFPP_FLOOD
    #
    #     actions = [parser.OFPActionOutput(out_port)]
    #
    #     # install a flow to avoid packet_in next time
    #     if out_port != ofproto.OFPP_FLOOD:
    #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
    #         if msg.buffer_id != ofproto.OFP_NO_BUFFER:
    #             #just add flow
    #             self.add_flow(datapath, 0,0,1, match, actions, msg.buffer_id)
    #             return
    #         else:
    #             #add flow and output
    #             self.add_flow(datapath, 0,0,1, match, actions)
    #
    #     data = None
    #     if msg.buffer_id == ofproto.OFP_NO_BUFFER:
    #         data = msg.data
    #
    #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
    #                               in_port=in_port, actions=actions, data=data)
    #     datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, 0, match, actions)
