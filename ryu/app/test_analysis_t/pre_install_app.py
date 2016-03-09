#!/usr/bin/env python
# -*- coding: utf-8 -*-
import networkx as nx
import copy

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, icmp
from ryu.lib.packet import ether_types
from ryu.lib import hub

'''
for linear topology:
pre-install flow entries for end-to-end hosts('h1' and 'h2')
'''
class ProactiveApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProactiveApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.discover_thread = hub.spawn(self.pre_install)

        # {dpid:{port:mac,port:mac,...},dpid:{port:mac,port:mac,...},...} only switches'mac
        self.dpids_port_to_mac = dict()
        # [dpid,dpid,...]
        self.dpids = list()

        # {(dpid,port):host_mac,(dpid,port):host_mac,...} only hosts'mac
        self.dpids_port_to_host = dict()
        #[host_mac,host_mac,host_mac,...]
        self.hosts = list()

        #{(src_dpid,dst_dpid):(src_port,dst_port),():(),...}
        self.links_dpid_to_port = dict()
        # [(src_dpid,dst_dpid),(src_dpid,dst_dpid),...]
        self.links = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        # {
        # (dpid,dpid):{xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid],...},
        # (dpid,dpid):{xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid],...},
        # ...}
        self.path_table = dict()

        self.dpid_to_dp = dict()

        self.SLEEP_PERIOD = 2 #seconds

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    def pre_install(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self._update_topology()
            self._update_hosts()
            if self.pre_adjacency_matrix != self.adjacency_matrix:
                self.logger.info('***********discover_topology thread: TOPO  UPDATE***********')
                self.path_table = self._get_path_table(self.adjacency_matrix)
                self.pre_install_flow()

    def _update_topology(self):
        switch_list = get_all_switch(self)
        if len(switch_list) != 0:
            self.dpids_port_to_mac = self._get_dpids_port_to_mac(switch_list)
            self.dpids = self._get_dpids(switch_list) #[dpid,dpid,dpid,...]
        link_dict = get_all_link(self)
        if len(link_dict) != 0:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)
            self.links = self._get_links(self.links_dpid_to_port) #[(src.dpid,dst.dpid),(src.dpid,dst.dpid),...]
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

    def _get_links(self,link_ports_table):
        return link_ports_table.keys()

    def _get_links_dpid_to_port(self,link_dict):
        table = dict()
        for link in link_dict.keys():
            src = link.src #ryu.topology.switches.Port
            dst = link.dst
            table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
        return table

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

    def _get_path_table(self, matrix):
        if matrix:
            dpids = matrix.keys()
            g = nx.Graph()
            g.add_nodes_from(dpids)
            for i in dpids:
                for j in dpids:
                    if matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
            return self.__graph_to_path(g)

    def __graph_to_path(self,g): # {(i,j):[[],[],...],(i,j):[[],[],[],..],...}
        all_shortest_paths = dict()
        for i in g.nodes():
            for j in g.nodes():
                if i == j:
                    continue
                all_shortest_paths[(i,j)] = list()
                try:
                    nx.shortest_path(g,i,j)
                except nx.exception.NetworkXNoPath:
                    continue
                for each in nx.all_shortest_paths(g,i,j):
                    all_shortest_paths[(i,j)].append(each)
        return all_shortest_paths

    def _update_hosts(self):
        host_list = get_all_host(self)
        if host_list:
            self.dpids_port_to_host = self._get_dpids_port_to_host(host_list)
            self.hosts = self._get_hosts(host_list)

    def _get_dpids_port_to_host(self,host_list):
        table = dict()
        for host in host_list:
            host_mac = host.mac
            host_port = host.port # Port
            dpid = host_port.dpid
            table[(dpid,host_port.port_no)] = host_mac
        return table

    def _get_hosts(self,host_list):
        hosts = list()
        for host in host_list:
            hosts.append(host.mac)
        return hosts

    def pre_install_flow(self):
        print("execute pre-install flow")
        if len(self.hosts) == 2:
            print("host num:",2)
            host1 = self.hosts[0]
            host2 = self.hosts[1]
            self._pre_install_flow(host1,host2)
            self._pre_install_flow(host2,host1)

    def _pre_install_flow(self,host1,host2):
        host1_dpid = None
        host2_dpid = None
        host1_port = None
        host2_port = None
        for dpid_port in self.dpids_port_to_host.keys():
                if self.dpids_port_to_host[dpid_port] == host1:
                    host1_dpid = dpid_port[0]
                    host1_port = dpid_port[1]
                elif self.dpids_port_to_host[dpid_port] == host2:
                    host2_dpid = dpid_port[0]
                    host2_port = dpid_port[1]
        if host1_dpid == host2_dpid:
            datapath = self.dpid_to_dp[host1_dpid]
            parser =  datapath.ofproto_parser
            priority = OFP_DEFAULT_PRIORITY
            match = parser.OFPMatch(in_port=host1_port,eth_dst=host2) # , eth_dst=host2
            actions = [parser.OFPActionOutput(host2_port)]
            self.add_flow(datapath, priority, match, actions)
        else:
            traffic = self.path_table[(host1_dpid,host2_dpid)][0]
            length = len(traffic)
            for i in range(length):
                datapath = self.dpid_to_dp[traffic[i]]
                parser = datapath.ofproto_parser
                priority = OFP_DEFAULT_PRIORITY
                if i == 0:
                    match = parser.OFPMatch(in_port=host1_port,eth_dst=host2) # , eth_dst=host2
                    out_port = self.links_dpid_to_port[(traffic[i],traffic[i+1])][0]
                    actions = [parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, priority, match, actions)
                elif i == length -1:
                    in_port = self.links_dpid_to_port[(traffic[i-1],traffic[i])][1]
                    match = parser.OFPMatch(in_port=in_port,eth_dst=host2) # , eth_dst=host2
                    actions = [parser.OFPActionOutput(host2_port)]
                    self.add_flow(datapath, priority, match, actions)
                else:
                    in_port = self.links_dpid_to_port[(traffic[i-1],traffic[i])][1]
                    out_port = self.links_dpid_to_port[(traffic[i],traffic[i+1])][0]
                    match = parser.OFPMatch(in_port=in_port,eth_dst=host2) # , eth_dst=host2
                    actions = [parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, priority, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        ar = pkt.get_protocol(arp.arp)
        # ic = pkt.get_protocol(icmp.icmp)
        #
        if isinstance(ar, arp.arp):
            print("-----arp packet------")
        #     print("dpid:",datapath.id)
        #     print(pkt)
        #     for each in self.mac_to_port:
        #         print "dpid:",each
        #         for a in self.mac_to_port[each]:
        #             print "mac:",a,"->","port:",self.mac_to_port[each][a]
        # if isinstance(ic, icmp.icmp):
        #     print("-----icmp packet------")
        #     print("dpid:",datapath.id)
        #     print(pkt)
        #     for each in self.mac_to_port:
        #         print "dpid:",each
        #         for a in self.mac_to_port[each]:
        #             print "mac:",a,"->","port:",self.mac_to_port[each][a]

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
