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
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_all_switch, get_link,get_all_link,get_all_host,get_host
import collections

# '''
# ofproto_v1_3_parser.py
# class OFPFlowMod(MsgBase)
#     def __init__(self, datapath, cookie=0, cookie_mask=0, table_id=0,
#                  command=ofproto.OFPFC_ADD,
#                  idle_timeout=0, hard_timeo
# ut=0,
#                  priority=ofproto.OFP_DEFAULT_PRIORITY,
#                  buffer_id=ofproto.OFP_NO_BUFFER,
#                  out_port=0, out_group=0, flags=0,
#                  match=None,
#                  instructions=[]):
# '''
'''
class OFPMatch(StringifyMixin):
    Flow Match Structure

    This class is implementation of the flow match structure having
    compose/query API.
    There are new API and old API for compatibility. the old API is
    supposed to be removed later.

    You can define the flow match by the keyword arguments.
    The following arguments are available.

    ================ =============== ==================================
    Argument         Value           Description
    ================ =============== ==================================
    in_port          Integer 32bit   Switch input port
    in_phy_port      Integer 32bit   Switch physical input port
    metadata         Integer 64bit   Metadata passed between tables
    eth_dst          MAC address     Ethernet destination address
    eth_src          MAC address     Ethernet source address
    eth_type         Integer 16bit   Ethernet frame type
    vlan_vid         Integer 16bit   VLAN id
    vlan_pcp         Integer 8bit    VLAN priority
    ip_dscp          Integer 8bit    IP DSCP (6 bits in ToS field)
    ip_ecn           Integer 8bit    IP ECN (2 bits in ToS field)
    ip_proto         Integer 8bit    IP protocol
    ipv4_src         IPv4 address    IPv4 source address
    ipv4_dst         IPv4 address    IPv4 destination address
    tcp_src          Integer 16bit   TCP source port
    tcp_dst          Integer 16bit   TCP destination port
    udp_src          Integer 16bit   UDP source port
    udp_dst          Integer 16bit   UDP destination port
    sctp_src         Integer 16bit   SCTP source port
    sctp_dst         Integer 16bit   SCTP destination port
    icmpv4_type      Integer 8bit    ICMP type
    icmpv4_code      Integer 8bit    ICMP code
    arp_op           Integer 16bit   ARP opcode
    arp_spa          IPv4 address    ARP source IPv4 address
    arp_tpa          IPv4 address    ARP target IPv4 address
    arp_sha          MAC address     ARP source hardware address
    arp_tha          MAC address     ARP target hardware address
    ipv6_src         IPv6 address    IPv6 source address
    ipv6_dst         IPv6 address    IPv6 destination address
    ipv6_flabel      Integer 32bit   IPv6 Flow Label
    icmpv6_type      Integer 8bit    ICMPv6 type
    icmpv6_code      Integer 8bit    ICMPv6 code
    ipv6_nd_target   IPv6 address    Target address for ND
    ipv6_nd_sll      MAC address     Source link-layer for ND
    ipv6_nd_tll      MAC address     Target link-layer for ND

    mpls_label       Integer 32bit   MPLS label
    mpls_tc          Integer 8bit    MPLS TC
    mpls_bos         Integer 8bit    MPLS BoS bit

    pbb_isid         Integer 24bit   PBB I-SID
    tunnel_id        Integer 64bit   Logical Port Metadata
    ipv6_exthdr      Integer 16bit   IPv6 Extension Header pseudo-field
    ================ =============== ==================================
'''

class PathFinder(app_manager.RyuApp):

    '''
     get topology
     generate the path table
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(PathFinder, self).__init__(*args, **kwargs)
        self.mac_to_port = dict()

        self.switches_mac_to_port = dict()
        self.hosts_mac_to_port = dict()
        self.links_dpid_to_port = dict()

        self.switches = list()
        self.links = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        self.path_table = list()
        self.pre_path_table = list()
        self.differ_path_table = list()

        self.id_to_dp = dict()
        self.datapaths= dict()

        # self.discover_thread = hub.spawn(self.discover_topology)

        self.SLEEP_PERIOD = 1 #seconds
        self.PRIORITY = OFP_DEFAULT_PRIORITY


        self.MAC_LIST = ["00:00:00:00:00:01",
                         "00:00:00:00:00:02",
                         "00:00:00:00:00:03",
                         "00:00:00:00:00:04",
                         "00:00:00:00:00:05",
                         "00:00:00:00:00:06"]

    def discover_topology(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self._update_topology()
            if self.pre_adjacency_matrix != self.adjacency_matrix:
                print("topo update")
            else:
                print("topo not update")
                # self._show()
                # self.path_table = self._get_paths()
                # for src in self.path_table.keys():
                #     print("src:",src)
                #     for dst in self.path_table[src].keys():
                #         print("dst:",dst)
                #         gen = self.path_table[src][dst]
                #         print(gen)

    # --------------------------------------------------------------------------
    def _update_topology(self):
        switch_list = get_all_switch(self) # return a list[ryu.topology.switches.Switch]
        if switch_list:
            self.switches_mac_to_port = self._get_switches_mac_to_port(switch_list)
        # for switch in self.switches_mac_to_port.keys():
        #     print("dpid:",switch)
        #     for mac in self.switches_mac_to_port[switch].keys():
        #         print("switch_mac:",mac,'->',"switch_port:",self.switches_mac_to_port[switch][mac])

        host_list = get_all_host(self) # return a list[ryu.topology.switches.Host]
        if host_list:
            self.hosts_mac_to_port = self._get_hosts_mac_to_port(host_list)
        # for dpid in self.hosts_mac_to_port.keys():
        #     print("dpid:",dpid)
        #     for mac in self.hosts_mac_to_port[dpid].keys():
        #         print("host_port:",mac,'->',"switch_port:",self.hosts_mac_to_port[dpid][mac])

        link_dict = get_all_link(self) # return ryu.topology.switches.LinkState{Link class -> timestamp}
        if link_dict:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)

        self.switches = self._get_switches(switch_list) # dpid
        self.links = self._get_links(self.links_dpid_to_port) #(src.dpid,dst.dpid)
        self.adjacency_matrix = self._get_adjacency_matrix(self.switches, self.links)

    def _get_hosts_mac_to_port(self,host_list):
        '''
        ('dpid:', 4)
        ('host_port:', '00:00:00:00:00:02', '->', 'switch_port:', 3)
        ('host_port:', '00:00:00:00:00:01', '->', 'switch_port:', 2)
        ('dpid:', 5)
        ('host_port:', '00:00:00:00:00:03', '->', 'switch_port:', 2)
        ('host_port:', '00:00:00:00:00:04', '->', 'switch_port:', 3)
        ('dpid:', 6)
        ('host_port:', '00:00:00:00:00:06', '->', 'switch_port:', 3)
        ('host_port:', '00:00:00:00:00:05', '->', 'switch_port:', 2)
        '''
        table = dict()
        for host in host_list:
            host_mac = host.mac
            host_port = host.port
            dpid = host_port.dpid
            table.setdefault(dpid,{})
            table[dpid][host_mac] = host_port.port_no
        return table

    def _get_switches_mac_to_port(self,switch_list):
        '''
        ('dpid:', 1)
        ('switch_mac:', '62:87:4c:5f:06:8a', '->', 'switch_port:', 1)
        ('switch_mac:', 'e6:2e:5e:f4:a8:dd', '->', 'switch_port:', 3)
        ('switch_mac:', 'a6:05:2f:9a:13:53', '->', 'switch_port:', 2)
        ('dpid:', 2)
        ('switch_mac:', 'c2:fb:7c:5b:6e:9e', '->', 'switch_port:', 2)
        ('switch_mac:', 'ca:3c:70:29:7d:50', '->', 'switch_port:', 1)
        ('dpid:', 3)
        ('switch_mac:', '0e:de:48:aa:a6:97', '->', 'switch_port:', 1)
        ('switch_mac:', '02:fe:77:8d:25:ba', '->', 'switch_port:', 2)
        ('dpid:', 4)
        ('switch_mac:', '46:70:97:3e:48:d6', '->', 'switch_port:', 2)
        ('switch_mac:', 'fa:61:db:70:c3:7f', '->', 'switch_port:', 3)
        ('switch_mac:', '52:57:78:55:ff:0f', '->', 'switch_port:', 1)
        ('dpid:', 5)
        ('switch_mac:', '9a:a0:88:f9:98:0d', '->', 'switch_port:', 2)
        ('switch_mac:', 'aa:d3:f5:9a:cf:90', '->', 'switch_port:', 1)
        ('switch_mac:', '76:ab:e3:f1:d4:7c', '->', 'switch_port:', 3)
        ('dpid:', 6)
        ('switch_mac:', '22:70:ce:59:26:a2', '->', 'switch_port:', 2)
        ('switch_mac:', 'd2:d6:53:e9:bc:84', '->', 'switch_port:', 3)
        ('switch_mac:', '1e:cd:25:1d:cc:6f', '->', 'switch_port:', 1)
        '''
        table = dict()
        for switch in switch_list:
            dpid = switch.dp.id
            table.setdefault(dpid,{})
            ports = switch.ports
            for port in ports:
                table[dpid][port.hw_addr] =  port.port_no
        return table

    def _get_links_dpid_to_port(self,link_dict):
        table = dict()
        for link in link_dict.keys():
            src = link.src #ryu.topology.switches.Port
            dst = link.dst
            table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
        return table

    def _get_switches(self,switch_list):
        dpid_list = list()
        for switch in switch_list:
            dpid_list.append(switch.dp.id)
        return dpid_list

    def _get_links(self,link_ports_table):
        return link_ports_table.keys()

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

    def _get_paths(self):
        if self.switches and self.links and self.adjacency_matrix:
            g = nx.Graph()
            g.add_nodes_from(self.switches)
            for i in self.adjacency_matrix.keys():
                for j in self.adjacency_matrix[i].keys():
                    if self.adjacency_matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
                    else:
                        continue
            all_shortest_paths = list()
            for i in g.nodes():
                for j in g.nodes():
                    if i == j:
                        continue
                    if g.has_node(i) and g.has_node(j):
                        for each in nx.all_shortest_paths(g,i,j):
                            try:
                                all_shortest_paths.append(each)
                            except nx.NetworkXNoPath:
                                print("catch nx.NetworkXNoPath")
            return all_shortest_paths

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

    def _get_differ_path_table(self):
        differ_path_table = list()
        if self.pre_path_table is None:
            print("self.pre_path_table is None")
            differ_path_table = self.path_table
        elif self.path_table is None:
            print("self.path_table is None")
            return list()
        elif self.path_table != self.pre_path_table: # find the different path
            print("self.path_table != self.pre_path_table")
            for each in self.path_table:
                if each not in self.pre_path_table:
                    differ_path_table.append(each)
        return differ_path_table
    # --------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        print("_state_change_handler")
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths: # register datapath: 0000000000000004
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    # events = [event.EventSwitchEnter,event.EventSwitchLeave, # switch
    #           event.EventPortAdd,event.EventPortDelete, event.EventPortModify, # port
    #           event.EventLinkAdd, event.EventLinkDelete,# link
    #           event.EventHostAdd] # host
    events = [event.EventSwitchEnter,event.EventSwitchLeave]
    @set_ev_cls(events)
    def update_topology_handler(self, ev):
        print("update_topology_handler")
        dp = ev.switch.dp
        self._update_topology()
        self.pre_path_table = copy.deepcopy(self.path_table)
        self.path_table = self._get_paths()
        self.differ_path_table = self._get_differ_path_table()
        if self.differ_path_table :
            print("differ_path_table")
            self.install_flow(self.differ_path_table,dp)

    def install_flow(self,path_table,dp):
        self.PRIORITY += 1
        for path in path_table:#path:[1,2,3,5]
            num = len(path)
            if num == 2:
                pass
            else:
                label_str = ''
                for i in range(num):
                    label_str += str(path[i])
                mpls_label = int(label_str)
                # print(mpls_label)
                mpls_tc = 5
                mpls_bos = 1
                for i in range(num):
                    if i == 0 or i == num - 1:
                        pass
                    else:
                        # print("dpid:",path[i])
                        datapath = dp
                        # print(datapath)
                        ofproto = datapath.ofproto
                        parser = datapath.ofproto_parser
                        match = parser.OFPMatch(mpls_label=mpls_label)

                        # match = parser.OFPMatch(in_port=2, ipv4_src="0.0.0.0")

                        # self.switches_mac_to_port = dict()
                        # self.hosts_mac_to_port = dict()
                        # self.links_dpid_to_port = dict()
                        # table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
                        if (path[i],path[i+1]) in self.links_dpid_to_port.keys():
                            # print(path[i],path[i+1])
                            port_tuple = self.links_dpid_to_port[(path[i],path[i+1])]
                            # print(port_tuple)
                            actions = [parser.OFPActionOutput(port_tuple[0])]
                            # def add_flow(self, datapath, priority, match, actions, buffer_id=None):
                            # self.add_flow(datapath, 100, 1000, self.PRIORITY, match, actions)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def switch_features_handler(self, ev):
        print('switch_features_handler')
        msg = ev.msg
        # self.logger.info('OFPSwitchFeatures received: '
        #               'datapath_id=0x%016x n_buffers=%d '
        #               'n_tables=%d auxiliary_id=%d '
        #               'capabilities=0x%08x',
        #               msg.datapath_id, msg.n_buffers, msg.n_tables,
        #               msg.auxiliary_id, msg.capabilities)
        datapath = msg.datapath
        self.id_to_dp[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath,0, 0, 0, match, actions)

    def add_flow(self, datapath, idle_timeout, hard_timeout, priority, match, actions, buffer_id=None):

        '''
        OFPFlowMod
        datapath, cookie=0, cookie_mask=0, table_id=0,
                 command=ofproto.OFPFC_ADD,
                 idle_timeout=0, hard_timeout=0,
                 priority=ofproto.OFP_DEFAULT_PRIORITY,
                 buffer_id=ofproto.OFP_NO_BUFFER,
                 out_port=0, out_group=0, flags=0,
                 match=None,
                 instructions=[]
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if hard_timeout == 1000:
            print("install flow hard_time")

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            # OFPFlowMod default command=ofproto.OFPFC_ADD
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        print("send_msg")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # print("_packet_in_handler")
        if ev.msg.msg_len < ev.msg.total_len:
            pass
            # self.logger.debug("packet truncated: only %s of %s bytes",
            #                   ev.msg.msg_len, ev.msg.total_len)
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
        dpid = datapath.id
        if dst in["00:00:00:00:00:01","00:00:00:00:00:02"]:
            print("!!!src:",src)
            print("!!!!dst:",dst)
            print(' eth.ethertype:0x%08x' % eth.ethertype)
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in dpid:%s src:%s dst:%s in_port:%s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 100,100, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 100, 100, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


