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
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu import utils
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_all_switch, get_link,get_all_link,get_all_host,get_host

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

        self.path_table = dict()

        # self.discover_thread = hub.spawn(self.discover_topology)

        self.SLEEP_PERIOD = 1 #seconds

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
        self.switches_mac_to_port = self._get_switches_mac_to_port(switch_list)
        # for switch in self.switch_ports_table.keys():
        #     print("dpid:",switch)
        #     for mac in self.switch_ports_table[switch].keys():
        #         print("switch_mac:",mac,'->',"switch_port:",self.switch_ports_table[switch][mac])

        host_list = get_all_host(self) # return a list[ryu.topology.switches.Host]
        self.hosts_mac_to_port = self._get_hosts_mac_to_port(host_list)
        # for dpid in self.host_port_to_mac.keys():
        #     print("dpid:",dpid)
        #     for mac in self.host_port_to_mac[dpid].keys():
        #         print("host_port:",mac,'->',"switch_port:",self.host_port_to_mac[dpid][mac])

        link_dict = get_all_link(self) # return ryu.topology.switches.LinkState{Link class -> timestamp}
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
        print("link_dict:",len(link_dict))
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
        if self.switches and self.links:
            g = nx.Graph()
            g.add_nodes_from(self.switches)
            for i in self.adjacency_matrix.keys():
                for j in self.adjacency_matrix[i].keys():
                    if self.adjacency_matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
                    else:
                        continue
            all_shortest_paths = dict() #{1:{1:[],2:[],3:[],...},2:{1:[],2:[],...},...}
            for i in g.nodes():
                all_shortest_paths[i] = dict()
                for j in g.nodes():
                    #  nx.all_shortest_paths() return a generator
                    all_shortest_paths[i][j] = [path for path in nx.all_shortest_paths(g,i,j) ] # [[],[],[],...]
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
    # --------------------------------------------------------------------------

    events = [event.EventSwitchEnter,event.EventSwitchLeave, # switch
              event.EventPortAdd,event.EventPortDelete, event.EventPortModify, # port
              event.EventLinkAdd, event.EventLinkDelete,# link
              event.EventHostAdd] # host
    # events = [event.EventSwitchEnter,event.EventSwitchLeave]
    @set_ev_cls(events)
    def update_topology_handler(self, ev):
        self._update_topology()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        # self.logger.info('OFPSwitchFeatures received: '
        #               'datapath_id=0x%016x n_buffers=%d '
        #               'n_tables=%d auxiliary_id=%d '
        #               'capabilities=0x%08x',
        #               msg.datapath_id, msg.n_buffers, msg.n_tables,
        #               msg.auxiliary_id, msg.capabilities)
        datapath = msg.datapath
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
            # OFPFlowMod default command=ofproto.OFPFC_ADD
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        msg:
        ['_TYPE', '__class__', '__delattr__', '__dict__', '__doc__',
        '__format__', '__getattribute__', '__hash__', '__init__',
        '__module__', '__new__', '__reduce__', '__reduce_ex__',
        '__repr__', '__setattr__', '__sizeof__', '__str__',
        '__subclasshook__', '__weakref__', '_base_attributes',
        '_class_prefixes', '_class_suffixes', '_decode_value',
        '_encode_value', '_get_decoder', '_get_default_decoder',
        '_get_default_encoder', '_get_encoder', '_get_type',
        '_is_class', '_restore_args', '_serialize_body',
        '_serialize_header', '_serialize_pre', 'buf',
        'buffer_id', 'cls_from_jsondict_key', 'cls_msg_type',
        'cookie', 'data', 'datapath', 'from_jsondict', 'match',
        'msg_len', 'msg_type', 'obj_from_jsondict', 'parser',
        'reason', 'serialize', 'set_buf', 'set_classes',
        'set_headers', 'set_xid', 'stringify_attrs',
        'table_id', 'to_jsondict', 'total_len', 'version', 'xid']
            print("msg_type:",msg.msg_type)

        ether_types:
        # ETH_TYPE_IP = 0x0800
        # ETH_TYPE_ARP = 0x0806
        # ETH_TYPE_8021Q = 0x8100
        # ETH_TYPE_IPV6 = 0x86dd
        # ETH_TYPE_SLOW = 0x8809
        # ETH_TYPE_MPLS = 0x8847
        # ETH_TYPE_8021AD = 0x88a8
        # ETH_TYPE_LLDP = 0x88cc
        # ETH_TYPE_8021AH = 0x88e7
        # ETH_TYPE_IEEE802_3 = 0x05dc
        # ETH_TYPE_CFM = 0x8902
        :param ev:
        :return:
        '''
        # if ev.msg.msg_len < ev.msg.total_len:
            # self.logger.info("packet truncated: only %s of %s bytes",
            #                   ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        # self.logger.info('OFPPacketIn received: '
        #           'buffer_id=%x total_len=%d reason=%s '
        #           'table_id=%d cookie=%d match=%s data=%s',
        #           msg.buffer_id, msg.total_len, reason,
        #           msg.table_id, msg.cookie, msg.match,
        #           utils.hex_array(msg.data))
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] # OFPMatch
        #if eth_dst is in host addr then pack with mpls

        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0] # return a list so list[0] to extract it
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            print("ether_types is ETH_TYPE_LLDP")
            return


