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

        self.switch_ports_table = dict()
        self.link_ports_table = dict()
        self.switches = list()
        self.links = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        self.path_table = dict()

        self.discover_thread = hub.spawn(self.discover_topology)

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

    def _update_topology(self):
        switch_list = get_all_switch(self) # return a list[ryu.topology.switches.Switch]
        self.switch_ports_table = self._get_switch_ports(switch_list)
        self.switches = self._get_switches(self.switch_ports_table) # dpid

        link_dict = get_all_link(self) # return ryu.topology.switches.LinkState{Link class -> timestamp}
        self.link_ports_table = self._get_link_ports(link_dict)
        self.links = self._get_links(self.link_ports_table)

        self.adjacency_matrix = self._get_adjacency_matrix(self.switches, self.links)

    # --------------------------------------------------------------------------
    def _get_switch_ports(self,switch_list):
        table = dict()
        for switch in switch_list:
            dpid = switch.dp.id
            print(dpid)
            table[dpid] = set() # dpid->port_num
            for port in switch.ports:
                 table[dpid].add(port.port_no)
            print(table[dpid])
        return table

    def _get_switches(self,switch_port_table):
        return switch_port_table.keys()

    def _get_link_ports(self,link_dict):
        table = dict()
        for link in link_dict.keys():
            src = link.src #ryu.topology.switches.Port
            dst = link.dst
            table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
        return table

    def _get_links(self,link_ports_table):
        return link_ports_table.keys()

    def _get_mac_to_port(self, link_dict):
        mac_to_port = dict()
        for link in link_dict.keys():
            for port in [link.src,link.dst]:
                dpid = port.dpid
                mac_to_port.setdefault(dpid, {})
                mac_to_port[dpid][port.hw_addr] = dpid.port_no
        return mac_to_port

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
            all_shortest_paths = dict()
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
        # print(ev)
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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, #  send to the controller
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


 # ['_TYPE', '__class__', '__delattr__', '__dict__', '__doc__',
 #  '__format__', '__getattribute__', '__hash__', '__init__',
 #  '__module__', '__new__', '__reduce__', '__reduce_ex__',
 #  '__repr__', '__setattr__', '__sizeof__', '__str__',
 #  '__subclasshook__', '__weakref__', '_base_attributes',
 #  '_class_prefixes', '_class_suffixes', '_decode_value',
 #  '_encode_value', '_get_decoder', '_get_default_decoder',
 #  '_get_default_encoder', '_get_encoder', '_get_type',
 #  '_is_class', '_restore_args', '_serialize_body',
 #  '_serialize_header', '_serialize_pre', 'buf',
 #  'buffer_id', 'cls_from_jsondict_key', 'cls_msg_type',
 #  'cookie', 'data', 'datapath', 'from_jsondict', 'match',
 #  'msg_len', 'msg_type', 'obj_from_jsondict', 'parser',
 #  'reason', 'serialize', 'set_buf', 'set_classes',
 #  'set_headers', 'set_xid', 'stringify_attrs',
 #  'table_id', 'to_jsondict', 'total_len', 'version', 'xid']
 #        print("msg_type:",msg.msg_type)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

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
        # arp_pkt = pkt.get_protocol(arp.arp)
        # ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        if src in self.MAC_LIST and dst in self.MAC_LIST:
            pass

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in -> dpid:%s src:%s dst:%s in_port:%s", dpid, src, dst, in_port)

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
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

