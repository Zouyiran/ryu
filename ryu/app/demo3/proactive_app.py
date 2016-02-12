#!/usr/bin/env python
# -*- coding: utf-8 -*-


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.topology.api import get_all_switch, get_all_link

from flow_dispatcher import FlowDispatcher
from path_finder import PathFinder

class ProactiveApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "PathFinder": PathFinder
    }

    def __init__(self, *args, **kwargs):
        super(ProactiveApp, self).__init__(*args, **kwargs)
        self.path_finder = kwargs["PathFinder"]
        self.flowDispatcher = FlowDispatcher()

        self.dpid_to_dp = self.path_finder.dpid_to_dp
        self.path_table = self.path_finder.path_table
        self.dpids = self.path_finder.dpids

        self.dpid_ip_to_port = dict()


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler_stp(self, ev):
        msg = ev.msg
        buffer_id = msg.buffer_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp): # arp request and arp reply
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            self.dpid_ip_to_port.setdefault(dpid,{})
            self.dpid_ip_to_port[dpid][arp_src_ip] = in_port # record it!
            if arp_dst_ip in self.dpid_ip_to_port[dpid]:
                out_port = self.dpid_ip_to_port[dpid][arp_dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD
            data = msg.data
            self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)
        if isinstance(ip_pkt,ipv4.ipv4): # ipv4
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            self.dpid_ip_to_port.setdefault(dpid,{})
            self.dpid_ip_to_port[dpid][src_ip] = in_port # record it!
            if dst_ip in self.dpid_ip_to_port[dpid]:
                out_port = self.dpid_ip_to_port[dpid][dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD
            data = msg.data
            self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)














