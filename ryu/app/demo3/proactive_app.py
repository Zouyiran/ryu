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
import  path_finder

class ProactiveApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "PathFinder": path_finder.PathFinder
    }

    def __init__(self, *args, **kwargs):
        super(ProactiveApp, self).__init__(*args, **kwargs)
        self.path_finder = kwargs["PathFinder"]
        self.flowDispatcher = FlowDispatcher()

        self.dpid_to_dp = self.path_finder.dpid_to_dp
        self.path_table = self.path_finder.path_table
        self.dpids = self.path_finder.dpids
        self.access_port = self.path_finder.dpids_to_access_port

        self.dpid_ip_to_port = dict()
        self.access_table = dict()



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
            self.register_access_info(dpid, arp_src_ip, in_port)

        if isinstance(ip_pkt,ipv4.ipv4): # ipv4
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            # self.dpid_ip_to_port.setdefault(dpid,{})
            # self.dpid_ip_to_port[dpid][src_ip] = in_port # record it!
            # if dst_ip in self.dpid_ip_to_port[dpid]:
            #     out_port = self.dpid_ip_to_port[dpid][dst_ip]
            # else:
            #     out_port = ofproto.OFPP_FLOOD
            # data = msg.data
            # self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if isinstance(icmp_pkt,icmp.icmp):
                if in_port in self.access_port[dpid]:
                    src_sw = self._get_host_location(src_ip)
                    dst_sw = self._get_host_location(dst_ip)
                    if src_sw and dst_sw:
                        src_dpid = src_sw[0]
                        dst_dpid = dst_sw[0]
                        src_in_port = src_sw[1]
                        dst_out_port = dst_sw[1]
                        if src_dpid == dst_dpid: # belongs to same dpid
                            print("src_dpid == dst_dpid:",src_dpid)
                            priority = OFP_DEFAULT_PRIORITY
                            if buffer_id != ofproto.OFP_NO_BUFFER:
                                print("buffer_id != ofproto.OFP_NO_BUFFER:")
                                match = {
                                        "dl_type":ether_types.ETH_TYPE_IP,
                                        "in_port":in_port,
                                        "nw_dst":dst_ip,
                                        }
                                actions = [{"type":"OUTPUT","port":dst_out_port}]
                                self.flowDispatcher.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
                            else:
                                print("buffer_id == ofproto.OFP_NO_BUFFER:")
                                match = {
                                        "dl_type":ether_types.ETH_TYPE_IP,
                                        "in_port":in_port,
                                        "nw_dst":dst_ip,
                                        }
                                actions = [{"type":"OUTPUT","port":dst_out_port}]
                                self.flowDispatcher.add_flow_rest_1(dpid, priority, match, actions)
                                data = msg.data
                                self.flowDispatcher.packet_out(datapath, in_port, dst_out_port, data)
                        else:
                            traffic = self.get_traffic(src_dpid,dst_dpid)
                            if traffic:
                                self.install_flow(traffic,src_in_port,dst_out_port)

    def register_access_info(self, dpid, ip, port):

        if port in self.access_port[dpid]:
            print("dpid:",dpid)
            print("ip:",ip)
            print("port:",port)
            self.access_table[(dpid,port)] = ip

    def _get_host_location(self,ip):
        for sw in self.access_table.keys():
            if self.access_table[sw] == ip:
                return sw
        return None
    def get_traffic(self,src_dpid, dst_dpid):
        traffic = []
        return traffic

    def install_flow(self,traffic,src_in_port, dst_out_port):
        pass












