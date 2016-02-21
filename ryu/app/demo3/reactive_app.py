#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY

from flow_sender import FlowSender
import  re_path_finder


class ReactiveApp(app_manager.RyuApp):
    '''
    on the Network Layer
    reactive app:
    when first data packet come in,
    packet_in to the controller,
    select one traffic,
    install flow along all the switches,
    and then packet out the data packet
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'PathFinder': re_path_finder.PathFinder,
    }

    def __init__(self, *args, **kwargs):
        super(ReactiveApp, self).__init__(*args, **kwargs)
        self.path_finder = kwargs['PathFinder']
        self.flowSender = FlowSender()

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
            self.flowSender.packet_out(datapath, in_port, out_port, data, None)
            self.register_access_info(dpid, arp_src_ip, in_port)

        if isinstance(ip_pkt,ipv4.ipv4): # ipv4
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if isinstance(icmp_pkt,icmp.icmp):
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
                        match = {
                                "dl_type":ether_types.ETH_TYPE_IP,
                                "in_port":in_port,
                                "nw_dst":dst_ip,
                                }
                        actions = [{"type":"OUTPUT","port":dst_out_port}]
                        if buffer_id != ofproto.OFP_NO_BUFFER:
                            self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
                        else:
                            self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
                            data = msg.data
                            self.flowSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                    else:
                        print("src_dpid != dst_dpid:",src_dpid)
                        traffic = self.get_traffic(src_dpid,dst_dpid)
                        if traffic:# reachable
                            self.install_flow_2(datapath, traffic,dst_ip,src_in_port,dst_out_port,buffer_id,msg)

    def register_access_info(self, dpid, ip, port):
        if port in self.path_finder.dpids_to_access_port[dpid]: # {1: [4], 2: [], 3: [], 4: [2, 3], 5: [2, 3], 6: [2, 3]}
            self.access_table[(dpid,port)] = ip

    def _get_host_location(self,ip):
        for sw in self.access_table.keys():
            if self.access_table[sw] == ip:
                return sw
        return None

    def get_traffic(self,src_dpid, dst_dpid):
        traffic = []
        all_traffic = self.path_finder.path_table[(src_dpid,dst_dpid)]
        if all_traffic:
            i = random.randint(0,len(all_traffic)-1)
            traffic = all_traffic[i]
        return traffic
    #datapath, traffic,dst_ip,src_in_port,dst_out_port,buffer_id,msg
    def install_flow_2(self,datapath, traffic, dst_ip, src_in_port, dst_out_port, buffer_id, msg):
        dpid = datapath.id
        ofproto = datapath.ofproto
        print("traffic:",traffic)
        if dpid == traffic[0]:
            print("install flow on src_dpid:",dpid)
            priority = OFP_DEFAULT_PRIORITY
            in_port = src_in_port
            match = {
                    "dl_type":ether_types.ETH_TYPE_IP,
                    "in_port":in_port,
                    "nw_dst":dst_ip,
                    }
            out_port = self.path_finder.links_dpid_to_port[(traffic[0],traffic[1])][0]
            actions = [{"type":"OUTPUT","port":out_port}]
        elif dpid == traffic[-1]:
            print("install flow on dst_dpid:",dpid)
            priority = OFP_DEFAULT_PRIORITY
            in_port = self.path_finder.links_dpid_to_port[(traffic[-2],traffic[-1])][1]
            match = {
                    "dl_type":ether_types.ETH_TYPE_IP,
                    "in_port":in_port,
                    "nw_dst":dst_ip,
                    }
            out_port = dst_out_port
            actions = [{"type":"OUTPUT","port":out_port}]
        else:
            print("install flow on dpid:",dpid)
            priority = OFP_DEFAULT_PRIORITY
            index = 0
            for each_dpid in traffic:
                index += 1
                if dpid == each_dpid:
                    break
            in_port = self.path_finder.links_dpid_to_port[(traffic[index-2],traffic[index-1])][1]
            match = {
                    "dl_type":ether_types.ETH_TYPE_IP,
                    "in_port":in_port,
                    "nw_dst":dst_ip,
                    }
            out_port = self.path_finder.links_dpid_to_port[(traffic[index-1],traffic[index])][0]
            actions = [{"type":"OUTPUT","port":out_port}]
        if buffer_id != ofproto.OFP_NO_BUFFER:
            self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
        else:
            self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
            data = msg.data
            self.flowSender.packet_out(datapath, in_port, out_port, data, buffer_id)

    def install_flow(self, traffic, dst_ip, src_in_port, dst_out_port, buffer_id, ofproto, msg):
        n = len(traffic)
        for i in range(n): # 0,1,.., n-1
            j = n - 1 - i # n-1,n-2,...,0
            dpid = traffic[j]
            if j == n - 1: # dst_dpid
                print("install flow on dpid:",dpid)
                priority = OFP_DEFAULT_PRIORITY
                in_port = self.path_finder.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "in_port":in_port,
                        "nw_dst":dst_ip,
                        }
                actions = [{"type":"OUTPUT","port":dst_out_port}]
                self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
            elif j == 0: # src_dpid
                print("install flow on dpid:",dpid)
                priority = OFP_DEFAULT_PRIORITY
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "in_port":src_in_port,
                        "nw_dst":dst_ip,
                        }
                out_port = self.path_finder.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                actions = [{"type":"OUTPUT","port":out_port}]
                if buffer_id != ofproto.OFP_NO_BUFFER:
                    self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
                else:
                    self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
                    data = msg.data
                    self.flowSender.packet_out(self.path_finder.dpid_to_dp[dpid], src_in_port, out_port, data, buffer_id)
            else:
                print("install flow on dpid:",dpid)
                priority = OFP_DEFAULT_PRIORITY
                in_port = self.path_finder.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = self.path_finder.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "in_port":in_port,
                        "nw_dst":dst_ip,
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
                self.flowSender.add_flow_rest_1(dpid, priority, match, actions)















