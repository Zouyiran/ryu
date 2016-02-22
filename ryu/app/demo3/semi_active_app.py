#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types, mpls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY

from flow_sender import FlowSender
from path_calculator import PathCalculator


class SemiActiveApp(app_manager.RyuApp):
    '''
    on the Network Layer
    semi_active app

    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'PathCalculator': PathCalculator,
    }

    def __init__(self, *args, **kwargs):
        super(SemiActiveApp, self).__init__(*args, **kwargs)
        self.path_calculator = kwargs['PathCalculator']
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
            # icmp_pkt = pkt.get_protocol(icmp.icmp)
            # if isinstance(icmp_pkt,icmp.icmp):
            src_sw = self._get_host_location(src_ip)
            dst_sw = self._get_host_location(dst_ip)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            src_mac = eth.src
            dst_mac = eth.dst
            if src_sw and dst_sw:
                src_dpid = src_sw[0]
                dst_dpid = dst_sw[0]
                src_in_port = src_sw[1]
                dst_out_port = dst_sw[1]
                # NO need to mpls
                if src_dpid == dst_dpid and src_dpid == dpid:
                    print("src_dpid == dst_dpid")
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
                else: # (src_dpid,dst_dpid) in self.path_calculator.path_table.keys():
                    print("src_dpid != dst_dpid",src_dpid,dst_dpid)
                    paths = self.path_calculator.path_table[(src_dpid,dst_dpid)]
                    path_num = len(paths)
                    if path_num == 0:
                        return # unreachable
                    print("paths:",paths)
                    traffic = self.flow_generate(src_dpid,dst_dpid)
                    print("traffic:",traffic)
                    # NO need to mpls
                    if len(traffic) == 2:
                        self.install_flow(traffic,dst_ip,src_in_port,dst_out_port)
                        self.install_flow(traffic[::-1],src_ip,dst_out_port,src_in_port)
                        out_port = self.path_calculator.links_dpid_to_port[(traffic[0],traffic[1])][0]
                        data = msg.data
                        self.flowSender.packet_out(datapath, in_port, out_port, data, buffer_id)
                    # need to mpls
                    elif len(traffic) > 2:
                        print("traffic length:",len(traffic))
                        # pack mpls
                        if dpid == traffic[0]:
                            print("dpid == traffic[0]:",dpid)
                            self.install_flow(traffic,dst_ip,src_in_port,dst_out_port)
                            self.install_flow(traffic[::-1],src_ip,dst_out_port,src_in_port)
                            out_port = self.path_calculator.links_dpid_to_port[(traffic[0],traffic[1])][0]
                            label = self._get_mpls_label(traffic)
                            pack = self.__add_mpls(pkt, label, src_mac, dst_mac)
                            pack.serialize()
                            data = pack.data
                            self.flowSender.packet_out(datapath, in_port, out_port, data, None)
                        # unpack mpls
                        elif dpid == traffic[-1]:
                            print("dpid == traffic[-1]:",dpid)
                            out_port = dst_out_port
                            pack = self.__remove_mpls(pkt, src_mac, dst_mac)
                            pack.serialize()
                            data = pack.data
                            self.flowSender.packet_out(datapath, in_port, out_port, data, None)
                        else:
                            print("not path[0] and not path[-1], so this is a BUG!!!")
                        return

    def _get_mpls_label(self,traffic):
        for label in self.path_calculator.mpls_to_path.keys():
            if self.path_calculator.mpls_to_path[label] == traffic:
                return label
        return None

    def __add_mpls(self,  pkt_old, label, src_mac, dst_mac):
        pkt_new = packet.Packet()
        mpls_proto = mpls.mpls(label=label) # label:20bit(0~1048576-1), exp(QoS):3bit, bsb:1bit, ttl:8bit
        pkt_new.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac,ethertype=ether_types.ETH_TYPE_MPLS))
        pkt_new.add_protocol(mpls_proto)
        for i in range(1,len(pkt_old)):#[ethernet, ipv4, tcp,..]
            pkt_new.add_protocol(pkt_old[i])
        return pkt_new

    def __remove_mpls(self,pkt_old, src_mac, dst_mac):
        pkt_new = packet.Packet()
        pkt_new.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac,ethertype=ether_types.ETH_TYPE_IP))
        for i in range(2,len(pkt_old)):#[ethernet, mpls, ipv4, tcp,..]
            pkt_new.add_protocol(pkt_old[i])
        return pkt_new

    def register_access_info(self, dpid, ip, port):
        if port in self.path_calculator.dpids_to_access_port[dpid]: # {1: [4], 2: [], 3: [], 4: [2, 3], 5: [2, 3], 6: [2, 3]}
            self.access_table[(dpid,port)] = ip

    def _get_host_location(self,host):
        for sw in self.access_table.keys():
            if self.access_table[sw] == host:
                return sw
        return None

    def flow_generate(self,src_dpid, dst_dpid):
        traffic = []
        all_traffic = self.path_calculator.path_table[(src_dpid,dst_dpid)]
        if all_traffic:
            i = random.randint(0,len(all_traffic)-1)
            traffic = all_traffic[i]
        return traffic


    # def install_flow(self, traffic, dst_ip, src_in_port, dst_out_port, buffer_id, ofproto, msg):
    #     n = len(traffic)
    #     for i in range(n): # 0,1,.., n-1
    #         j = n - 1 - i # n-1,n-2,...,0
    #         dpid = traffic[j]
    #         if j == n - 1: # dst_dpid
    #             print("install flow on dpid:",dpid)
    #             priority = OFP_DEFAULT_PRIORITY
    #             in_port = self.path_calculator.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
    #             match = {
    #                     "dl_type":ether_types.ETH_TYPE_IP,
    #                     "in_port":in_port,
    #                     "nw_dst":dst_ip,
    #                     }
    #             actions = [{"type":"OUTPUT","port":dst_out_port}]
    #             self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
    #         elif j == 0: # src_dpid
    #             print("install flow on dpid:",dpid)
    #             priority = OFP_DEFAULT_PRIORITY
    #             match = {
    #                     "dl_type":ether_types.ETH_TYPE_IP,
    #                     "in_port":src_in_port,
    #                     "nw_dst":dst_ip,
    #                     }
    #             out_port = self.path_calculator.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
    #             actions = [{"type":"OUTPUT","port":out_port}]
    #             if buffer_id != ofproto.OFP_NO_BUFFER:
    #                 self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
    #             else:
    #                 self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
    #                 data = msg.data
    #                 self.flowSender.packet_out(self.path_calculator.dpid_to_dp[dpid], src_in_port, out_port, data, buffer_id)
    #         else:
    #             print("install flow on dpid:",dpid)
    #             priority = OFP_DEFAULT_PRIORITY
    #             in_port = self.path_calculator.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
    #             out_port = self.path_calculator.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
    #             match = {
    #                     "dl_type":ether_types.ETH_TYPE_IP,
    #                     "in_port":in_port,
    #                     "nw_dst":dst_ip,
    #                     }
    #             actions = [{"type":"OUTPUT","port":out_port}]
    #             self.flowSender.add_flow_rest_1(dpid, priority, match, actions)

    # install both src->dst and dst->src
    def install_flow(self, traffic, dst_ip, src_in_port, dst_out_port):
        n = len(traffic)
        for j in range(n):
            dpid = traffic[j]
            priority = OFP_DEFAULT_PRIORITY
            if j == 0:
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "in_port":src_in_port,
                        "nw_dst":dst_ip,
                        }
                out_port = self.path_calculator.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                actions = [{"type":"OUTPUT","port":out_port}]
            elif j == n - 1:
                in_port = self.path_calculator.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "in_port":in_port,
                        "nw_dst":dst_ip,
                        }
                actions = [{"type":"OUTPUT","port":dst_out_port}]
            else:
                in_port = self.path_calculator.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = self.path_calculator.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "in_port":in_port,
                        "nw_dst":dst_ip,
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
            self.flowSender.add_flow_rest_1(dpid, priority, match, actions)