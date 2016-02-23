#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types, mpls, tcp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY

from flow_sender import FlowSender
from pro_path_finder import PathFinder


class SemiActiveApp(app_manager.RyuApp):
    '''
    on the Network Layer
    semi_active app

    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'PathFinder': PathFinder,
    }

    def __init__(self, *args, **kwargs):
        super(SemiActiveApp, self).__init__(*args, **kwargs)
        self.path_finder = kwargs['PathFinder']
        self.flowSender = FlowSender()

        self.dpid_ip_to_port = dict()
        self.access_table = dict()
        self.traffic = None


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        buffer_id = msg.buffer_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
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
            self.flowSender.packet_out(datapath, in_port, out_port, data)
            self.register_access_info(dpid, arp_src_ip, in_port)

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if isinstance(tcp_pkt, tcp.tcp): # reactive select a path and install flow
            pass

            ip_pkt = pkt.get_protocol(ipv4.ipv4)
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
                    else:
                        print("src_dpid != dst_dpid",src_dpid,dst_dpid)
                        if dpid == src_dpid:
                            self.traffic = self.traffic_generate(src_dpid,dst_dpid)
                        if self.traffic:
                            # NO need to mpls
                            if len(self.traffic) == 2:
                                self.install_flow(self.traffic,dst_ip,src_in_port,dst_out_port)
                                self.install_flow(self.traffic[::-1],src_ip,dst_out_port,src_in_port)
                                out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
                                data = msg.data
                                self.flowSender.packet_out(datapath, in_port, out_port, data)
                            # need to mpls
                            elif len(self.traffic) > 2:
                                print("traffic length:",len(self.traffic))
                                # pack mpls
                                if dpid == self.traffic[0]:
                                    print("pack mpls dpid == traffic[0]:",dpid)
                                    self.install_flow(self.traffic,dst_ip,src_in_port,dst_out_port)
                                    self.install_flow(self.traffic[::-1],src_ip,dst_out_port,src_in_port)
                                    out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
                                    label = self._get_mpls_label(self.traffic)
                                    pack = self.__add_mpls(pkt, label, src_mac, dst_mac)
                                    pack.serialize()
                                    data = pack.data
                                    self.flowSender.packet_out(datapath, in_port, out_port, data)
                                # unpack mpls
                                elif dpid == self.traffic[-1]:
                                    print("unpack mpls dpid == traffic[-1]:",dpid)
                                    out_port = dst_out_port
                                    pack = self.__remove_mpls(pkt, src_mac, dst_mac)
                                    pack.serialize()
                                    data = pack.data
                                    self.flowSender.packet_out(datapath, in_port, out_port, data)
                                else:
                                    print("not path[0] and not path[-1], so this is a BUG!!!")
                                return

    def _get_mpls_label(self,traffic):
        for label in self.path_finder.mpls_to_path.keys():
            if self.path_finder.mpls_to_path[label] == traffic:
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
        if port in self.path_finder.dpids_to_access_port[dpid]: # {1: [4], 2: [], 3: [], 4: [2, 3], 5: [2, 3], 6: [2, 3]}
            self.access_table[(dpid,port)] = ip

    def _get_host_location(self,host):
        for sw in self.access_table.keys():
            if self.access_table[sw] == host:
                return sw
        return None

    def traffic_generate(self,src_dpid, dst_dpid):
        traffic = []
        all_traffic = self.path_finder.path_table[(src_dpid,dst_dpid)]
        if all_traffic:
            i = random.randint(0,len(all_traffic)-1) # randomly select a path
            traffic = all_traffic[i]
        return traffic

    def install_flow(self, traffic, dst_ip, src_in_port, dst_out_port):
        n = len(traffic)
        for j in range(n):
            dpid = traffic[j]
            priority = OFP_DEFAULT_PRIORITY
            if j == 0:
                print("install flow on src_dpid:",dpid)
                in_port = src_in_port
                out_port = self.path_finder.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
            elif j == n - 1:
                print("install flow on dst_dpid:",dpid)
                in_port = self.path_finder.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = dst_out_port
            else:
                print("install flow on dpid:",dpid)
                in_port = self.path_finder.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = self.path_finder.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
            match = {
                    "dl_type":ether_types.ETH_TYPE_IP,
                    "in_port":in_port,
                    "nw_dst":dst_ip,
                    }
            actions = [{"type":"OUTPUT","port":out_port}]
            self.flowSender.add_flow_rest_1(dpid, priority, match, actions)