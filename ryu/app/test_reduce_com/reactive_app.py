#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random

import  re_path_finder
from ryu.app.test_reduce_t.command_sender import CommandSender
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types, tcp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY


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

    }# 'stplib': stplib.Stp

    def __init__(self, *args, **kwargs):
        super(ReactiveApp, self).__init__(*args, **kwargs)
        self.path_finder = kwargs['PathFinder']
        # self.stp = kwargs['stplib']
        self.flowSender = CommandSender()

        self.dpid_ip_to_port = dict()
        self.access_table = dict()
        self.traffic = None
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #stplib.EventPacketIn
    def packet_in_handler(self, ev):
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
        if isinstance(arp_pkt, arp.arp): # arp request and arp reply
            # print("------arp----------")
            # print("dpid:",datapath.id)
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            self.dpid_ip_to_port.setdefault(dpid,{})
            self.dpid_ip_to_port[dpid][arp_src_ip] = in_port
            if arp_dst_ip in self.dpid_ip_to_port[dpid]:
                out_port = self.dpid_ip_to_port[dpid][arp_dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD
            data = msg.data
            self.flowSender.packet_out(datapath, in_port, out_port, data)
            self.register_access_info(dpid, arp_src_ip, in_port)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if isinstance(ipv4_pkt,ipv4.ipv4):
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            src_sw = self._get_host_location(src_ip)
            dst_sw = self._get_host_location(dst_ip)
            if src_sw and dst_sw:# end-to-end connection
                src_dpid = src_sw[0]
                dst_dpid = dst_sw[0]
                src_in_port = src_sw[1]
                dst_out_port = dst_sw[1]

                icmp_pkt = pkt.get_protocol(icmp.icmp)
                tcp_pkt = pkt.get_protocol(tcp.tcp)

                if isinstance(tcp_pkt,tcp.tcp):
                    print("----tcp-------")
                    src_tcp = tcp_pkt.src_port
                    dst_tcp = tcp_pkt.dst_port
                    if src_dpid == dst_dpid and src_dpid == dpid:
                        print("src_dpid == dst_dpid")
                        priority = OFP_DEFAULT_PRIORITY
                        match = {
                            "dl_type":ether_types.ETH_TYPE_IP,
                            "nw_proto":6,
                            "in_port":in_port,
                            "nw_src":src_ip,
                            "nw_dst":dst_ip,
                            "tp_src":src_tcp,
                            "tp_dst":dst_tcp
                                }
                        actions = [{"type":"OUTPUT","port":dst_out_port}]
                        if buffer_id != ofproto.OFP_NO_BUFFER:
                            self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, 100)
                        else:
                            self.flowSender.add_flow_rest_1(dpid, priority, match, actions, 100)
                            data = msg.data
                            self.flowSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                    else:
                        print("src_dpid != dst_dpid")
                        if dpid == src_dpid:
                            self.traffic = self.get_traffic(src_dpid,dst_dpid)
                        if self.traffic: # end-to-end reachable
                            self.install_flow_tcp(self.traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp)
                            data = msg.data
                            out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
                            self.flowSender.packet_out(datapath, in_port, out_port, data)
                    return

                if isinstance(icmp_pkt,icmp.icmp):
                    print("----icmp-------")
                    if src_dpid == dst_dpid and src_dpid == dpid:
                        print("src_dpid == dst_dpid")
                        priority = OFP_DEFAULT_PRIORITY
                        match = {
                                "dl_type":ether_types.ETH_TYPE_IP,
                                "in_port":in_port,
                                "nw_src":src_ip,
                                "nw_dst":dst_ip,
                                }
                        actions = [{"type":"OUTPUT","port":dst_out_port}]
                        if buffer_id != ofproto.OFP_NO_BUFFER:
                            self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, 300)
                        else:
                            self.flowSender.add_flow_rest_1(dpid, priority, match, actions, 300)
                            data = msg.data
                            self.flowSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                    else:
                        print("src_dpid != dst_dpid")
                        if dpid == src_dpid:
                            self.traffic = self.get_traffic(src_dpid,dst_dpid)
                        if self.traffic: # end-to-end reachable
                            self.install_flow(self.traffic,dst_ip,src_in_port,dst_out_port)
                            # self.install_flow(self.traffic[::-1],src_ip,dst_out_port,src_in_port)
                            data = msg.data
                            out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
                            self.flowSender.packet_out(datapath, in_port, out_port, data)
                    return

    def register_access_info(self, dpid, ip, port):
        print(self.path_finder.dpids_to_access_port)
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
            self.flowSender.add_flow_rest_1(dpid, priority, match, actions, 300)

    def install_flow_tcp(self, traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp):
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
                    "nw_proto":6,
                    "in_port":in_port,
                    "nw_src":src_ip,
                    "nw_dst":dst_ip,
                    "tp_src":src_tcp,
                    "tp_dst":dst_tcp
                    }
            actions = [{"type":"OUTPUT","port":out_port}]
            self.flowSender.add_flow_rest_1(dpid, priority, match, actions, 100)