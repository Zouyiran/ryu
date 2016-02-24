#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types, tcp
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

    } # 'stplib': stplib.Stp

    def __init__(self, *args, **kwargs):
        super(ReactiveApp, self).__init__(*args, **kwargs)
        self.path_finder = kwargs['PathFinder']
        # self.stp = kwargs['stplib']
        self.flowSender = FlowSender()

        self.dpid_ip_to_port = dict()
        self.access_table = dict()
        self.traffic = None
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #stplib.EventPacketIn
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

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        if isinstance(arp_pkt, arp.arp): # arp request and arp reply
            print("------arp----------")
            print("dpid:",datapath.id)
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

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if isinstance(ip_pkt,ipv4.ipv4): # ipv4
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if isinstance(icmp_pkt,icmp.icmp):
                print('-------icmp---------')
                print("src_ip:",src_ip)
                print("dst_ip:",dst_ip)
                src_sw = self._get_host_location(src_ip)
                dst_sw = self._get_host_location(dst_ip)
                if src_sw and dst_sw:
                    src_dpid = src_sw[0]
                    print("src_dpid:",src_dpid)
                    dst_dpid = dst_sw[0]
                    print("dst_dpid:",dst_dpid)
                    src_in_port = src_sw[1]
                    dst_out_port = dst_sw[1]
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
                        print("src_dpid != dst_dpid")
                        if dpid == src_dpid:
                            self.traffic = self.get_traffic(src_dpid,dst_dpid)
                        if self.traffic: # end-to-end reachable
                            self.install_flow(self.traffic,dst_ip,src_in_port,dst_out_port)
                            data = msg.data
                            out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
                            self.flowSender.packet_out(datapath, in_port, out_port, data)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def packet_in_handler(self, ev):
    #     msg = ev.msg
    #     buffer_id = msg.buffer_id
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     dpid = datapath.id
    #     in_port = msg.match['in_port']
    #
    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         return
    #
    #     # tcp_pkt = pkt.get_protocol(tcp.tcp)
    #     # if isinstance(tcp_pkt,tcp.tcp):
    #     #     print("--------tcp-------------")
    #     #     src_tcp = tcp_pkt.src_port
    #     #     dst_tcp = tcp_pkt.dst_port
    #     #     ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #     #     if isinstance(ip_pkt,ipv4.ipv4):
    #     #         src_ip = ip_pkt.src
    #     #         dst_ip = ip_pkt.dst
    #     #         src_sw = self._get_host_location(src_ip)
    #     #         dst_sw = self._get_host_location(dst_ip)
    #     #         if src_sw and dst_sw:
    #     #             src_dpid = src_sw[0]
    #     #             dst_dpid = dst_sw[0]
    #     #             src_in_port = src_sw[1]
    #     #             dst_out_port = dst_sw[1]
    #     #             if src_dpid == dst_dpid and src_dpid == dpid:
    #     #                 print("src_dpid == dst_dpid")
    #     #                 priority = OFP_DEFAULT_PRIORITY
    #     #                 match = {
    #     #                     "dl_type":ether_types.ETH_TYPE_IP,
    #     #                     "in_port":in_port,
    #     #                     "nw_src:":src_ip,
    #     #                     "nw_dst":dst_ip,
    #     #                     "tp_src":src_tcp,
    #     #                     "tp_dst":dst_tcp
    #     #                         }
    #     #                 actions = [{"type":"OUTPUT","port":dst_out_port}]
    #     #                 if buffer_id != ofproto.OFP_NO_BUFFER:
    #     #                     self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
    #     #                 else:
    #     #                     self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
    #     #                     data = msg.data
    #     #                     self.flowSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
    #     #             else:
    #     #                 print("src_dpid != dst_dpid")
    #     #                 if dpid == src_dpid:
    #     #                     self.traffic = self.get_traffic(src_dpid,dst_dpid)
    #     #                 if self.traffic: # end-to-end reachable
    #     #                     self.install_flow_2(self.traffic,src_ip, dst_ip,src_in_port,dst_out_port,src_tcp, dst_tcp)
    #     #                     data = msg.data
    #     #                     out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
    #     #                     self.flowSender.packet_out(datapath, in_port, out_port, data)
    #     #     return
    #
    #     ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #     if isinstance(ip_pkt,ipv4.ipv4): # ipv4
    #         src_ip = ip_pkt.src
    #         dst_ip = ip_pkt.dst
    #         icmp_pkt = pkt.get_protocol(icmp.icmp)
    #         if isinstance(icmp_pkt,icmp.icmp):
    #             print('-------icmp---------')
    #             print("src_ip:",src_ip)
    #             print("dst_ip:",dst_ip)
    #             src_sw = self._get_host_location(src_ip)
    #             dst_sw = self._get_host_location(dst_ip)
    #             if src_sw and dst_sw:
    #                 src_dpid = src_sw[0]
    #                 print("src_dpid:",src_dpid)
    #                 dst_dpid = dst_sw[0]
    #                 print("dst_dpid:",dst_dpid)
    #                 src_in_port = src_sw[1]
    #                 dst_out_port = dst_sw[1]
    #                 if src_dpid == dst_dpid and src_dpid == dpid:
    #                     print("src_dpid == dst_dpid")
    #                     priority = OFP_DEFAULT_PRIORITY
    #                     match = {
    #                             "dl_type":ether_types.ETH_TYPE_IP,
    #                             "in_port":in_port,
    #                             "nw_dst":dst_ip,
    #                             }
    #                     actions = [{"type":"OUTPUT","port":dst_out_port}]
    #                     if buffer_id != ofproto.OFP_NO_BUFFER:
    #                         self.flowSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id)
    #                     else:
    #                         self.flowSender.add_flow_rest_1(dpid, priority, match, actions)
    #                         data = msg.data
    #                         self.flowSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
    #                 else:
    #                     print("src_dpid != dst_dpid")
    #                     if dpid == src_dpid:
    #                         self.traffic = self.get_traffic(src_dpid,dst_dpid)
    #                     if self.traffic: # end-to-end reachable
    #                         self.install_flow(self.traffic,dst_ip,src_in_port,dst_out_port)
    #                         data = msg.data
    #                         out_port = self.path_finder.links_dpid_to_port[(self.traffic[0],self.traffic[1])][0]
    #                         self.flowSender.packet_out(datapath, in_port, out_port, data)
    #         return

    # @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    # def _topology_change_handler(self, ev):
    #     dp = ev.dp
    #     dpid_str = dpid_lib.dpid_to_str(dp.id)
    #     msg = 'Receive topology change event. Flush MAC table.'
    #     self.logger.debug("[dpid=%s] %s", dpid_str, msg)
    #
    #     if dp.id in self.mac_to_port:
    #         self.delete_flow(dp)
    #         del self.mac_to_port[dp.id]
    #
    # def delete_flow(self, datapath):
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #
    #     for dst in self.mac_to_port[datapath.id].keys():
    #         match = parser.OFPMatch(eth_dst=dst)
    #         mod = parser.OFPFlowMod(
    #             datapath, command=ofproto.OFPFC_DELETE,
    #             out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
    #             priority=1, match=match)
    #         datapath.send_msg(mod)
    #
    # @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    # def _port_state_change_handler(self, ev):
    #     dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
    #     of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
    #                 stplib.PORT_STATE_BLOCK: 'BLOCK',
    #                 stplib.PORT_STATE_LISTEN: 'LISTEN',
    #                 stplib.PORT_STATE_LEARN: 'LEARN',
    #                 stplib.PORT_STATE_FORWARD: 'FORWARD'}
    #     self.logger.debug("[dpid=%s][port=%d] state=%s",
    #                       dpid_str, ev.port_no, of_state[ev.port_state])


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

    def install_flow_2(self, traffic, src_ip, dst_ip, src_in_port, dst_out_port,src_tcp, dst_tcp):
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
                    "nw_src:":src_ip,
                    "nw_dst":dst_ip,
                    "tp_src":src_tcp,
                    "tp_dst":dst_tcp
                    }
            actions = [{"type":"OUTPUT","port":out_port}]
            self.flowSender.add_flow_rest_1(dpid, priority, match, actions)