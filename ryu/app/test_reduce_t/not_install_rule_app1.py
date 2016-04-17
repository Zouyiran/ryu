#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy

from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types, mpls, tcp, udp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY

from command_sender import CommandSender
from network_monitor import NetworkMonitor
from route_calculator import RouteCalculator
from flow_collector import FlowCollector
from flow_classifier import FlowClassifier
from path_pre_install import PathPreInstall


'''
---For 2 chapter----
when packet_in then
packet_out ONLY!
comparison for not_install_rule_app1

----test----
Linear topology
iperfTCP

'''

class HLApp(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'network_monitor': NetworkMonitor,
        'flow_collector':FlowCollector
    }

    def __init__(self, *args, **kwargs):
        super(HLApp, self).__init__(*args, **kwargs)
        self.network_monitor = kwargs['network_monitor'] # context
        self.flow_collector = kwargs['flow_collector'] #context

        self.commandSender = CommandSender.get_instance() # util
        self.routeCalculator = RouteCalculator.get_instance() # util

        self.flowClassifier = FlowClassifier() # mechanism
        self.pathPreInstall = PathPreInstall() # mechanism

        self.DISCOVER_PERIOD = 3
        self.COLLECTOR_PERIOD = 5
        self.FLOW_COUNT = 1

        self.network_monitor_thread = hub.spawn(self._monitor)

    # context
    def _monitor(self):
        while True:
            hub.sleep(self.DISCOVER_PERIOD)
            self.network_monitor.pre_adjacency_matrix = copy.deepcopy(self.network_monitor.adjacency_matrix)
            self.network_monitor.update_topology()
            if self.network_monitor.pre_adjacency_matrix != self.network_monitor.adjacency_matrix:
                self.logger.info('***********adjacency_matrix CHANGED***********')
                self.routeCalculator.pre_path_table = copy.deepcopy(self.routeCalculator.path_table)
                self.routeCalculator.path_table = self.routeCalculator.get_path_table(
                                                    self.network_monitor.adjacency_matrix,
                                                    self.network_monitor.dpids_to_access_port)
                self.routeCalculator.pre_route_table = copy.deepcopy(self.routeCalculator.route_table)
                self.routeCalculator.route_table = self.routeCalculator.get_route_table(
                                                    self.network_monitor.adjacency_matrix,
                                                    self.network_monitor.dpids_to_access_port)
                if self.routeCalculator.pre_path_table != self.routeCalculator.path_table:
                    self.logger.info('------path_table CHANGED-------')

    # install table-miss flow entry for each switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # add miss entry
        self.commandSender.add_flow(datapath, 0, match, actions)


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
        if isinstance(arp_pkt, arp.arp): #  arp request and reply
            print("----arp-------")
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            self.network_monitor.dpid_ip_to_port.setdefault(dpid,{})
            self.network_monitor.dpid_ip_to_port[dpid][arp_src_ip] = in_port
            if arp_dst_ip in self.network_monitor.dpid_ip_to_port[dpid]:
                out_port = self.network_monitor.dpid_ip_to_port[dpid][arp_dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD
            data = msg.data
            self.commandSender.packet_out(datapath, in_port, out_port, data)
            self.__register_access_info(dpid, arp_src_ip, in_port)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if isinstance(ipv4_pkt,ipv4.ipv4):
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            src_sw = self.__get_host_location(src_ip)
            dst_sw = self.__get_host_location(dst_ip)
            if src_sw and dst_sw:# end-to-end connection
                print('--------------end-to-end connection--------------')
                src_dpid = src_sw[0]
                dst_dpid = dst_sw[0]
                src_in_port = src_sw[1]
                dst_out_port = dst_sw[1]

                icmp_pkt = pkt.get_protocol(icmp.icmp)
                tcp_pkt = pkt.get_protocol(tcp.tcp)

                if isinstance(icmp_pkt,icmp.icmp):
                    print("----icmp-------")
                    if src_dpid == dst_dpid:
                        print("src_dpid == dst_dpid")
                        data = msg.data
                        self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                    else:
                        print("src_dpid != dst_dpid",src_dpid,dst_dpid)
                        if dpid == src_dpid:
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid)
                            out_port = self.network_monitor.links_dpid_to_port[(route[0],route[1])][0]
                        elif dpid == dst_dpid:
                            out_port = dst_out_port
                        else:
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid)
                            index = 0
                            for i in range(len(route)):
                                if route[i] == dpid:
                                    index = i
                                    break
                            out_port = self.network_monitor.links_dpid_to_port[(route[index],route[index+1])][0]
                        data = msg.data
                        self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return

                if isinstance(tcp_pkt,tcp.tcp):
                    print("------tcp-----------")
                    if src_dpid == dst_dpid:
                        print("src_dpid == dst_dpid")
                        data = msg.data
                        self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                    else:
                        print("src_dpid != dst_dpid")
                        if dpid == src_dpid:
                            print('dpid:',dpid)
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid)
                            out_port = self.network_monitor.links_dpid_to_port[(route[0],route[1])][0]
                            print('out_port:',out_port)
                        elif dpid == dst_dpid:
                            print('dpid:',dpid)
                            out_port = dst_out_port
                            print('out_port:',out_port)
                        else:
                            print('dpid:',dpid)
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid)
                            index = 0
                            for i in range(len(route)):
                                if route[i] == dpid:
                                    index = i
                                    break
                            out_port = self.network_monitor.links_dpid_to_port[(route[index],route[index+1])][0]
                            print('out_port:',out_port)
                        data = msg.data
                        self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return

    def __add_last(self, dpid, out_port, label):
        match = {
                "dl_type":ether_types.ETH_TYPE_MPLS,
                "mpls_label":label,
                }
        actions = [{"type":"OUTPUT","port":out_port}]
        self.commandSender.add_flow_rest_1(dpid, OFP_DEFAULT_PRIORITY, match, actions)

    def _get_mpls_label(self,traffic):
        for label in self.pathPreInstall.mpls_to_path.keys():
            if self.pathPreInstall.mpls_to_path[label] == traffic:
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

    def __register_access_info(self, dpid, ip, port):
        if port in self.network_monitor.dpids_to_access_port[dpid]: # {1: [4], 2: [], 3: [], 4: [2, 3], 5: [2, 3], 6: [2, 3]}
            self.network_monitor.access_table[(dpid,port)] = ip

    def __get_host_location(self,host):
        for sw in self.network_monitor.access_table.keys():
            if self.network_monitor.access_table[sw] == host:
                return sw
        return None

    # 3 layer
    def install_flow(self, traffic, dst_ip, src_in_port, dst_out_port):
        n = len(traffic)
        for j in range(n):
            dpid = traffic[j]
            priority = OFP_DEFAULT_PRIORITY
            if j == 0:
                print("install flow on src_dpid:",dpid)
                in_port = src_in_port
                out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
            elif j == n - 1:
                print("install flow on dst_dpid:",dpid)
                in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = dst_out_port
            else:
                print("install flow on dpid:",dpid)
                in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
            match = {
                    "dl_type":ether_types.ETH_TYPE_IP,
                    "in_port":in_port,
                    "nw_dst":dst_ip,
                    }
            actions = [{"type":"OUTPUT","port":out_port}]
            self.commandSender.add_flow_rest_1(dpid, priority, match, actions, 300)

    #4 layer
    def install_flow_tcp(self, traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp):
            n = len(traffic)
            for j in range(n):
                dpid = traffic[j]
                priority = OFP_DEFAULT_PRIORITY
                if j == 0:
                    print("install flow on src_dpid:",dpid)
                    in_port = src_in_port
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                elif j == n - 1:
                    print("install flow on dst_dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = dst_out_port
                else:
                    print("install flow on dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
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
                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, 100)

    #4 layer
    def install_flow_udp(self, traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp):
            n = len(traffic)
            for j in range(n):
                dpid = traffic[j]
                priority = OFP_DEFAULT_PRIORITY
                if j == 0:
                    print("install flow on src_dpid:",dpid)
                    in_port = src_in_port
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                elif j == n - 1:
                    print("install flow on dst_dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = dst_out_port
                else:
                    print("install flow on dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "nw_proto":6,
                        "in_port":in_port,
                        "nw_src":src_ip,
                        "nw_dst":dst_ip,
                        "up_src":src_tcp,
                        "up_dst":dst_tcp
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, 100)