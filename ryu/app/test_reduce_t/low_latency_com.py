#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy

from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types, mpls, tcp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY

from command_sender import CommandSender
from network_monitor import NetworkMonitor
from route_calculator import RouteCalculator
from flow_collector import FlowCollector
from flow_classifier import FlowClassifier
from path_pre_install import PathPreInstall

class HLApp(app_manager.RyuApp):
    '''
    hybrid and low latency app

    '''
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

        self.network_monitor_thread = hub.spawn(self._monitor)
        # self.flow_collector_thread = hub.spawn(self._collector)

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
                if self.routeCalculator.pre_path_table != self.routeCalculator.path_table:
                    self.logger.info('------path_table CHANGED-------')
                    self.pathPreInstall.setup_mpls_path(self.routeCalculator.pre_path_table,
                                                        self.routeCalculator.path_table, self.network_monitor)
    # context
    def _collector(self):
        while True:
            hub.sleep(self.COLLECTOR_PERIOD)
            access_dpids = self.network_monitor.access_dpids
            if len(access_dpids) != 0:
                print("len(access_dpids):",len(access_dpids))
                for dpid in access_dpids:
                    self.flow_collector.dpid_to_flow.setdefault(dpid, {})
                    stats_flow = self.flow_collector.request_stats_flow(dpid)[str(dpid)]
                    self.flow_collector.dpid_to_flow[dpid] = self.flow_collector.parse_stats_flow(stats_flow)


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
                src_dpid = src_sw[0]
                dst_dpid = dst_sw[0]
                src_in_port = src_sw[1]
                dst_out_port = dst_sw[1]
                eth = pkt.get_protocols(ethernet.ethernet)[0]
                src_mac = eth.src
                dst_mac = eth.dst

                icmp_pkt = pkt.get_protocol(icmp.icmp)
                tcp_pkt = pkt.get_protocol(tcp.tcp)

                # for tcp: NOT use mpls
                if isinstance(tcp_pkt,tcp.tcp):
                    print("----tcp-------")
                    src_tcp = tcp_pkt.src_port
                    dst_tcp = tcp_pkt.dst_port
                    if dpid == src_dpid: # packet_in
                        if src_dpid == dst_dpid:
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
                                self.commandSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, 100)
                            else:
                                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, 100)
                                data = msg.data
                                self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                        else:
                            print("src_dpid != dst_dpid")
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid) # for follow-up packet
                            self.install_flow_tcp(route, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp)
                            data = msg.data
                            out_port = self.network_monitor.links_dpid_to_port[(route[0],route[1])][0]
                            self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return

                # for icmp: use mpls
                if isinstance(icmp_pkt,icmp.icmp):
                    print("----icmp-------")
                    print("dpid:",dpid)

                    if dpid == src_dpid: # from src packet_in
                        # NO need to mpls
                        if src_dpid == dst_dpid:
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
                                self.commandSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, 300)
                            else:
                                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, 300)
                                data = msg.data
                                self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                        else:
                            print("src_dpid != dst_dpid",src_dpid,dst_dpid)
                            traffic = self.routeCalculator.get_traffic(src_dpid, dst_dpid)
                            if traffic:
                                # NO need to mpls
                                if len(traffic) == 2:
                                    self.install_flow(traffic,dst_ip,src_in_port,dst_out_port)
                                    self.install_flow(traffic[::-1],src_ip,dst_out_port,src_in_port)
                                    out_port = self.network_monitor.links_dpid_to_port[(traffic[0],traffic[1])][0]
                                    data = msg.data
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                # need to mpls
                                elif len(traffic) > 2:
                                    print("traffic length:",len(traffic))
                                    print("pack mpls dpid on traffic[0]:",dpid)
                                    print(traffic)
                                    self.install_flow(traffic,dst_ip,src_in_port,dst_out_port)
                                    self.install_flow(traffic[::-1],src_ip,dst_out_port,src_in_port)
                                    out_port = self.network_monitor.links_dpid_to_port[(traffic[0],traffic[1])][0]
                                    label = self._get_mpls_label(traffic)
                                    pack = self.__add_mpls(pkt, label, src_mac, dst_mac)
                                    pack.serialize()
                                    data = pack.data
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                    elif dpid == dst_dpid:
                        print("unpack mpls dpid on traffic[-1]:",dpid)
                        out_port = dst_out_port
                        pack = self.__remove_mpls(pkt, src_mac, dst_mac)
                        pack.serialize()
                        data = pack.data
                        self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return
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