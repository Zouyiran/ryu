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
from path_calculator import PathCalculator
from flow_collector import FlowCollector
from flow_classifier import FlowClassifier

class LowLatencyApp(app_manager.RyuApp):
    '''
    reduce latency app

    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'network_monitor': NetworkMonitor,
        'flow_collector':FlowCollector
    }

    def __init__(self, *args, **kwargs):
        super(LowLatencyApp, self).__init__(*args, **kwargs)
        self.commandSender = CommandSender()
        self.network_monitor = kwargs['network_monitor']
        self.pathCalculator = PathCalculator()
        self.flow_collector = kwargs['flow_collector']
        self.flowClassifier = FlowClassifier()

        self.mpls_to_path = dict()
        self.LABEL = 0
        self.LABEL_BE_USED = set()
        self.LABEL_RECYCLE = set()

        self.DISCOVER_PERIOD = 3
        self.COLLECTOR_PERIOD = 5

        self.network_monitor_thread = hub.spawn(self._monitor)
        # self.flow_collector_thread = hub.spawn(self._collector)

    def _monitor(self):
        while True:
            hub.sleep(self.DISCOVER_PERIOD)
            self.network_monitor.pre_adjacency_matrix = copy.deepcopy(self.network_monitor.adjacency_matrix)
            self.network_monitor.update_topology()
            if self.network_monitor.pre_adjacency_matrix != self.network_monitor.adjacency_matrix:
                self.logger.info('***********network_aware thread: adjacency_matrix CHANGED***********')
                self.pathCalculator.pre_path_table = copy.deepcopy(self.pathCalculator.pre_path_table)
                self.pathCalculator.path_table = self.pathCalculator.get_path_table(
                                                    self.network_monitor.adjacency_matrix,
                                                    self.network_monitor.dpids_to_access_port)
                if self.pathCalculator.pre_path_table != self.pathCalculator.path_table:
                    self.logger.info('***********network_aware thread: path_table CHANGED***********')
                    self.pre_setup_flows(self.pathCalculator.pre_path_table,
                                        self.pathCalculator.path_table)
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


    # delete old mpls_path, add new mpls_path
    def pre_setup_flows(self,pre_path_table, path_table):
        '''
        mpls path pre-setup mechanism
        :param pre_path_table:
        :param path_table:
        :return:
        '''
        print("...................pre-install flow..................")
        if len(pre_path_table) == 0 and len(path_table) != 0: # initial
            print("...................initial flows..................")
            self.LABEL = 0
            self.LABEL_BE_USED.clear()
            self.LABEL_RECYCLE.clear()
            for path_pair in path_table.keys():
                paths = path_table[path_pair]
                path_num = len(paths)
                if path_num > 0:
                    for path in paths:
                        n = len(path)
                        if n > 2:
                            self.mpls_to_path[self.LABEL] = path
                            self.LABEL_BE_USED.add(self.LABEL) # record its mpls label
                            self.__add_flow(path,self.LABEL)
                            self.LABEL += 1
        else: # network change
            print("...................network changed flows..................")
            delete_path_table = dict()
            for dpid_pair in self.pathCalculator.pre_path_table:
                if dpid_pair not in self.pathCalculator.path_table:
                    delete_path_table[dpid_pair] = self.pathCalculator.pre_path_table[dpid_pair]
                elif self.pathCalculator.pre_path_table[dpid_pair] != self.pathCalculator.path_table[dpid_pair]:
                    delete_path_table[dpid_pair] = list()
                    for each_path in self.pathCalculator.pre_path_table[dpid_pair]:
                        if each_path not in self.pathCalculator.path_table[dpid_pair]:
                            delete_path_table[dpid_pair].append(each_path)
            for dpid_pair in delete_path_table:
                paths = delete_path_table[dpid_pair]
                path_num = len(paths)
                if path_num > 0:
                    for path in paths:
                        n = len(path)
                        if n > 2:
                            for label in self.mpls_to_path:
                                if self.mpls_to_path[label] == path:
                                    self.LABEL_BE_USED.remove(label)
                                    self.LABEL_RECYCLE.add(label)
                                    del self.mpls_to_path[label]
                                    self.__delete_flow(path,label)
                                    break
            add_path_table = dict()
            for dpid_pair in self.pathCalculator.path_table:
                if dpid_pair not in self.pathCalculator.pre_path_table:
                    add_path_table[dpid_pair] = self.pathCalculator.path_table[dpid_pair]
                elif self.pathCalculator.pre_path_table[dpid_pair] != self.pathCalculator.path_table[dpid_pair]:
                    add_path_table[dpid_pair] = list()
                    for each_path in self.pathCalculator.path_table[dpid_pair]:
                        if each_path not in self.pathCalculator.pre_path_table[dpid_pair]:
                            add_path_table[dpid_pair].append(each_path)
            for dpid_pair in add_path_table:
                paths = add_path_table[dpid_pair]
                path_num = len(paths)
                if path_num > 0:
                    for path in paths:
                        n = len(path)
                        if n > 2:
                            if self.LABEL_RECYCLE:
                                label = self.LABEL_RECYCLE.pop()
                                self.mpls_to_path[label] = path
                                self.LABEL_BE_USED.add(label)
                                self.__add_flow(path,label)
                            else:
                                self.mpls_to_path[self.LABEL] = path
                                self.LABEL_BE_USED.add(self.LABEL)
                                self.__add_flow(path,self.LABEL)
                                self.LABEL += 1
    def __delete_flow(self, path, label):
        n = len(path)
        if n >2:
            for i in range(1,n-1):
                dpid = path[i]
                priority = OFP_DEFAULT_PRIORITY # 32768 or 0x8000
                match = {
                        "dl_type":ether_types.ETH_TYPE_MPLS,
                        "mpls_label":label,
                        }
                self.commandSender.delete_flow_rest(dpid, priority, match)
    def __add_flow(self, path, label):
        n = len(path)
        if n >2:
            for i in range(1,n-1):
                dpid = path[i]
                priority = OFP_DEFAULT_PRIORITY # 32768 or 0x8000
                in_port = self.network_monitor.links_dpid_to_port[(path[i-1],path[i])][1]
                out_port = self.network_monitor.links_dpid_to_port[(path[i],path[i+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_MPLS,
                        "in_port":in_port,
                        "mpls_label":label,
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
                self.commandSender.add_flow_rest_1(dpid, priority, match, actions)


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
                traffic = None
                src_dpid = src_sw[0]
                dst_dpid = dst_sw[0]
                src_in_port = src_sw[1]
                dst_out_port = dst_sw[1]

                icmp_pkt = pkt.get_protocol(icmp.icmp)
                tcp_pkt = pkt.get_protocol(tcp.tcp)

                # for tcp: NOT use mpls
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
                            self.commandSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, 100)
                        else:
                            self.commandSender.add_flow_rest_1(dpid, priority, match, actions, 100)
                            data = msg.data
                            self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                    else:
                        print("src_dpid != dst_dpid")
                        if dpid == src_dpid:
                            traffic = self.pathCalculator.get_traffic(src_dpid,dst_dpid)
                        if traffic: # end-to-end reachable
                            self.install_flow_tcp(traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp)
                            data = msg.data
                            out_port = self.network_monitor.links_dpid_to_port[(traffic[0],traffic[1])][0]
                            self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return

                # for icmp: use mpls
                if isinstance(icmp_pkt,icmp.icmp):
                    print("----icmp-------")
                    print("dpid:",dpid)
                    eth = pkt.get_protocols(ethernet.ethernet)[0]
                    src_mac = eth.src
                    dst_mac = eth.dst
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
                            traffic = self.pathCalculator.get_traffic(src_dpid, dst_dpid)
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
        for label in self.mpls_to_path.keys():
            if self.mpls_to_path[label] == traffic:
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