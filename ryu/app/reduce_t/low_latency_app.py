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
###reduce_t###
--> hybrid and low latency app
1) network_monitor_thread --> mpls path setup / topology update
2) flow_collector_thread --> flow classifier --> active pair / elephant flow
4) call commandSender and routeCalculator
3) packet in handler
----test----
data center topology
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

        self.DISCOVER_PERIOD = 5
        self.COLLECTOR_PERIOD = 5
        self.FLOW_COUNT = 1

        self.network_monitor_thread = hub.spawn(self._monitor)
        self.flow_collector_thread = hub.spawn(self._collector)
        # hub.spawn(self._flow_count)

        self.TCP_IDLE_TIME = 10
        self.ICMP_IDLE_TIME = 60

    def _flow_count(self):
        while True:
            hub.sleep(self.DISCOVER_PERIOD)
            total = 0
            for dpid in self.network_monitor.dpids:
                res = self.commandSender.get_aggr_flow(dpid).json()
                count = res[str(dpid)][0]['flow_count']
                count = int(count)
                total += count
            file = open('/home/zouyiran/bs/myself/ryu/ryu/app/reduce_t/flow_count.txt','a')
            file.write('flow_count:'+str(total)+'\n')
            file.close()

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
                    self.pathPreInstall.setup_mpls_path(self.routeCalculator.pre_path_table,
                                                        self.routeCalculator.path_table, self.network_monitor)

    def _collector(self):
        while True:
            hub.sleep(self.COLLECTOR_PERIOD)
            access_dpids = self.network_monitor.access_dpids
            if len(access_dpids) != 0:
                self.flow_collector.dpid_to_flow.clear()
                self.flowClassifier.active_sample.clear()
                for dpid in access_dpids:
                    self.flow_collector.dpid_to_flow.setdefault(dpid, [])
                    stats_flow = self.flow_collector.request_stats_flow(dpid)[str(dpid)]
                    self.flow_collector.dpid_to_flow[dpid] = self.flow_collector.parse_stats_flow(stats_flow)
            self.flowClassifier.active_sample = self.flowClassifier.create_sample(self.flow_collector.dpid_to_flow)
            file = open('/home/zouyiran/bs/myself/ryu/ryu/app/reduce_t/flow_classify.txt','a')
            file.write('\n'+'-------------------flow--classify-------------'+'\n')
            for i in self.flowClassifier.active_sample:
                file.write(str(i)+'\n')
                file.write(str(self.flowClassifier.active_sample[i])+'\n')
            file.close()

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
        if isinstance(arp_pkt, arp.arp):
            print("----arp-------")
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            self.network_monitor.dpid_ip_to_port.setdefault(dpid,{})
            self.network_monitor.dpid_ip_to_port[dpid][arp_src_ip] = in_port
            if arp_dst_ip in self.network_monitor.dpid_ip_to_port[dpid]:
                out_port = self.network_monitor.dpid_ip_to_port[dpid][arp_dst_ip]
                data = msg.data
                self.commandSender.packet_out(datapath, in_port, out_port, data)
            else:
                pre_dpid = None
                for pair in self.network_monitor.links_dpid_to_port.keys():
                    if self.network_monitor.links_dpid_to_port[pair][1] == in_port:
                        pre_dpid = pair[0]
                if pre_dpid:
                    tree = self.network_monitor.get_tree()
                    neighbor = tree.adj[dpid].keys()
                    for k in neighbor:
                        if k != pre_dpid:
                            out_port = self.network_monitor.links_dpid_to_port[(dpid, k)][0]
                            data = msg.data
                            self.commandSender.packet_out(datapath, in_port, out_port, data)
                    if dpid in self.network_monitor.dpids_to_access_port.keys():
                        access_ports = self.network_monitor.dpids_to_access_port[dpid]
                        if len(access_ports) > 0:
                            for out_port in access_ports:
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
                udp_pkt = pkt.get_protocol(udp.udp)

                if isinstance(icmp_pkt,icmp.icmp):
                    print("----icmp-------")
                    print("dpid:",dpid)
                    if dpid == src_dpid: # from src packet_in
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
                                self.commandSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, self.ICMP_IDLE_TIME)
                            else:
                                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, self.ICMP_IDLE_TIME)
                                data = msg.data
                                self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                        else:
                            print("src_dpid != dst_dpid",src_dpid,dst_dpid)
                            path = self.routeCalculator.get_path(src_dpid, dst_dpid) # for 1st packet
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid) # for follow-up packet
                            if route:
                                if len(path) <= 4: # 2
                                    self.install_flow(route,dst_ip,src_in_port,dst_out_port)
                                    out_port = self.network_monitor.links_dpid_to_port[(route[0],route[1])][0]
                                    data = msg.data
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                elif len(path) > 4: # 2
                                    print("pack mpls dpid on traffic[0]:",dpid)
                                    out_port = self.network_monitor.links_dpid_to_port[(path[0],path[1])][0]
                                    label = self._get_mpls_label(path)
                                    pack = self.__add_mpls(pkt, label, src_mac, dst_mac)
                                    pack.serialize()
                                    data = pack.data
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                    self.install_flow(route,dst_ip,src_in_port,dst_out_port)
                    elif dpid == dst_dpid:
                        print("unpack mpls dpid on traffic[-1]:",dpid)
                        out_port = dst_out_port
                        pack = self.__remove_mpls(pkt, src_mac, dst_mac)
                        pack.serialize()
                        data = pack.data
                        self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return

                if isinstance(tcp_pkt,tcp.tcp):
                    print("------tcp-----------")
                    src_tcp = tcp_pkt.src_port
                    dst_tcp = tcp_pkt.dst_port
                    if dpid == src_dpid: # packet_in
                        # file = open('/home/zouyiran/bs/myself/ryu/ryu/app/reduce_t/fattree_record.txt','a')
                        if src_dpid == dst_dpid:
                            print("src_dpid == dst_dpid")
                            # file.write('----->'+'host_src:'+str(src_ip)+'->'+'host_dst:'+str(dst_ip)+'--'+
                            #            'src_dpid:'+str(src_dpid)+' dst_dpid:'+str(dst_dpid)+'\n')
                            priority = OFP_DEFAULT_PRIORITY+10
                            match = {
                                "dl_type":ether_types.ETH_TYPE_IP,
                                "nw_proto":6,
                                "in_port":in_port,
                                "nw_src":src_ip,
                                "nw_dst":dst_ip,
                                "tcp_src":src_tcp,
                                "tcp_dst":dst_tcp
                                    }
                            actions = [{"type":"OUTPUT","port":dst_out_port}]
                            if buffer_id != ofproto.OFP_NO_BUFFER:
                                self.commandSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, self.TCP_IDLE_TIME)
                            else:
                                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, self.TCP_IDLE_TIME)
                                data = msg.data
                                self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                        else:
                            print("src_dpid != dst_dpid")
                            # file.write('----->'+'host_src:'+str(src_ip)+'->'+'host_dst:'+str(dst_ip)+'--'+
                            #            'src_dpid:'+str(src_dpid)+' dst_dpid:'+str(dst_dpid)+'\n')
                            path = self.routeCalculator.get_path(src_dpid, dst_dpid) # for 1st packet
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid) # for follow-up packet
                            # file.write('traffic'+str(path)+'\n')
                            # file.write('route'+str(route)+'\n')
                            if route:
                                if len(path) <= 4: # 2
                                    self.install_flow_tcp(route, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp)
                                    data = msg.data
                                    out_port = self.network_monitor.links_dpid_to_port[(route[0],route[1])][0]
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                elif len(path) > 4: # 2
                                    print("pack mpls dpid on traffic[0]:",dpid)
                                    out_port = self.network_monitor.links_dpid_to_port[(path[0],path[1])][0]
                                    label = self._get_mpls_label(path)
                                    pack = self.__add_mpls(pkt, label, src_mac, dst_mac)
                                    pack.serialize()
                                    data = pack.data
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                    self.install_flow_tcp(route, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp)
                        # file.close()
                    elif dpid == dst_dpid:
                        print("unpack mpls dpid on traffic[-1]:",dpid)
                        out_port = dst_out_port
                        pack = self.__remove_mpls(pkt, src_mac, dst_mac)
                        pack.serialize()
                        data = pack.data
                        self.commandSender.packet_out(datapath, in_port, out_port, data)
                    return

                if isinstance(udp_pkt,udp.udp):
                    print("----udp-------")
                    src_udp = udp_pkt.src_port
                    dst_udp = udp_pkt.dst_port
                    if dpid == src_dpid:
                        if src_dpid == dst_dpid:
                            print("src_dpid == dst_dpid")
                            priority = OFP_DEFAULT_PRIORITY+10
                            match = {
                                "dl_type":ether_types.ETH_TYPE_IP,
                                "nw_proto":6,
                                "in_port":in_port,
                                "nw_src":src_ip,
                                "nw_dst":dst_ip,
                                "udp_src":src_udp,
                                "udp_dst":dst_udp,
                                    }
                            actions = [{"type":"OUTPUT","port":dst_out_port}]
                            if buffer_id != ofproto.OFP_NO_BUFFER:
                                self.commandSender.add_flow_rest_2(dpid, priority, match, actions,buffer_id, self.TCP_IDLE_TIME)
                            else:
                                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, self.TCP_IDLE_TIME)
                                data = msg.data
                                self.commandSender.packet_out(datapath, in_port, dst_out_port, data, buffer_id)
                        else:
                            print("src_dpid != dst_dpid")
                            path = self.routeCalculator.get_path(src_dpid, dst_dpid) # for 1st packet
                            route = self.routeCalculator.get_route(src_dpid, dst_dpid) # for follow-up packet
                            if route:
                                if len(path) <= 4: # 2
                                    self.install_flow_udp(route, src_ip, dst_ip, src_in_port, dst_out_port, src_udp, dst_udp)
                                    data = msg.data
                                    out_port = self.network_monitor.links_dpid_to_port[(route[0],route[1])][0]
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                elif len(path) > 4: # 2
                                    print("pack mpls dpid on traffic[0]:",dpid)
                                    out_port = self.network_monitor.links_dpid_to_port[(path[0],path[1])][0]
                                    label = self._get_mpls_label(path)
                                    pack = self.__add_mpls(pkt, label, src_mac, dst_mac)
                                    pack.serialize()
                                    data = pack.data
                                    self.commandSender.packet_out(datapath, in_port, out_port, data)
                                    self.install_flow_udp(route, src_ip, dst_ip, src_in_port, dst_out_port, src_udp, dst_udp)
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
                # print("install flow on src_dpid:",dpid)
                in_port = src_in_port
                out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
            elif j == n - 1:
                # print("install flow on dst_dpid:",dpid)
                in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = dst_out_port
            else:
                # print("install flow on dpid:",dpid)
                in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
            match = {
                    "dl_type":ether_types.ETH_TYPE_IP,
                    "in_port":in_port,
                    "nw_dst":dst_ip,
                    }
            actions = [{"type":"OUTPUT","port":out_port}]
            self.commandSender.add_flow_rest_1(dpid, priority, match, actions, self.ICMP_IDLE_TIME)

    #4 layer
    def install_flow_tcp(self, traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_tcp, dst_tcp):
            n = len(traffic)
            for j in range(n):
                dpid = traffic[j]
                priority = OFP_DEFAULT_PRIORITY + 10
                if j == 0:
                    # print("install flow on src_dpid:",dpid)
                    in_port = src_in_port
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                elif j == n - 1:
                    # print("install flow on dst_dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = dst_out_port
                else:
                    # print("install flow on dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "nw_proto":6,
                        "in_port":in_port,
                        "nw_src":src_ip,
                        "nw_dst":dst_ip,
                        "tcp_src":src_tcp,
                        "tcp_dst":dst_tcp
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, self.TCP_IDLE_TIME)

    #4 layer
    def install_flow_udp(self, traffic, src_ip, dst_ip, src_in_port, dst_out_port, src_udp, dst_udp):
            n = len(traffic)
            for j in range(n):
                dpid = traffic[j]
                priority = OFP_DEFAULT_PRIORITY + 10
                if j == 0:
                    # print("install flow on src_dpid:",dpid)
                    in_port = src_in_port
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                elif j == n - 1:
                    # print("install flow on dst_dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = dst_out_port
                else:
                    # print("install flow on dpid:",dpid)
                    in_port = self.network_monitor.links_dpid_to_port[(traffic[j-1],traffic[j])][1]
                    out_port = self.network_monitor.links_dpid_to_port[(traffic[j],traffic[j+1])][0]
                match = {
                        "dl_type":ether_types.ETH_TYPE_IP,
                        "nw_proto":6,
                        "in_port":in_port,
                        "nw_src":src_ip,
                        "nw_dst":dst_ip,
                        "udp_src":src_udp,
                        "udp_dst":dst_udp
                        }
                actions = [{"type":"OUTPUT","port":out_port}]
                self.commandSender.add_flow_rest_1(dpid, priority, match, actions, self.TCP_IDLE_TIME)