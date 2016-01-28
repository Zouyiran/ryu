# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from flow_dispatcher import FlowDispatcher
from path_finder import PathFinder
from traffic_finder import TrafficFinder


class ProactiveApp(app_manager.RyuApp):
    '''
    Proactive App:
    handle incoming event and
    trigger the relevant handle module
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProactiveApp, self).__init__(*args, **kwargs)
        self.flowDispatcher = FlowDispatcher()
        self.path_finder = PathFinder()
        self.traffic_finder = TrafficFinder()
        self.dpid_to_dp = dict()
        self.discover_thread = hub.spawn(self.path_finder.find())

    # install table-miss flow entry
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.flowDispatcher.add_flow(datapath, 0, match, actions)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.traffic_finder.find(ev)
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     dpid = datapath.id
    #
    #     in_port = msg.match['in_port']
    #     pkt = packet.Packet(msg.data)
    #
    #     arp_pkt = pkt.get_protocol(arp.arp)
    #     ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #
    #     if arp_pkt:
    #         arp_src_ip = arp_pkt.src_ip
    #         print("arp_src_ip:",arp_src_ip)
    #         arp_dst_ip = arp_pkt.dst_ip
    #         print("arp_dst_ip:",arp_dst_ip)
    #         # record the access info
    #         self.register_access_info(dpid, in_port, arp_src_ip)
    #
    # def register_access_info(self,dpid,in_port, ip):
    #     self.access_table.setdefault(dpid,{})
    #     port_to_ip = self.access_table[dpid]
    #     if in_port in port_to_ip.keys():
    #         if port_to_ip[in_port] == ip:
    #             pass
    #     else:
    #         port_to_ip[in_port] = ip
    #     for dpid in self.access_table:
    #         print("dpid:",dpid)
    #         for each in self.access_table[dpid]:
    #             print(each,"->",self.access_table[dpid][each])
    #
    #
    #     if in_port in self.access_table[dpid]:
    #         if (dpid, in_port) in self.access_table:
    #             if ip != self.access_table[(dpid, in_port)]:
    #                 self.access_table[(dpid, in_port)] = ip
    #         else:
    #             self.access_table[(dpid, in_port)] = ip


    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.dpid_to_dp:
                self.logger.info('register datapath: %04x', datapath.id)
                self.dpid_to_dp[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.dpid_to_dp:
                self.logger.info('un register datapath: %04x', datapath.id)
                del self.dpid_to_dp[datapath.id]




