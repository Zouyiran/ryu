#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.topology.api import get_all_switch, get_all_link, get_all_host

from flow_sender import FlowSender

class FlowCollector(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowCollector, self).__init__(*args, **kwargs)
        self.flowSender = FlowSender()

        self.dpids = []
        self.dpid_to_flow = dict() # {dpid:[Flow,Flow,Flow,...],dpid:[Flow,Flow,Flow,...],...}

        self.COLLECT_PERIOD = 5
        self.collector_thread = hub.spawn(self._collector)

    def _collector(self):
        while True:
            hub.sleep(self.COLLECT_PERIOD)
            self.dpids = self._request_stats_switches()
            for dpid in self.dpids:
                self.dpid_to_flow.setdefault(dpid, {})
                stats_flow = self._request_stats_flow(dpid)[str(dpid)]
                self.dpid_to_flow[dpid] = self._parse_stats_flow(stats_flow)
            # self.print_dpid_to_flow()

    def _request_stats_switches(self):
        res = self.flowSender.get_stats_switches() # Response
        return res.json() #list

    def _request_stats_flow(self, dpid):
        res = self.flowSender.get_stats_flow(dpid)
        return res.json() # dict

    def _parse_stats_flow(self,stats_flow):
        flow_list = list()
        for each_flow in stats_flow:
            if each_flow["actions"] == ["OUTPUT:CONTROLLER"]:
                continue
            if each_flow["match"].has_key("mpls_label"):
                continue
            flow = Flow()
            flow.idle_timeout = each_flow["idle_timeout"]
            flow.packet_count = each_flow["packet_count"]
            flow.byte_count = each_flow["byte_count"]
            flow.duration_sec = each_flow["duration_sec"]
            if each_flow.has_key("src_ip"):
                flow.src_ip = each_flow["src_ip"]
            if each_flow.has_key("dst_ip"):
                flow.dst_ip = each_flow["dst_ip"]
            if each_flow.has_key("src_tcp"):
                flow.src_tcp = each_flow["src_tcp"]
            if each_flow.has_key("dst_tcp"):
                flow.dst_tcp = each_flow["dst_tcp"]
            flow_list.append(flow)
        return flow_list

    def print_dpid_to_flow(self):
        for each_dpid in self.dpid_to_flow:
            print("------------------------")
            print "dpid:"+ str(each_dpid)
            print "flows packet_count:"
            for each_flow in self.dpid_to_flow[each_dpid]:
                print each_flow.packet_count

class Flow(object):
    def __init__(self):
        super(Flow, self).__init__()
        self.idle_timeout = 0
        self.packet_count = 0
        self.byte_count = 0
        self.duration_sec = 0
        self.src_ip = ""
        self.dst_ip = ""
        self.src_tcp = ""
        self.dst_tcp = ""




