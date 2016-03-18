#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

from command_sender import CommandSender


class FlowCollector(app_manager.RyuApp):
    '''
    only collect access switches
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowCollector, self).__init__(*args, **kwargs)
        self.flowSender = CommandSender.get_instance()

        self.dpids = []
        self.dpid_to_flow = dict() # {dpid:[Flow,Flow,Flow,...],dpid:[Flow,Flow,Flow,...],...}


    # not used
    def request_stats_switches(self):
        res = self.flowSender.get_stats_switches() # Response
        return res.json() #list

    def request_stats_flow(self, dpid):
        res = self.flowSender.get_stats_flow(dpid)
        return res.json() # dict

    def parse_stats_flow(self,stats_flow):
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




