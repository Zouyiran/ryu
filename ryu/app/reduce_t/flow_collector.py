#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

from command_sender import CommandSender

'''
###reduce_t###
--> flow collector
1) call rest_api and parse json
'''

class FlowCollector(app_manager.RyuApp):
    '''
    only collect access switches
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowCollector, self).__init__(*args, **kwargs)
        self.flowSender = CommandSender.get_instance()

        self.dpids = []

        # {dpid:[{"idle_timeout":...,"packet_count":...,"byte_count":...,},{},{},...],
        #  dpid:[{},{},{]...],...}
        self.dpid_to_flow = dict()

    def request_stats_switches(self):
        res = self.flowSender.get_stats_switches()
        return res.json() #list

    def request_stats_flow(self, dpid):
        res = self.flowSender.get_stats_flow(dpid)
        return res.json() # dict

    def parse_stats_flow(self,stats_flow):
        flow_list = list()
        for each_flow in stats_flow:
            match = each_flow["match"]
            if match.has_key("tp_src") or match.has_key("up_src"):
                flow = dict()
                flow["idle_timeout"] = each_flow["idle_timeout"]
                flow["packet_count"] = each_flow["packet_count"]
                flow["byte_count"] = each_flow["byte_count"]
                flow["duration_sec"] = each_flow["duration_sec"]
                flow["nw_src"] = match["nw_src"]
                flow["nw_dst"] = match["nw_dst"]
                flow_list.append(flow)
        return flow_list

#---------------------Print_to_debug------------------------
    def print_stats(self):
        for each_dpid in self.dpid_to_flow:
            print("----------print_flow_collect_stats--------------")
            print "dpid:" + str(each_dpid)
            print "flow_num:" + str(len(self.dpid_to_flow[each_dpid]))
