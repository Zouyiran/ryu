#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

class FlowSender(object):

    def __init__(self):
        self.IP = "http://localhost:8080"

    def add_flow(self, datapath, priority, match, actions,  buffer_id=None, idle_timeout=0, hard_timeout=0):
        '''
        OFPFlowMod default argument:
        command=ofproto.OFPFC_ADD,
        idle_timeout=0, hard_timeout=0,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # OFPFlowMod: The controller sends this message to modify the flow table.
        # command=ofproto.OFPFC_ADD
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    match=match,instructions=inst,
                                    buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_rest_1(self, dpid, priority, match, actions, idle_timeout=0, hard_timeout=0):
        uri = "/stats/flowentry/add"
        data = {"dpid": dpid,
                "table_id": 0,
                "priority": priority,
                "idle_timeout": idle_timeout,
                "hard_timeout": hard_timeout,
                "match": match, # match {}
                "actions": actions # actions []
                }
        requests.post(url=self.IP+uri,data=str(data))

    # "idle_timeout": "hard_timeout":
    def add_flow_rest_2(self, dpid, priority, match, actions, buffer_id, idle_timeout=0, hard_timeout=0):
        uri = "/stats/flowentry/add"
        data = {"dpid":dpid,
                "table_id":0,
                "buffer_id":buffer_id,
                "priority": priority,
                "idle_timeout": idle_timeout,
                "hard_timeout": hard_timeout,
                "match":match, # match {}
                "actions":actions # actions []
                }
        requests.post(url=self.IP+uri,data=str(data))

    def delete_flow_rest(self, dpid, priority, match):
        uri = "/stats/flowentry/delete"
        data = {"dpid":dpid,
                "table_id":0,
                "priority": priority,
                "match":match, # match {}
                }
        requests.post(url=self.IP+uri,data=str(data))

    def get_hosts(self):
        uri = "/v1.0/topology/hosts"
        return requests.get(url=self.IP+uri)

    def packet_out(self, datapath, in_port, out_port, data, buffer_id=None):
        if buffer_id is None:
            buffer_id = datapath.ofproto.OFP_NO_BUFFER
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        # OFPPacketOut: The controller uses this message to send a packet out throught the switch.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

