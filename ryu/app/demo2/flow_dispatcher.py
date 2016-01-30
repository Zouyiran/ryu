# -*- coding: utf-8 -*-

import requests

class FlowDispatcher(object):

    def __init__(self):
        self.IP = "http://localhost:8080"

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # OFPFlowMod: The controller sends this message to modify the flow table.
        # command=ofproto.OFPFC_ADD
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_rest_1(self, dpid, priority, match, actions):
        uri = "/stats/flowentry/add"
        data = {"dpid":dpid,
                "table_id":0,
                "priority": priority,
                "match":match, # match {}
                "actions":actions # actions []
                }
        requests.post(url=self.IP+uri,data=str(data))

    def add_flow_rest_2(self, dpid, priority, match, actions, buffer_id):
        uri = "/stats/flowentry/add"
        data = {"dpid":dpid,
                "table_id":0,
                "buffer_id":buffer_id,
                "priority": priority,
                "match":match, # match {}
                "actions":actions # actions []
                }
        requests.post(url=self.IP+uri,data=str(data))


    def packet_out(self, datapath, in_port, out_port, data, buffer_id=None):
        if buffer_id is None:
            print("NO_BUFFER!!!")
            buffer_id = datapath.ofproto.OFP_NO_BUFFER
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        # OFPPacketOut: The controller uses this message to send a packet out throught the switch.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

