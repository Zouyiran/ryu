#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

'''
###reduce_t###
--> commander sender
1) call built-in function
2) rest api
'''

class CommandSender(object):

    # singletone
    _instance = None

    def __init__(self):
        self.IP = "http://localhost:8080"

    @staticmethod
    def get_instance():
        if not CommandSender._instance:
            CommandSender._instance = CommandSender()
        return CommandSender._instance

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

    def get_stats_switches(self):
        '''
        get the list of all switches
        GET /stats/switches
        [
          1,
          2,
          3,
          4,
          5,
          6,
          7,
          8,
          9,
          10
        ]
        '''
        uri = "/stats/switches"
        response = requests.get(url=self.IP+uri)
        return response

    def get_stats_flow(self, dpid):
        '''
        get flows stats of the switch
        GET /stats/flow/<dpid>
        {
          "1": [
            {
              "actions": [
                "OUTPUT:CONTROLLER"
              ],
              "idle_timeout": 0,
              "cookie": 0,
              "packet_count": 130,
              "hard_timeout": 0,
              "byte_count": 25003,
              "length": 80,
              "duration_nsec": 274000000,
              "priority": 0,
              "duration_sec": 415,
              "table_id": 0,
              "flags": 0,
              "match": {}
            },
        '''
        uri = "/stats/flow/" + str(dpid)
        response = requests.get(url=self.IP+uri)
        return response

    def get_stats_port(self, dpid):
        '''
        get ports stats of the switch
        GET /stats/port/<dpid>
        {
          "1": [
            {
              "tx_dropped": 0,
              "rx_packets": 0,
              "rx_crc_err": 0,
              "tx_bytes": 0,
              "rx_dropped": 0,
              "port_no": "LOCAL",
              "rx_over_err": 0,
              "rx_frame_err": 0,
              "rx_bytes": 0,
              "tx_errors": 0,
              "duration_nsec": 528000000,
              "collisions": 0,
              "duration_sec": 289,
              "rx_errors": 0,
              "tx_packets": 0
            },

        '''
        uri = "/stats/port/" + str(dpid)
        response = requests.get(url=self.IP+uri)
        return response

    def get_stats_portdesc(self, dpid):
        '''
        get ports description of the switch
        GET /stats/portdesc/<dpid>
        {
          "1": [
            {
              "hw_addr": "0a:59:38:9b:a4:45",
              "curr": 0,
              "supported": 0,
              "max_speed": 0,
              "advertised": 0,
              "peer": 0,
              "port_no": "LOCAL",
              "curr_speed": 0,
              "name": "s1",
              "state": 1,
              "config": 1
            },
            {
              "hw_addr": "e2:85:85:22:37:ea",
              "curr": 2112,
              "supported": 0,
              "max_speed": 0,
              "advertised": 0,
              "peer": 0,
              "port_no": 1,
              "curr_speed": 10000000,
              "name": "s1-eth1",
              "state": 0,
              "config": 0
            },
        '''
        uri = "/stats/portdesc/" + str(dpid)
        response = requests.get(url=self.IP+uri)
        return response

    def get_aggr_flow(self, dpid):
        '''
        # get aggregate flows stats of the switch
        # GET /stats/aggregateflow/<dpid>
        :param dpid:
        :return:
        {
          "5": [
            {
              "packet_count": 404,
              "byte_count": 31828,
              "flow_count": 26
            }
          ]
        }
        '''
        uri = "/stats/aggregateflow/" + str(dpid)
        response = requests.get(url=self.IP+uri)
        return response



