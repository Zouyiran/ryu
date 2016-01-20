# -*- coding: utf-8 -*-

import logging
import struct
import copy
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu import utils
from ryu.lib.packet import ether_types


from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_all_switch, get_link,get_all_link

# '''
# ofproto_v1_3_parser.py
# class OFPFlowMod(MsgBase)
#     def __init__(self, datapath, cookie=0, cookie_mask=0, table_id=0,
#                  command=ofproto.OFPFC_ADD,
#                  idle_timeout=0, hard_timeo
# ut=0,
#                  priority=ofproto.OFP_DEFAULT_PRIORITY,
#                  buffer_id=ofproto.OFP_NO_BUFFER,
#                  out_port=0, out_group=0, flags=0,
#                  match=None,
#                  instructions=[]):
# '''

SLEEP_PERIOD = 5
IS_UPDATE = False

class PathTable(app_manager.RyuApp):

    '''
     get switches and links, that is topology
     generate the path table
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PathTable, self).__init__(*args, **kwargs)
        self.name = "PathTable"
        self.mac_to_port = {}
        self.switch_ports_table = {}
        self.link_ports_table = {}
        self.switches = []
        self.links = []
        # self.switch_controller_port = {}
        self.adjacency_matrix = {}
        self.pre_adjacency_matrix = {}
        self.discover_thread = hub.spawn(self.discover_topology)

    # topology discovery thread
    def discover_topology(self):
        i = 0
        while True:
            if i == 5:
                self._update_topology(None)
                # self._show()
                i = 0
            hub.sleep(SLEEP_PERIOD)
            i += 1

    # def _show(self):
    #     switch_num = len(self.adjacency_matrix)
    #     # if IS_UPDATE:
    #     print "---------------------adjacency_matrix---------------------"
    #     print '%10s' % ("switch"),
    #     for i in range(1, switch_num + 1):
    #         print '%10d' % i,
    #     print ""
    #     for i in self.adjacency_matrix.keys():
    #         print '%10d' % i,
    #         for j in self.adjacency_matrix[i].values():
    #             print '%10.0f' % j,
    #         print ""

    events = [event.EventSwitchEnter,event.EventSwitchLeave, # switch
              event.EventPortAdd,event.EventPortDelete, event.EventPortModify, # port
              event.EventLinkAdd, event.EventLinkDelete] # link

    @set_ev_cls(events)
    def _update_topology(self, ev):
        switch_list = get_all_switch(self) # return a list, the type of element is ryu.topology.switches.Switch
        # self.logger.info('type of element switch_list:%s',type(switch_list))
        self.get_switch_ports(switch_list)
        self.switches = self.get_switches(self.switch_ports_table)

        link_dict = get_link(self, dpid=None) #return ryu.topology.switches.LinkState  a kind of dict: Link class -> timestamp
        # self.logger.info('type of element link_list:%s',type(link_dict))
        # TODO bug need to fix: get_link() is None, it is so strange
        if link_dict:
            print("link_dict is not None")
        else:
            print("link_dict is None")
        self.get_link_ports(link_dict)
        self.links = self.get_links(self.link_ports_table)

        self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
        self.get_adjacency_matrix(self.switches, self.links)
        if self.pre_adjacency_matrix != self.adjacency_matrix:
            IS_UPDATE = True


    def get_switch_ports(self,switch_list):
        self.switch_ports_table.clear()
        for switch in switch_list:
            dpid = switch.dp.id
            self.switch_ports_table[dpid] = set() # dpid->port_num
            # self.switch_ports_table.setdefault(dpid, set()) # dpid->port_num
            # self.switch_controller_port.setdefault(dp_id, set())
            for port in switch.ports:
                 self.switch_ports_table[dpid].add(port.port_no)

    def get_switches(self,switch_port_table):
        return switch_port_table.keys()

    def get_link_ports(self,link_dict):
        self.link_ports_table.clear()
        for link in link_dict.keys():
            src = link.src
            dst = link.dst
            # self.link_ports_table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
            # self.link_ports_table.setdefault((src.dpid,dst.dpid),(src.port_no, dst.port_no))
            self.link_ports_table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)

    def get_links(self,link_ports_table):
        return link_ports_table.keys()

    def get_adjacency_matrix(self,switches,links):
        for src in switches:
            print("*"*20)
            print("src",src)
            for dst in switches:
                print("dst",dst)
                self.adjacency_matrix[src] = {dst: float('inf')}
                if src == dst:
                    self.adjacency_matrix[src][dst] = 0
                elif (src, dst) in links:
                    self.adjacency_matrix[src][dst] = 1


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        # self.logger.info('OFPSwitchFeatures received: '
        #               'datapath_id=0x%016x n_buffers=%d '
        #               'n_tables=%d auxiliary_id=%d '
        #               'capabilities=0x%08x',
        #               msg.datapath_id, msg.n_buffers, msg.n_tables,
        #               msg.auxiliary_id, msg.capabilities)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            # OFPFlowMod default command=ofproto.OFPFC_ADD
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            pass
            # self.logger.info("packet truncated: only %s of %s bytes",
            #                   ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        self.logger.debug('dir(ev):',dir(ev))
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'
        # self.logger.info('OFPPacketIn received: '
        #           'buffer_id=%x total_len=%d reason=%s '
        #           'table_id=%d cookie=%d match=%s data=%s',
        #           msg.buffer_id, msg.total_len, reason,
        #           msg.table_id, msg.cookie, msg.match,
        #           utils.hex_array(msg.data))

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0] # return a list so list[0] to extract it

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in -> dpid:%s src:%s dst:%s in_port:%s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

