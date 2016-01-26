# -*- coding: utf-8 -*-

import logging
import struct
import copy
from operator import attrgetter
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0, ofproto_protocol
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu import utils
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_all_switch, get_link,get_all_link,get_all_host,get_host
import collections


class PathFinder(app_manager.RyuApp):

    '''
     get topology
     generate the path table
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(PathFinder, self).__init__(*args, **kwargs)
        self.mac_to_port = dict()

        self.switches_mac_to_port = dict()
        self.hosts_mac_to_port = dict()
        self.links_dpid_to_port = dict()

        self.switches = list()
        self.links = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        self.path_table = list()
        self.pre_path_table = list()
        self.differ_path_table = list()

        self.id_to_dp = dict()

        # self.discover_thread = hub.spawn(self.discover_topology)

        self.SLEEP_PERIOD = 1 #seconds
        self.PRIORITY = OFP_DEFAULT_PRIORITY


        self.MAC_LIST = ["00:00:00:00:00:01",
                         "00:00:00:00:00:02",
                         "00:00:00:00:00:03",
                         "00:00:00:00:00:04",
                         "00:00:00:00:00:05",
                         "00:00:00:00:00:06"]


    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.id_to_dp:
                self.logger.info('register datapath: %04x', datapath.id)
                self.id_to_dp[datapath.id] = datapath
                self._update_topology()
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.id_to_dp:
                self.logger.info('unregister datapath: %04x', datapath.id)
                del self.id_to_dp[datapath.id]
                self._update_topology()


    def _update_topology(self):
        switch_list = get_all_switch(self) # return a list[ryu.topology.switches.Switch]
        if switch_list:
            self.switches_mac_to_port = self._get_switches_mac_to_port(switch_list)

        host_list = get_all_host(self) # return a list[ryu.topology.switches.Host]
        if host_list:
            self.hosts_mac_to_port = self._get_hosts_mac_to_port(host_list)

        link_dict = get_all_link(self) # return ryu.topology.switches.LinkState{Link class -> timestamp}
        if link_dict:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)

        self.switches = self._get_switches(switch_list) # dpid
        self.links = self._get_links(self.links_dpid_to_port) #(src.dpid,dst.dpid)
        self.adjacency_matrix = self._get_adjacency_matrix(self.switches, self.links)