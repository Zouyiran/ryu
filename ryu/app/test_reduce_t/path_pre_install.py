#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ryu.lib.packet import ether_types
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from command_sender import CommandSender

class PathPreInstall(object):
    '''
     PathPreInstall:
     pre install mpls path between access switches

    '''

    def __init__(self):
        super(PathPreInstall, self).__init__()
        self.name = 'PathPreInstall'
        self.commandSender = CommandSender.get_instance()

        self.mpls_to_path = dict()
        self.LABEL = 0
        self.LABEL_BE_USED = set()
        self.LABEL_RECYCLE = set()

    # delete old mpls_path, add new mpls_path
    def setup_mpls_path(self, pre_path_table, path_table, network_monitor):
        '''

        :param pre_path_table:
        :param path_table:
        :param network_monitor:
        :return:
        '''

        print("...................pre-install flow..................")
        if len(pre_path_table) == 0 and len(path_table) != 0: # initial
            print("...................network initial..................")
            self.LABEL = 0
            self.LABEL_BE_USED.clear()
            self.LABEL_RECYCLE.clear()
            for path_pair in path_table.keys():
                path = path_table[path_pair]
                if len(path) > 0:
                    self.mpls_to_path[self.LABEL] = path
                    self.LABEL_BE_USED.add(self.LABEL) # record its mpls label
                    self.__add_flow(path,self.LABEL, network_monitor)
                    self.LABEL += 1
        elif len(pre_path_table) != 0 and len(path_table) == 0:
            print("...................network disappear..................")
            pass

        else: # network change
            print("...................network changed..................")
            delete_path_table = dict()
            for dpid_pair in pre_path_table:
                if dpid_pair not in path_table:
                    delete_path_table[dpid_pair] = pre_path_table[dpid_pair]
                elif pre_path_table[dpid_pair] != path_table[dpid_pair]:
                    delete_path_table[dpid_pair] = pre_path_table[dpid_pair]
            for dpid_pair in delete_path_table:
                path = delete_path_table[dpid_pair]
                if len(path) > 0:
                    for label in self.mpls_to_path:
                        if self.mpls_to_path[label] == path:
                            self.LABEL_BE_USED.remove(label)
                            self.LABEL_RECYCLE.add(label)
                            del self.mpls_to_path[label]
                            self.__delete_flow(path,label, network_monitor)
                            break
            add_path_table = dict()
            for dpid_pair in path_table:
                if dpid_pair not in pre_path_table:
                    add_path_table[dpid_pair] = path_table[dpid_pair]
                elif pre_path_table[dpid_pair] != path_table[dpid_pair]:
                     add_path_table[dpid_pair] = path_table[dpid_pair]
            for dpid_pair in add_path_table:
                path = add_path_table[dpid_pair]
                if len(path) > 0:
                    if self.LABEL_RECYCLE:
                        label = self.LABEL_RECYCLE.pop()
                        self.mpls_to_path[label] = path
                        self.LABEL_BE_USED.add(label)
                        self.__add_flow(path, label, network_monitor)
                    else:
                        self.mpls_to_path[self.LABEL] = path
                        self.LABEL_BE_USED.add(self.LABEL)
                        self.__add_flow(path,self.LABEL, network_monitor)
                        self.LABEL += 1

    def __delete_flow(self, path, label, network_monitor):
        n = len(path)
        if n > 2:
            for i in range(1,n-1):
                dpid = path[i]
                if dpid in network_monitor.dpids:
                    match = {
                            "dl_type":ether_types.ETH_TYPE_MPLS,
                            "mpls_label":label,
                            }
                    self.commandSender.delete_flow_rest(dpid, OFP_DEFAULT_PRIORITY, match)

    def __add_flow(self, path, label, network_monitor):
        n = len(path)
        if n >2:
            for i in range(1,n-1):
                dpid = path[i]
                if dpid in network_monitor.dpids:
                    in_port = network_monitor.links_dpid_to_port[(path[i-1],path[i])][1]
                    out_port = network_monitor.links_dpid_to_port[(path[i],path[i+1])][0]
                    match = {
                            "dl_type":ether_types.ETH_TYPE_MPLS,
                            "in_port":in_port,
                            "mpls_label":label,
                            }
                    actions = [{"type":"OUTPUT","port":out_port}]
                    self.commandSender.add_flow_rest_1(dpid, OFP_DEFAULT_PRIORITY, match, actions)