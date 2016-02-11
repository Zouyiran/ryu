# -*- coding: utf-8 -*-

import copy
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib import stplib
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet, ethernet, arp, ether_types,mpls, icmp
from ryu.topology.api import get_all_switch, get_all_link,get_all_host

from flow_dispatcher import FlowDispatcher


class ProactiveApp(app_manager.RyuApp):
    '''
    when arp packet return
    pre-install the flows along the selected path
    the pre-install action be triggered on the first returned switch(the dst_mac switch)
    so the icmp packet will NOT packet_in to the controller
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(ProactiveApp, self).__init__(*args, **kwargs)
        self.stp = kwargs['stplib']

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        # config = {dpid_lib.str_to_dpid('0000000000000001'):
        #              {'bridge': {'priority': 0x8000}},
        #           dpid_lib.str_to_dpid('0000000000000002'):
        #              {'bridge': {'priority': 0x9000}},
        #           dpid_lib.str_to_dpid('0000000000000003'):
        #              {'bridge': {'priority': 0xa000}}}
        # self.stp.set_config(config)

        self.mac_to_port = {}

        self.flowDispatcher = FlowDispatcher()

        # {dpid:{mac:port,mac:port,...},dpid:{mac:port,mac:port,...},...} mac is switch_mac NOT host_mac
        self.dpid_mac_to_port = dict()
        # [dpid,dpid,...]
        self.dpids = list()

        self.hostmac_to_dpid = dict()
        self.hostmac_to_port = dict()
        # [hostmac, hostmac,...]
        self.hosts = list()

        #{(src_dpid,dst_dpid):(src_port,dst_port),():(),...}
        self.links_dpid_to_port = dict()
        # [(src_dpid,dst_dpid),(src_dpid,dst_dpid),...]
        self.links = list()

        self.adjacency_matrix = dict()
        self.pre_adjacency_matrix = dict()

        # {
        # (dpid,dpid):{xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid],...},
        # (dpid,dpid):{xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid],...},
        # ...}
        self.path_table = dict()

        self.SLEEP_PERIOD = 10 #seconds

        self.dpid_to_dp = dict()
        self.mac_to_port = dict()

        self.discover_thread = hub.spawn(self.path_find)


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

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler_stp(self, ev):
        # print("packet_in_handler_stp")
        msg = ev.msg
        buffer_id = msg.buffer_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src_mac = eth.src
        dst_mac = eth.dst
        ar = pkt.get_protocol(arp.arp)
        if ar and src_mac in self.hosts and dst_mac in self.hosts:
            print('>>>>>>packet_in_handler_stp if ar and src_mac in self.hosts and dst_mac in self.hosts the DPID:',dpid)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:# add flow
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.flowDispatcher.add_flow(datapath,
                                             OFP_DEFAULT_PRIORITY,
                                             match,
                                             actions,
                                             buffer_id,
                                             idle_timeout=10001,
                                             hard_timeout=0)
            else:
                self.flowDispatcher.add_flow(datapath,
                                             OFP_DEFAULT_PRIORITY,
                                             match,
                                             actions,
                                             idle_timeout=10001,
                                             hard_timeout=0)
        # attention:
        # if self.data is not None:
        #     assert self.buffer_id == 0xffffffff #OFP_NO_BUFFER = 0xffffffff
        if buffer_id == ofproto.OFP_NO_BUFFER or out_port == ofproto.OFPP_FLOOD: #help to packet_out
            data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        ar = pkt.get_protocol(arp.arp)
        if ar and src_mac in self.hosts and dst_mac in self.hosts:
            print('>>>>>>if ar and src_mac in self.hosts and dst_mac in self.hosts the DPID:',dpid)
            src_dpid = self.hostmac_to_dpid[dst_mac]
            dst_dpid = self.hostmac_to_dpid[src_mac]
            if src_dpid  == dst_dpid:
                print("src_dpid  == dst_dpid")
                out_port = in_port
                in_port =  self.hostmac_to_port[dst_mac]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=src_mac)
                self.flowDispatcher.add_flow(datapath,
                                             OFP_DEFAULT_PRIORITY,
                                             match,
                                             actions,
                                             idle_timeout=10000,
                                             hard_timeout=0)
            else:
                print("src_dpid  != dst_dpid")
                if dpid == dst_dpid:
                    print("now dpid == dst_dpid")
                    paths = self.path_table[(src_dpid,dst_dpid)]
                    path_num = len(paths)
                    if path_num == 0:
                        self.logger.info(src_mac,"->",dst_mac,": unreachable")
                    else:
                        path = self.traffic_find(paths)
                        print("path:",path)
                        for i in range(len(path)):
                            dpid = path[i]
                            print("path dpid is:",dpid)
                            datapath = self.dpid_to_dp[dpid]
                            parser = datapath.ofproto_parser
                            if i == 0:
                                in_port = self.hostmac_to_port[dst_mac]
                                out_port = self.links_dpid_to_port[(path[i],path[i+1])][0]

                            elif i == len(path) - 1:
                                in_port =  self.links_dpid_to_port[(path[i-1],path[i])][1]
                                out_port = self.hostmac_to_port[src_mac]
                            else:
                                in_port =  self.links_dpid_to_port[(path[i-1],path[i])][1]
                                out_port = self.links_dpid_to_port[(path[i],path[i+1])][0]
                            match = parser.OFPMatch(in_port=in_port, eth_dst=src_mac)
                            actions = [parser.OFPActionOutput(out_port)]
                            self.flowDispatcher.add_flow(datapath,
                                                         OFP_DEFAULT_PRIORITY,
                                                         match,
                                                         actions,
                                                         idle_timeout=10000,
                                                         hard_timeout=0)

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

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

#--------------------------------
#--------------------------------

#----------------------------Traffic_Finder----------------------------------------
    def _pick_one_path(self, paths):
        path = paths[0]
        return path

    def traffic_find(self, paths): # paths  [[],[],[],...]
        path_num = len(paths)
        if path_num == 1:
            path = paths[0]
        else:
            path = self._pick_one_path(paths)
        return path

#----------------------------Path_Finder----------------------------------------
    def path_find(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self._update_topology() # update: self.dpid_mac_to_port,self.dpids, self.links_dpid_to_port, self.links, self.adjacency_matrix
            self._update_hosts() # update: self.hostmac_to_dpid, self.hostmac_to_port, self.hosts
            # when adjacency matrix is update,then update the path_table
            if self.pre_adjacency_matrix != self.adjacency_matrix:
                self.logger.info('***********discover_topology thread: TOPO  UPDATE***********')
                # self._show_matrix()
                self.path_table = self._get_path_table(self.adjacency_matrix)
                # self._show_path_table()

    def _update_topology(self):
        switch_list = get_all_switch(self)
        # print("switch_list length:",len(switch_list))
        if switch_list:
            self.dpid_mac_to_port = self._get_switches_mac_to_port(switch_list)
            self.dpids = self._get_switches(switch_list) # dpid
        link_dict = get_all_link(self)
        if link_dict:
            self.links_dpid_to_port = self._get_links_dpid_to_port(link_dict)
            self.links = self._get_links(self.links_dpid_to_port) #(src.dpid,dst.dpid)
        if self.dpids and self.links:
            self.adjacency_matrix = self._get_adjacency_matrix(self.dpids, self.links)

    def _update_hosts(self):
        host_obj  = get_all_host(self)
        # print("host_obj length:",len(host_obj))
        if host_obj:
            self.hostmac_to_dpid, self.hostmac_to_port = self._get_hosts_to_dpid_and_port(host_obj)
            self.hosts = self._get_hosts(host_obj) # mac

    def _get_path_table(self, matrix):
        if matrix:
            g = nx.Graph()
            g.add_nodes_from(self.dpids)
            for i in self.dpids:
                for j in self.dpids:
                    if matrix[i][j] == 1:
                        g.add_edge(i,j,weight=1)
            return self.__graph_to_path(g)

    def __graph_to_path(self,g):
        all_shortest_paths = dict()
        for i in g.nodes():
            for j in g.nodes():
                if i == j:
                    continue
                all_shortest_paths[(i,j)] = list()
                try:
                    nx.shortest_path(g,i,j)
                except nx.exception.NetworkXNoPath:
                    continue
                for each in nx.all_shortest_paths(g,i,j):
                    all_shortest_paths[(i,j)].append(each)
        return all_shortest_paths

    def _get_switches_mac_to_port(self,switch_list):
        table = dict()
        for switch in switch_list:
            dpid = switch.dp.id
            # print("_get_switches_mac_to_port -> dpid:",dpid)
            table.setdefault(dpid,{})
            ports = switch.ports
            for port in ports:
                table[dpid][port.hw_addr] =  port.port_no
        return table

    def _get_switches(self,switch_list):
        dpid_list = list()
        for switch in switch_list:
            dpid_list.append(switch.dp.id)
        return dpid_list #[dpid,dpid, dpid,...]

    def _get_links_dpid_to_port(self,link_dict):
        table = dict()
        for link in link_dict.keys():
            src = link.src #ryu.topology.switches.Port
            dst = link.dst
            table[(src.dpid,dst.dpid)] = (src.port_no, dst.port_no)
        return table

    def _get_links(self,link_ports_table):
        return link_ports_table.keys() #[(src.dpid,dst.dpid),(src.dpid,dst.dpid),...]

    def _get_adjacency_matrix(self,switches,links):
        graph = dict()
        for src in switches:
            graph[src] = dict()
            for dst in switches:
                graph[src][dst] = float('inf')
                if src == dst:
                    graph[src][dst] = 0
                elif (src, dst) in links:
                    graph[src][dst] = 1
        return graph

    def _get_hosts_to_dpid_and_port(self,host_list):
        hostmac_to_dpid = dict()
        hostmac_to_port = dict()
        for host in host_list:
            host_mac = host.mac
            host_port = host.port
            hostmac_to_port[host_mac] = host_port.port_no
            dpid = host_port.dpid
            hostmac_to_dpid[host_mac] = dpid
        return  hostmac_to_dpid, hostmac_to_port

    def _get_hosts(self, host_list):
        table = list()
        for each in host_list:
            table.append(each.mac) #[mac,mac,mac,...]
        return table

#---------------------Print_to_debug------------------------
    def _show_matrix(self):
        switch_num = len(self.adjacency_matrix)
        print "---------------------adjacency_matrix---------------------"
        print '%10s' % ("switch"),
        for i in range(1, switch_num + 1):
            print '%10d' % i,
        print ""
        for i in self.adjacency_matrix.keys():
            print '%10d' % i,
            for j in self.adjacency_matrix[i].values():
                print '%10.0f' % j,
            print ""

    def _show_path_table(self):
        print "---------------------path_table---------------------"
        for pair in self.path_table.keys():
            print("pair:",pair)
            for each in self.path_table[pair]:
                print each,
            print""

    # def _show_traffic_table(self):
    #     print "---------------------traffic_table---------------------"
    #     for pair in self.traffic_table.keys():
    #         print("pair:",pair)
    #         print self.traffic_table[pair]

    def _show_host(self):
        print "---------------------show_host---------------------"
        for each in self.hostmac_to_dpid:
            print("each:",each,"->","dpid:",self.hostmac_to_dpid[each])
        for each in self.hostmac_to_port:
            print("each:",each,"->","port:",self.hostmac_to_port[each])

    def _show_link_dpid_to_port(self):
        print "---------------------show_link_dpid_to_port---------------------"
        for pair in self.links_dpid_to_port:
            print("dpid_pair:",pair)
            print("port:",self.links_dpid_to_port[pair])

