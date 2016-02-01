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
from ryu.lib.packet import packet, ethernet, arp, ether_types,mpls, icmp
from ryu.topology.api import get_all_switch, get_all_link,get_all_host

from flow_dispatcher import FlowDispatcher


class ProactiveApp(app_manager.RyuApp):
    '''
    Proactive App:
    handle incoming event and
    trigger the relevant handle module
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProactiveApp, self).__init__(*args, **kwargs)
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

        self.SLEEP_PERIOD = 20 #seconds
        self.PRIORITY = OFP_DEFAULT_PRIORITY # 0x8000
        self.LABEL = 0

        self.dpid_to_dp = dict()
        self.ip_to_port = dict()
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


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        buffer_id = msg.buffer_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        # in_reason = msg.reason
        # if in_reason == ofproto.OFPR_NO_MATCH:
        #     reason = 'NO_MATCH'
        # elif in_reason == ofproto.OFPR_ACTION:
        #     reason = 'ACTION'
        # elif in_reason == ofproto.OFPR_INVALID_TTL:
        #     reason = 'INVALID_TTL'
        # else:
        #     reason = 'UNKNOWN'
        in_port = msg.match['in_port']

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        pkt = packet.Packet(msg.data) # array.array('B',msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # the topology.switches.Switches can handle the LLDP packet
            # for LLDP working, must --observe-links
            return

        src_mac = eth.src
        dst_mac = eth.dst

        ar = pkt.get_protocol(arp.arp)
        if ar:
            print("----------arp----------")
            print("dpid:",dpid)

#----------------  mpls ----------------
        # host_mac = self.hostmac_to_dpid.keys() # self.hosts
        if not ar and src_mac in self.hosts and dst_mac in self.hosts:
            ic = pkt.get_protocol(icmp.icmp)
            if ic:
                print("----------icmp----------")
            print("dpid:",dpid)
            print("in_port:",in_port)
            print("src_mac:",src_mac)
            print("dst_mac:",dst_mac)
            src_dpid = self.hostmac_to_dpid[src_mac]
            dst_dpid = self.hostmac_to_dpid[dst_mac]

            # NO need to mpls
            if src_dpid == dst_dpid:
                out_port = self.hostmac_to_port[dst_mac]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                if buffer_id != ofproto.OFP_NO_BUFFER:
                    self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions, buffer_id, 1000, 0)
                    return
                else:
                    self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions, 1000, 0)
                data = None
                if buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)
                return

            elif (src_dpid,dst_dpid) in self.path_table.keys(): # must be in it, "if" is no need
                paths = self.path_table[(src_dpid,dst_dpid)] # {xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid]}
                path_num = len(paths)
                if path_num == 0:
                    self.logger.info(src_mac,"->",dst_mac,": unreachable")
                    return
                else:
                    path = self.traffic_find(paths) # return (123,[1,2,3])
                label = path[0]
                path = path[1]

                # NO need to mpls
                if len(path) == 2:
                    if dpid == path[0]:
                        out_port = self.links_dpid_to_port[(path[0],path[1])][0]
                    else:
                        out_port = self.hostmac_to_port[dst_mac]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                    if buffer_id != ofproto.OFP_NO_BUFFER:
                        self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions, buffer_id, 1000, 0)
                        return
                    else:
                        self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions, 1000, 0)
                    data = None
                    if buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)
                    return

                # need to mpls
                elif len(path) > 2:
                    if dpid == path[0]:
                        out_port = self.links_dpid_to_port[(path[0],path[1])][0]
                        pack = self.__add_mpls(pkt,label, src_mac, dst_mac)
                        pack.serialize()
                        data = pack.data
                        self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)
                        self.__add_path_flows(in_port, dst_mac, parser, path)
                    elif dpid == path[-1]:
                        out_port = self.hostmac_to_port[dst_mac]
                        pack = self.__remove_mpls(pkt, src_mac, dst_mac)
                        pack.serialize()
                        data = pack.data
                        self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)
                    else:
                        self.logger.info("not path[0] and not path[-1], so this is a BUG!!!")
                    return
#----------------  mpls ----------------

#----------------basic mac learning----------------
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # add a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            # verify if we have a valid buffer_id, if yes avoid to send both flow_mod & packet_out
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.flowDispatcher.add_flow(datapath, 1, match, actions, buffer_id)
                return
            else:
                self.flowDispatcher.add_flow(datapath, 1, match, actions)
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)
#----------------basic mac learning----------------

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

    def __add_path_flows(self,first_in_port, dst_mac, parser, path):
        num = len(path)
        for i in range(num):
            dpid = path[i]
            if i == 0:
                in_port = first_in_port
            else:
                in_port = self.links_dpid_to_port[(path[i-1],path[i])][1]
            if i == num - 1:
                out_port = self.hostmac_to_port[dst_mac]
            else:
                out_port = self.links_dpid_to_port[(path[i],path[i+1])][0]
            datapath = self.dpid_to_dp[dpid]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.flowDispatcher.add_flow(datapath, 1, match, actions)


    def __add_mpls(self,  pkt_old, label, src_mac, dst_mac):
        pkt_new = packet.Packet()
        mpls_proto = mpls.mpls(label=label) # label:20bit(0~1048576-1), exp(QoS):3bit, bsb:1bit, ttl:8bit
        pkt_new.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac,ethertype=ether_types.ETH_TYPE_MPLS))
        pkt_new.add_protocol(mpls_proto)
        for i in range(1,len(pkt_old)):#[ethernet, ipv4, tcp,..]
            pkt_new.add_protocol(pkt_old[i])
        return pkt_new

    def __remove_mpls(self,pkt_old, src_mac, dst_mac):
        pkt_new = packet.Packet()
        pkt_new.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac,ethertype=ether_types.ETH_TYPE_IP))
        for i in range(2,len(pkt_old)):#[ethernet, mpls, ipv4, tcp,..]
            pkt_new.add_protocol(pkt_old[i])
        return pkt_new

#----------------------------Traffic_Finder----------------------------------------
    def _pick_one_path(self, paths): # paths {xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid]}
        path = (paths.keys()[0], paths.values()[0])
        return path # (123,[1,2,3])

    def traffic_find(self, paths): # paths {xxx:[dpid,dpid,dpid],xxx:[dpid,dpid,dpid,dpid]}
        path_num = len(paths)
        if path_num == 1:
            path = (paths.keys()[0],paths.values()[0])
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
                self.path_table = self._get_path_table(self.adjacency_matrix)
                self.pre_install_flow(self.path_table)

    def _update_topology(self):
        switch_list = get_all_switch(self)
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
                all_shortest_paths[(i,j)] = dict()
                for each in nx.all_shortest_paths(g,i,j):
                    try:
                        all_shortest_paths[(i,j)][self.LABEL] = each
                        self.LABEL += 1
                    except nx.NetworkXNoPath:
                        print("CATCH EXCEPTION: nx.NetworkXNoPath")
        return all_shortest_paths

    def pre_install_flow(self, path_table):
        for pair in path_table.keys():
            paths = path_table[pair]
            path_num = len(paths)
            if path_num == 0:
                continue
            for label in paths.keys():
                path = paths[label]
                if len(path) > 2: # if at least host->dpid->dpid->dpid->host, then pre install
                    for i in range(1,len(path)-1):
                        dpid = path[i]
                        priority = self.PRIORITY # 32768 or 0x8000
                        in_port = self.links_dpid_to_port[(path[i-1],path[i])][1]
                        out_port = self.links_dpid_to_port[(path[i],path[i+1])][0]
                        match = {
                                "dl_type":ether_types.ETH_TYPE_MPLS,
                                "in_port":in_port,
                                "mpls_label":label,
                                }
                        actions = [{"type":"OUTPUT","port":out_port}]
                        self.flowDispatcher.add_flow_rest_1(dpid, priority, match, actions)

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

