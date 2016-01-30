# -*- coding: utf-8 -*-

import copy
import networkx as nx
import array


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto.ofproto_v1_3 import  OFP_DEFAULT_PRIORITY
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ether_types,mpls
from ryu.topology.api import get_switch, get_all_switch, get_link,get_all_link,get_all_host,get_host

from flow_dispatcher import FlowDispatcher
from traffic_finder import TrafficFinder


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
        self.traffic_finder = TrafficFinder()
        # {dpid:{mac:port,mac:port,...},dpid:{mac:port,mac:port,...},...}
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

        # {(dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid]], (dpid,dpid):[[dpid,dpid,dpid],[dpid,dpid,dpid,dpid]]}
        self.path_table = dict()

        self.SLEEP_PERIOD = 8 #seconds

        self.PRIORITY = OFP_DEFAULT_PRIORITY

        self.flowDispatcher = FlowDispatcher()
        self.dpid_to_dp = dict()
        self.discover_thread = hub.spawn(self.path_find)

        self.ip_to_port = dict()
        self.mac_to_port = dict()
        self.PRIORITY = OFP_DEFAULT_PRIORITY

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
        '''
        msg:
        self.buffer_id = buffer_id
        self.total_len = total_len
        self.reason = reason
        self.table_id = table_id
        self.cookie = cookie
        self.match = match
        self.data = data
        self.datapath = datapath
        self.version = None
        self.msg_type = None # EventOFPPacketIn 10
        self.msg_len = None
        self.xid = None
        self.buf = None
        :param ev:
        :return:
        '''
        msg = ev.msg
        buffer_id = msg.buffer_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_reason = msg.reason
        if in_reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO_MATCH'
        elif in_reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif in_reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID_TTL'
        else:
            reason = 'UNKNOWN'
        in_port = msg.match['in_port']

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)


        pkt = packet.Packet(msg.data) # *data* is a bytearray

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # the topology.switches.Switches can handle the LLDP packet
            # for LLDP working, must --observe-links
            return

        src_mac = eth.src
        dst_mac = eth.dst

        ar = pkt.get_protocol(arp.arp)

#----------------  mpls ----------------
        host_mac = self.hostmac_to_dpid.keys() # [mac, mac, mac,...]
        if not ar and src_mac in host_mac and dst_mac in host_mac:
            print("****************************************host to host**********************************************")
            print("dpid:",dpid)
            for p in pkt:
                print(p)
            print ""
            src_dpid = self.hostmac_to_dpid[src_mac]
            dst_dpid = self.hostmac_to_dpid[dst_mac]
            if src_dpid == dst_dpid:# belong to same dpid
                print("-----------belong to same dpid---------:",dst_dpid)
                out_port = self.hostmac_to_port[dst_mac]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                if buffer_id != ofproto.OFP_NO_BUFFER: # seem has buffer_id
                    self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions, buffer_id)
                    return
                else:
                    self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions)
                data = None
                if buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)
            elif (src_dpid,dst_dpid) in self.path_table.keys(): # must in it, "if" judge is no need
                print("-----------not belong to a same dpid-----------")
                paths = self.path_table[(src_dpid,dst_dpid)]
                path_num = len(paths)
                print("path_n num:",path_num)

                if path_num == 0:# unreachable
                    print(src_mac,"->",dst_mac,": unreachable")
                    return
                elif path_num == 1: # has only one path
                    path = paths[0]
                    print("path:",path)
                else:# several paths
                    # pick a one path,default pick the first path
                    path = paths[0]
                    print("path:",path)

                if len(path) == 2: # src_mac -> dpid_1 -> dpid_2 -> dst_mac
                    print("len(path)==2:",len(path))
                    if dpid == path[0]: # dpid_1
                        out_port = self.links_dpid_to_port[(path[0],path[1])][0]
                    else:# dpid == path[1]: # dpid_2
                        out_port = self.hostmac_to_port[dst_mac]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                    if buffer_id != ofproto.OFP_NO_BUFFER:
                        self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions, buffer_id)
                        return
                    else:
                        self.flowDispatcher.add_flow(datapath, self.PRIORITY, match, actions)
                    data = None
                    if buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)

                elif len(path) > 2: # src_mac -> dpid_1 -> dpid_2 -> dpid_3...-> dst_mac
                    print("len(path)>2:",len(path))
                    if dpid == path[0]: # the first dpid
                        out_port = self.links_dpid_to_port[(path[0],path[1])][0]
                        label_str = ''
                        for i in path:
                            label_str += str(i)
                        print(label_str)
                        mpls_proto = mpls.mpls(label=int(label_str))
                        print("mpls_proto:",mpls_proto)

                        protocol_list = list()
                        for p in pkt:
                            print("protocol_list:",p)
                            protocol_list.append(p) #[ethernet, ipv4, tcp,..]

                        pack = packet.Packet()
                        pack.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac,ethertype=ether_types.ETH_TYPE_MPLS)) #
                        pack.add_protocol(mpls_proto)
                        for i in range(1,len(protocol_list)):
                            pack.add_protocol(protocol_list[i])
                        for p in pack:
                            print("p:",p)
                        pack.serialize()
                        data = pack.data
                        self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)
                    elif dpid == path[-1]: # the last dpid
                        out_port = self.hostmac_to_port[dst_mac]

                        protocol_list = list()
                        for p in pkt:
                            protocol_list.append(p) #[ethernet, mpls, ipv4, tcp,..]

                        pack = packet.Packet()
                        pack.add_protocol(protocol_list[0])
                        for i in range(2,len(protocol_list)):
                            pack.add_protocol(protocol_list[i])
                        pack.serialize()
                        data = pack.data
                        self.flowDispatcher.packet_out(datapath, in_port, out_port, data, None)
                    else:
                        print("not path[0] and not path[-1], so this is a BUG!!!")
            return
#----------------  mpls ----------------

#---------------- mac learning ----------------
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        # for dpid in self.mac_to_port:
        #     print("dpid:",dpid)
        #     for each in self.mac_to_port[dpid]:
        #         print("mac:",each,"->","port:",self.mac_to_port[dpid][each])

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
#---------------- mac learning ----------------


#----------------  arp ip learning ----------------
        # for p in pkt.protocols:# p is a object of ryu.lib.packet.ethernet.ethernet
        #     if hasattr(p,'protocol_name'):
        #         proto_name = p.protocol_name
        #         if proto_name == 'arp':
        #             print("*****arp*********")
        #         if proto_name == 'tcp':
        #             print("*******tcp*******")
        #         print(proto_name)
                # if proto_name == 'arp':
                #     print('........arp.......')
                # if proto_name == "icmp":
                #     print('........icmp.......')

                    # src_ip = p.src_ip #p.src_ip
                    # print("src_ip:",src_ip)
                    # dst_ip = p.dst_ip #p.dst_ip
                    # print("dst_ip:",dst_ip)
                    # self.ip_to_port.setdefault(dpid, {})
                    # self.ip_to_port[dpid][src_ip] = in_port
                    # if dst_ip in self.ip_to_port[dpid]:
                    #     out_port = self.ip_to_port[dpid][dst_ip]
                    # else:
                    #     out_port = ofproto.OFPP_FLOOD
                    # for dpid in self.ip_to_port:
                    #     print("dpid:",dpid)
                    #     for each in self.ip_to_port[dpid]:
                    #         print("ip:",each,"->","port:",self.ip_to_port[dpid][each])
                    # actions = [{"type":"OUTPUT","port":out_port}]
                    #
                    # if out_port != ofproto.OFPP_FLOOD:
                    #     match = {
                    #             "in_port":in_port,
                    #             },
                    #     if buffer_id != ofproto.OFP_NO_BUFFER:
                    #         print("no_buffer")
                    #         self.flowDispatcher.add_flow_rest_2(dpid, 222, match, actions, buffer_id)
                    #         return
                    #     else:
                    #         self.flowDispatcher.add_flow_rest_2(dpid, 222, match, actions,ofproto.OFP_NO_BUFFER)
                    #
                    # data = None
                    # if buffer_id == ofproto.OFP_NO_BUFFER:
                    #     data = msg.data
                    # self.flowDispatcher.packet_out(datapath, in_port, out_port, data, buffer_id)
#----------------  arp ip learning ----------------


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

#----------------------------Traffic_Finder------------------------------------
    def traffic_find(self,ev):
        pass




#----------------------------Path_Finder----------------------------------------
    def path_find(self):
        while True:
            hub.sleep(self.SLEEP_PERIOD)
            self.pre_adjacency_matrix = copy.deepcopy(self.adjacency_matrix)
            self._update_topology()
            self._update_hosts() # TODO
            # when adjacency matrix is update,then update the path_table
            if self.pre_adjacency_matrix != self.adjacency_matrix:
                self.logger.info('***********discover_topology thread: TOPO  UPDATE***********')
                self.path_table = self._get_path_table(self.adjacency_matrix)
                self.pre_install_flow(self.path_table)

    def pre_install_flow(self, path_table):
        for pair in path_table.keys():
            paths = path_table[pair] # [[],[],[],...]
            path_num = len(paths)
            if path_num == 0: # unreachable
                pass
            elif path_num == 1: # have only one path
                path = paths[0]
                # mpls_label_str = ''
                # for i in path:
                #     mpls_label_str += str(i)
                #
                # if len(path) == 2:
                #     pass
                # else:
                #     for i in range(1,len(path)-1):
                #         dpid = path[i]
                #         priority = self.PRIORITY
                #         port_pair_1 = self.links_dpid_to_port[(path[i-1],path[i])]
                #         in_port = port_pair_1[1]
                #         port_pair_2 = self.links_dpid_to_port[(path[i],path[i+1])]
                #         out_port = port_pair_2[0]
                #         match = {
                #                 "dl_type":ether_types.ETH_TYPE_MPLS,
                #                 "in_port":in_port,
                #                 "mpls_label":int(mpls_label_str),
                #                 "mpls_tc":5,
                #                 "mpls_bos":1
                #                 }
                #         actions = [{"type":"OUTPUT","port":out_port}]
                #         self.flowDispatcher.add_flow_rest_1(dpid, priority, match, actions)
            else: # have several paths
                path = paths[0]
            if len(path) == 2:
                pass
            else:
                mpls_label_str = ''
                for i in path:
                    mpls_label_str += str(i)
                for i in range(1,len(path)-1):
                    dpid = path[i]
                    priority = self.PRIORITY
                    port_pair_1 = self.links_dpid_to_port[(path[i-1],path[i])]
                    in_port = port_pair_1[1]
                    port_pair_2 = self.links_dpid_to_port[(path[i],path[i+1])]
                    out_port = port_pair_2[0]
                    match = {
                            "dl_type":ether_types.ETH_TYPE_MPLS,
                            "in_port":in_port,
                            "mpls_label":int(mpls_label_str),
                            }
                    actions = [{"type":"OUTPUT","port":out_port}]
                    self.flowDispatcher.add_flow_rest_1(dpid, priority, match, actions)

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
                all_shortest_paths[(i,j)] = list()
                for each in nx.all_shortest_paths(g,i,j):
                    try:
                        all_shortest_paths[(i,j)].append(each)
                    except nx.NetworkXNoPath:
                        print("CATCH EXCEPTION: nx.NetworkXNoPath")
        return all_shortest_paths

    # def _get_traffic_table(self, path_table):
    #     traffic_table = dict()
    #     for src_host in self.hosts: # mac
    #         for dst_host in self.hosts: # mac
    #             if src_host == dst_host:
    #                 continue
    #             src_dpid = self.hostmac_to_dpid[src_host]
    #             dst_dpid = self.hostmac_to_dpid[dst_host]
    #             if src_dpid == dst_dpid: # belongs to a same dpid
    #                 traffic_table[(src_host, dst_host)]  = [src_dpid]
    #             elif (src_dpid, dst_dpid) in path_table.keys():
    #                 traffic_table[(src_host, dst_host)]  = path_table[(src_dpid, dst_dpid)][0]
    #             else: # unreachable
    #                 traffic_table[(src_host, dst_host)]  = []
    #     return traffic_table

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

