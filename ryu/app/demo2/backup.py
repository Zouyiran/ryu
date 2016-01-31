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