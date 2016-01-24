from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet
from time import sleep

class MPLS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    NEC_TABLE_NORMAL1 = 0
    NEC_TABLE_EXPANDED = 1
    NEC_TABLE_NORMAL2 = 20
    NEC_TABLE_MPLS1 = 50
    NEC_TABLE_MPLS2 = 51
    NEC_TABLE_SOFTWARE = 99

    OVS_TABLE_MPLS1 = 0
    OVS_TABLE_MPLS2 = 1

    def __init__(self, *args, **kwargs):
        super(MPLS, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            [
                parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER,
                    ofproto.OFPCML_NO_BUFFER)
            ])]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=parser.OFPMatch(),
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.info("packet in dpid:%s port:%s table:%s %s->%s -- %s", datapath.id, in_port, msg.table_id, eth.src, eth.dst, pkt)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            sleep(1)

            if ev.dp.id == 0x000158c232e8b2be:
                self.logger.info("Connection by NEC PF5240")
                self._nec_pf5240_connect(ev)
            elif ev.dp.id == 0x5e3e2c600c457a2f:
                self.logger.info("Connection by Quanta")
                # self._quanta_connect(ev)
            else:
                self.logger.warn("Connection by unknown dpid %s", ev.dp.id)


    def _nec_pf5240_connect(self, ev):
        log_prefix = "pf5240"

        datapath = ev.dp
        parser = datapath.ofproto_parser
        self._empty_table(datapath, self.NEC_TABLE_MPLS1)
        self.logger.warn("%s --- start pushing flowmod to table mpls1", log_prefix)
        # MPLS1 (this one works)
        mod_mpls1 = parser.OFPFlowMod(datapath=datapath,
                                priority=65000,
                                match=parser.OFPMatch(
                                    eth_dst='00:30:96:e6:fc:39',
                                    eth_type=ether.ETH_TYPE_MPLS,
                                ),
                                table_id=self.NEC_TABLE_MPLS1,
                                instructions=[parser.OFPInstructionGotoTable(self.NEC_TABLE_MPLS2)],
                                )
        datapath.send_msg(mod_mpls1)
        sleep(0.5)
        self.logger.warn("%s --- done  pushing flowmod to table mpls1", log_prefix)

        # MPLS2 (this one DOES NOT work)
        self._empty_table(datapath, self.NEC_TABLE_MPLS2)
        self.logger.warn("%s --- start pushing flowmod to table mpls2 (this usually fails..)", log_prefix)
        mod_mpls2 = parser.OFPFlowMod(datapath=datapath,
                                priority=1000,
                                match=parser.OFPMatch(
                                    in_port=1,
                                    eth_type=ether.ETH_TYPE_MPLS,
                                    mpls_label=29,
                                    mpls_bos=1),
                                table_id=self.NEC_TABLE_MPLS2,
                                instructions=[
                                    parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS,
                                                                 [
                                                                     parser.OFPActionPopMpls(ether.ETH_TYPE_IP),
                                                                     parser.OFPActionDecNwTtl(),
                                                                 ]),
                                    parser.OFPInstructionWriteMetadata(0xc00000a0, 0xffffffff),
                                    parser.OFPInstructionGotoTable(self.NEC_TABLE_NORMAL1)
                                ],
                                )
        datapath.send_msg(mod_mpls2)


        sleep(0.5)
        self.logger.warn("%s --- done  pushing flowmod to table mpls2", log_prefix)

        # normal1
        self._empty_table(datapath, self.NEC_TABLE_NORMAL1)
        self.logger.warn("%s --- start pushing flowmod to table normal1", log_prefix)
        mod_normal1 = parser.OFPFlowMod(datapath=datapath,
                                priority=1,
                                table_id=self.NEC_TABLE_NORMAL1,
                                match=parser.OFPMatch(
                                    eth_type=ether.ETH_TYPE_IP
                                ),
                                instructions=[
                                    parser.OFPInstructionActions(
                                        datapath.ofproto.OFPIT_APPLY_ACTIONS,
                                        [parser.OFPActionOutput(2)]
                                    ),
                                ],
                                )
        datapath.send_msg(mod_normal1)
        # mod_normal1_to_mpls = parser.OFPFlowMod(datapath=datapath,
        #                         priority=1000,
        #                         match=parser.OFPMatch(
        #                             eth_type=ether.ETH_TYPE_MPLS
        #                         ),
        #                         table_id=self.NEC_TABLE_NORMAL1,
        #                         instructions=[
        #                             parser.OFPInstructionGotoTable(self.NEC_TABLE_MPLS1)
        #                         ],
        #                         )
        # datapath.send_msg(mod_normal1_to_mpls)
        sleep(0.5)
        self.logger.warn("%s --- done  pushing flowmod to table normal1", log_prefix)




    def _quanta_connect(self, ev):
        log_prefix = "quanta"

        datapath = ev.dp
        parser = datapath.ofproto_parser
        self.logger.warn("%s --- start pushing flowmod to table mpls1", log_prefix)
        # MPLS1 (this one works)
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=1,
                                match=parser.OFPMatch(eth_type=ether.ETH_TYPE_MPLS),
                                table_id=self.OVS_TABLE_MPLS1,
                                instructions=[parser.OFPInstructionGotoTable(self.OVS_TABLE_MPLS2)],
                                )
        datapath.send_msg(mod)
        sleep(0.5)
        self.logger.warn("%s --- done  pushing flowmod to table mpls1", log_prefix)

        # MPLS2 (this one DOES NOT work)
        self.logger.warn("%s --- start pushing flowmod to table mpls2 (this usually fails..)", log_prefix)
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=1,
                                match=parser.OFPMatch(eth_type=ether.ETH_TYPE_MPLS, mpls_label=29, mpls_bos=1),
                                table_id=self.OVS_TABLE_MPLS2,
                                instructions=[
                                    parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS,
                                                                 [
                                                                     parser.OFPActionPopMpls(ether.ETH_TYPE_IP),
                                                                     parser.OFPActionDecNwTtl(),
                                                                     parser.OFPActionOutput(2),
                                                                 ]),
                                ],
                                )
        datapath.send_msg(mod)
        sleep(0.5)
        self.logger.warn("%s --- done  pushing flowmod to table mpls2", log_prefix)

    def _empty_table(self, datapath, table_id):
        self.logger.warn(" --- deleting flow entries in table %s", table_id)
        datapath.send_msg(
            datapath.ofproto_parser.OFPFlowMod(
                datapath,
                0,
                0,
                table_id,
                datapath.ofproto.OFPFC_DELETE,
                0,
                0,
                1,
                datapath.ofproto.OFPCML_NO_BUFFER,
                datapath.ofproto.OFPP_ANY,
                datapath.ofproto.OFPG_ANY,
                0,
                datapath.ofproto_parser.OFPMatch(),
                []
            )
        )