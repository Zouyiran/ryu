# -*- coding: utf-8 -*-
#TODO implement a lower latency app
'''
ofp_event.EventOFPSwitchFeature and EventOFPPacketIn
path_table and traffic_table
'''

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3



class LowLatency(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LowLatency,self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
        get each switch feature
        calculate path table of each switches pair, which 'may' need to use Networkx and topology
        dynamic processing to update the path table
        :param ev:
        :return:
        '''
        pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
        calculate traffic table of each hosts pair, which need to use the result_backup of the path table
        :param ev:
        :return:
        '''
        pass
