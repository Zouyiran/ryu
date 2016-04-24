#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gflags
import socket

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib.xflow import sflow

'''
sFlow demo, found in tech website
'''

FLAGS = gflags.FLAGS
gflags.DEFINE_string('sflow_listen_host', '', 'sflow listen host')
gflags.DEFINE_integer('sflow_listen_port', 6343, 'sflow listen port')
BUFSIZE = 65535

class sFlowCollector(app_manager.RyuApp):
     def __init__(self):
         super(sFlowCollector, self).__init__()
         self.is_active = True
         self._start_recv()

     def close(self):
         self.is_active = False
         hub.joinall([self.thread])

     def _start_recv(self):
         self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         self.sock.bind((FLAGS.sflow_listen_host, FLAGS.sflow_listen_port))
         self.thread = hub.spawn(self._recv_loop)

     def _recv_loop(self):
         self.logger.info('== sflow recv_loop start. ==')
         while self.is_active:
             (data, addrport) = self.sock.recvfrom(BUFSIZE)
             msg = sflow.sFlow.parser(data)
             if msg:
                 # debug print
                 self.logger.info(msg.__dict__)