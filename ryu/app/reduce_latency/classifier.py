#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize

from sklearn.svm import SVC
from sklearn.model_selection import KFold

# from sklearn.model_selection import
'''
class Flow(object):
    def __init__(self):
        super(Flow, self).__init__()
        self.idle_timeout = 0
        self.packet_count = 0
        self.byte_count = 0
        self.duration_sec = 0
        self.src_ip = ""
        self.dst_ip = ""
        self.src_tcp = ""
        self.dst_tcp = ""
'''


class Classifier(object):
    def __init__(self):
        super(Classifier, self).__init__()
        self.id_to_sample = dict()
        self.data = None
        self.target = None
        self.N_FLOW = 500
        self.N_PAKCET = 1000
        self.T_IDLE = 5

    def create_sample(self, dpid_to_flow):
        id_to_sample = dict() #{dpid:[n_flow, n_packet, t_idle],...}
        sample = list()
        for dpid in dpid_to_flow: # each access dpid
            for flow in dpid_to_flow[dpid]:# each Flow
                src_ip = flow.src_ip
                dst_ip = flow.dst_ip
                id_to_sample.setdefault((src_ip, dst_ip),[0,0,float('inf')]) # initial [n_flow, n_packet, t_idle]
                id_to_sample[(src_ip,dst_ip)][0] += 1
                id_to_sample[(src_ip,dst_ip)][1] += flow.packet_count
                idle = flow.idle_timeout
                if idle < id_to_sample[(src_ip,dst_ip)][2]:
                    id_to_sample[(src_ip,dst_ip)][2] = idle
        for each in id_to_sample:
            id_to_sample[each][0] /= 2
            id_to_sample[each][1] /= 2
            sample.append(id_to_sample[each])
        return id_to_sample, sample # list

    def create_target(self, sample):
        target = list()
        for each in sample:
            if each[0]>self.N_FLOW and each[1]>self.N_PAKCET and each[2]<self.T_IDLE:
                target.append(1) # alive
            else:
                target.append(0) # not alive
        return target # list

    def training(self, sample, target):
        C = 1 #[1e-2, 1, 1e2]
        gamma = 1e-1#[1e-1, 1, 1e1]
        clf = SVC(C=C, gamma=gamma)
        clf.fit(sample, target)
        return clf


    def cross_verify(self, sample, target, k=10):
        module_list = list()
        kFlod = KFold(n_folds=10)
        for train_index, test_index in kFlod.split(sample):
            train_sample = list()
            train_target = list()
            test_sample = list()
            test_target = list()
            for i in train_index:
                train_sample.append(sample[i])
                train_target.append(target[i])
            module = self.training(np.array(train_sample),np.array(train_target))
            module_list.append(module)
            for i in test_index:
                test_sample.append(sample[i])
                test_target.append(target[i])
            test_result = module.predict(np.array(test_sample))
        # verify_num = len(sample)/k
        # for i in range(k):
        #     if i == 0:
        #         verify_sample = sample[:verify_num]
        #         verify_target = target[:verify_num]
        #         sample_sample = sample[verify_num:]
        #         sample_target = target[verify_num:]
        #     elif i == k-1:
        #         verify_sample = sample[i*verify_num:]
        #         verify_target = target[i*verify_num:]
        #         sample_sample = sample[:i*verify_num]
        #         sample_target = target[:i*verify_num]
        #     else:
        #         verify_sample = sample[i*verify_num:(i+1)*verify_num]
        #         verify_target = target[i*verify_num:(i+1)*verify_num]
        #         sample_sample = sample[:i*verify_num]+sample[(i+1)*verify_num:]
        #         sample_target = target[:i*verify_num]+target[(i+1)*verify_num:]
        #     module = self.training(sample_sample,sample_target)
        #     module_target = module.predict(verify_sample)




    def get_module(self):
        #grid search
        pass