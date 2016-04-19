#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize

from sklearn import svm, cross_validation, datasets

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


class FlowClassifier(object):
    def __init__(self):
        super(FlowClassifier, self).__init__()
        self.active_sample = dict()
        self.data = None
        self.target = None
        self.N_FLOW = 500
        self.N_PAKCET = 1000
        self.T_IDLE = 5

    def create_sample(self, dpid_to_flow): # {'nw_dst': u'10.0.0.2', 'byte_count': 54, 'duration_sec': 2, 'packet_count': 1, 'idle_timeout': 10, 'nw_src': u'10.0.0.10'},
        for dpid in dpid_to_flow:
            for flow in dpid_to_flow[dpid]:
                src_ip = flow["nw_src"]
                dst_ip = flow["nw_dst"]
                self.active_sample.setdefault((src_ip, dst_ip),[0,0,0]) # initial
                self.active_sample[(src_ip,dst_ip)][0] += 1
                self.active_sample[(src_ip,dst_ip)][1] += int(flow["packet_count"])
                duration = int(flow["duration_sec"])
                if duration > self.active_sample[(src_ip,dst_ip)][2]:
                    self.active_sample[(src_ip,dst_ip)][2] = duration
        # for each in self.active_sample:
        #     self.active_sample[each][0] /= 2.0
        #     self.active_sample[each][1] /= 2.0


    def create_target(self, sample):
        target = list()
        for each in sample:
            if each[0]>self.N_FLOW and each[1]>self.N_PAKCET and each[2]<self.T_IDLE:
                target.append(1) # alive
            else:
                target.append(0) # not alive
        return target # list

    def select_module(self, sample, target, kernel, scoring=None, k=10):
        scores = list()
        scores_std = list()
        # sample_num = len(sample)
        # kflod = cross_validation.KFold(sample_num, n_folds=k)
        if kernel == "linear":
            svc = svm.SVC(kernel="linear")
            c_list = [1e-1, 1, 1e1]
            for c in c_list:
                svc.C = c
                this_scores = cross_validation.cross_val_score(svc, sample, target, scoring=scoring, cv=k)
                scores.append(np.mean(this_scores))
                scores_std.append(np.std(this_scores))
        if kernel == "rbf":
            c_list = [1e-1, 1, 1e1]
            gamma_list = [1e-1, 1, 1e1]
            for c in c_list:
                for gamma in gamma_list:
                    svc = svm.SVC(kernel="rbf", C=c, gamma=gamma)
                    this_scores = cross_validation.cross_val_score(svc, sample, target, scoring=scoring, cv=k)
                    scores.append(np.mean(this_scores))
                    scores_std.append(np.std(this_scores))
        return scores, scores_std

if __name__ == "__main__":
    classify = FlowClassifier()
    iris = datasets.load_iris()
    sample = iris.data
    target = iris.target
    scores, scores_std = classify.select_module(sample,target,'rbf',None, 10)
    print "scores mean:"
    print scores
    print "scores std:"
    print scores_std

