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
    classify = Classifier()
    iris = datasets.load_iris()
    sample = iris.data
    target = iris.target
    scores, scores_std = classify.select_module(sample,target,'rbf',None, 10)
    print "scores mean:"
    print scores
    print "scores std:"
    print scores_std

