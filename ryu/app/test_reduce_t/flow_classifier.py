#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np

class FlowClassifier(object):
    def __init__(self):
        super(FlowClassifier, self).__init__()
        self.active_sample = dict()
        self.data = [  [1, 3, 230, 0], [2, 96, 6336, 6], [2, 94, 277132, 8], [4, 87, 267934, 1], [4, 86, 5676, 1],
                       [2, 73, 267018, 10], [2, 98, 268660, 8], [2, 12, 12424, 0], [1, 28, 1868, 1], [2, 202, 2897012, 6],
                       [1, 29, 133018, 8], [2, 90, 5940, 0], [1, 30, 133084, 5], [1, 28, 1856, 5], [4, 16, 1184, 4],
                       [2, 109, 269390, 6], [1, 1, 74, 2], [1, 0, 0, 0], [5, 271, 763334, 2], [4, 0, 0, 0],
                       [4, 208, 538096, 6], [11, 590, 956516, 4], [4, 556, 6852464, 3], [3, 110, 269440, 0], [2, 107, 138178, 0],
                       [5, 267, 673170, 4], [11, 579, 562522, 4], [2, 100, 6592, 2], [2, 1, 74, 0], [9, 377, 942530, 0],
                       [7, 273, 673482, 0], [5, 60, 4028, 1], [4, 161, 403914, 0], [6, 222, 538988, 0], [10, 323, 545726, 0],
                       [2, 101, 6698, 0], [3, 104, 6872, 0], [9, 318, 283164, 0], [4, 204, 13448, 1], [4, 171, 11274, 0],
                       [6, 296, 19568, 0], [4, 210, 13964, 6], [2, 102, 268940, 7], [1, 3, 222, 2], [3, 108, 269272, 0],
                       [2, 106, 7020, 8], [1, 1, 66, 0], [3, 165, 404110, 2], [3, 162, 403968, 6], [4, 203, 13398, 1],
                       [1, 56, 134744, 12], [1, 52, 134536, 1], [1, 55, 134602, 10], [2, 110, 269420, 8], [4, 208, 538096, 4],
                       [2, 102, 6724, 7], [4, 199, 13150, 2], [6, 303, 19966, 2], [3, 154, 10660, 2], [6, 327, 808118, 8],
                       [7, 271, 673342, 0], [4, 556, 298896, 3], [4, 53, 134610, 0], [6, 307, 20246, 0], [5, 255, 16810, 7],
                       [2, 54, 134656, 0], [4, 209, 538186, 2], [1, 55, 3658, 12], [4, 199, 13114, 0], [4, 54, 134676, 0],
                       [5, 256, 16888, 1], [1, 53, 3510, 9], [6, 255, 16810, 0], [6, 325, 807990, 1], [5, 253, 16682, 1],
                       [4, 161, 401934, 0], [4, 202, 13340, 6], [4, 206, 538012, 7], [4, 214, 538504, 2], [2, 102, 6724, 0],
                       [4, 107, 269278, 0], [6, 324, 807956, 1], [4, 105, 269162, 0], [2, 52, 134536, 0], [1, 54, 134676, 9],
                       [2, 0, 0, 0], [2, 101, 6670, 0], [4, 203, 13394, 0], [4, 198, 496172, 1], [3, 52, 3456, 1],
                       [4, 222, 539020, 6], [2, 112, 269568, 9], [1, 50, 3288, 9], [4, 202, 13332, 5], [4, 152, 10032, 0],
                       [3, 146, 9612, 6], [6, 305, 806762, 0], [8, 1, 74, 0], [1, 52, 134528, 5], [2, 99, 6530, 7],
                       [4, 208, 284632, 5], [4, 196, 12888, 7], [4, 209, 538242, 5], [4, 198, 537500, 5], [4, 199, 537534, 4],
                       [1, 51, 3414, 5], [8, 9, 546, 1], [3, 150, 272068, 6], [3, 55, 134722, 1], [8, 204, 537880, 0],
                       [2, 59, 137898, 7]]

        self.target = [  0, 0, 0, 0, 1,
                         0, 0, 0, 0, 0,
                         0, 1, 0, 0, 1,
                         0, 0, 0, 0, 1,
                         0, 1, 0, 0, 0,
                         0, 1, 0, 0, 1,
                         1, 1, 0, 1, 1,
                         0, 1, 1, 1, 1,
                         1, 0, 0, 0, 0,
                         0, 0, 0, 0, 1,
                         0, 0, 0, 0, 0,
                         0, 1, 1, 0, 0,
                         1, 0, 0, 1, 0,
                         0, 0, 0, 1, 0,
                         1, 0, 1, 1, 1,
                         0, 0, 0, 0, 0,
                         0, 1, 0, 0, 0,
                         1, 0, 1, 0, 0,
                         0, 0, 0, 0, 1,
                         0, 1, 1, 0, 0,
                         0, 0, 0, 0, 0,
                         0, 1, 0, 0, 1,
                         0]

    def create_sample(self, dpid_to_flow):
        '''
        # {'nw_dst': u'10.0.0.2', 'byte_count': 54, 'duration_sec': 2,
        'packet_count': 1, 'idle_timeout': 10, 'nw_src': u'10.0.0.10'},
        :param dpid_to_flow:
        :return:
        '''
        active_sample = dict()
        for dpid in dpid_to_flow:
            for flow in dpid_to_flow[dpid]:
                src_ip = flow["nw_src"]
                dst_ip = flow["nw_dst"]
                active_sample.setdefault((src_ip, dst_ip),[0,0,0,float('inf')])
                # flow count
                active_sample[(src_ip,dst_ip)][0] += 1
                # packet count
                active_sample[(src_ip,dst_ip)][1] += int(flow["packet_count"])
                # byte count
                active_sample[(src_ip,dst_ip)][2] += int(flow["byte_count"])
                # duration
                duration = int(flow["duration_sec"])
                if duration < active_sample[(src_ip,dst_ip)][3]:
                    active_sample[(src_ip,dst_ip)][3] = duration
        return active_sample

    def get_data(self, data):
        data_array = np.asarray(data)
        return data_array

    def get_target(self,target):
        target_array = np.asarray(target)
        return target_array

#     def select_module(self, sample, target, kernel, scoring=None, k=10):
#         scores = list()
#         scores_std = list()
#         # sample_num = len(sample)
#         # kflod = cross_validation.KFold(sample_num, n_folds=k)
#         if kernel == "linear":
#             svc = svm.SVC(kernel="linear")
#             c_list = [1e-1, 1, 1e1]
#             for c in c_list:
#                 svc.C = c
#                 this_scores = cross_validation.cross_val_score(svc, sample, target, scoring=scoring, cv=k)
#                 scores.append(np.mean(this_scores))
#                 scores_std.append(np.std(this_scores))
#         if kernel == "rbf":
#             c_list = [1e-1, 1, 1e1]
#             gamma_list = [1e-1, 1, 1e1]
#             for c in c_list:
#                 for gamma in gamma_list:
#                     svc = svm.SVC(kernel="rbf", C=c, gamma=gamma)
#                     this_scores = cross_validation.cross_val_score(svc, sample, target, scoring=scoring, cv=k)
#                     scores.append(np.mean(this_scores))
#                     scores_std.append(np.std(this_scores))
#         return scores, scores_std
#
if __name__ == "__main__":
    classify = FlowClassifier()
    num = len(classify.data)
    count = 0
    for i in range(num):
        if classify.target[i] == 1:
            count += 1
    print 'count 1:',count




