#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

x = [1,2,3,4,5,6,7,8,9,10]
# reactive
# rtt_all_list = [[23.823, 6.151, 6.116, 6.074, 6.134, 6.122, 6.129, 6.072, 6.105, 6.11], #2
#             [38.439, 10.18, 10.18, 10.12, 10.125, 10.159, 10.199, 10.168, 10.187, 10.198], #4
#             [53.76, 14.255, 14.277, 14.289, 14.25, 14.271, 14.249, 14.227, 14.301, 14.226], #6
#             [72.021, 18.801, 18.265, 18.348, 18.308, 18.401, 18.296, 18.296, 18.35, 18.405], #8
#             [97.179, 22.359, 22.428, 22.419, 22.29, 22.405, 22.521, 22.417, 22.452, 22.423]] #10
#proactive
rtt_all_list = [[16.636, 6.096, 6.108, 6.102, 6.127, 6.087, 6.105, 6.111, 6.119, 6.088], #2
            [28.333, 10.112, 10.156, 10.18, 10.179, 10.188, 10.191, 10.746, 10.165, 10.189], #4
            [40.498, 14.151, 14.163, 14.273, 14.294, 14.24, 14.279, 14.288, 14.199, 14.278], #6
            [53.717, 18.322, 18.717, 18.383, 18.236, 18.225, 18.356, 18.308, 18.304, 18.239], #8
            [64.628, 22.325, 22.283, 22.437, 22.385, 22.473, 22.413, 22.435, 22.367, 22.488]] #10
label_list = ["2 switches", "4 switches","6 switches","8 switches","10 switches"]
color_list = ['green','blue','cyan','yellow','red']
for n in range(len(rtt_all_list)):
    rtt_list = rtt_all_list[n]
    label = label_list[n]
    color = color_list[n]
    plt.plot(x,rtt_list,label=label,color=color)
    plt.plot(x,rtt_list,'o',color=color)
plt.axis([1,10,0,100])
plt.xticks([1,2,3,4,5,6,7,8,9,10])
plt.xlabel("the order of ICMP packets")
plt.ylabel("the RTT of each ICMP packet(ms)")
plt.legend()
plt.show()


