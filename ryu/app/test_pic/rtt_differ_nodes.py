#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
rtt with differ nodes
plot for:latency for different number of switches
'''

x = [1,2,3,4,5,6,7]
# rtt_re = [[24.4, 6.096, 6.108, 6.102, 6.127, 6.087, 6.105, 6.111, 6.119, 6.088], #2
#             [40.6, 10.112, 10.156, 10.18, 10.179, 10.188, 10.191, 10.146, 10.165, 10.189], #4
#             [60.1, 14.151, 14.163, 14.273, 14.294, 14.24, 14.279, 14.288, 14.199, 14.278], #6
#             [70.0, 18.322, 18.317, 18.383, 18.236, 18.225, 18.356, 18.308, 18.304, 18.239], #8
#             [94.0, 22.325, 22.283, 22.437, 22.385, 22.473, 22.413, 22.435, 22.367, 22.488]] #10
# rtt_pro = [[16.636, 6.096, 6.108, 6.102, 6.127, 6.087, 6.105, 6.111, 6.119, 6.088], #2
#             [28.333, 10.112, 10.156, 10.18, 10.179, 10.188, 10.191, 10.746, 10.165, 10.189], #4
#             [40.498, 14.151, 14.163, 14.273, 14.294, 14.24, 14.279, 14.288, 14.199, 14.278], #6
#             [53.717, 18.322, 18.717, 18.383, 18.236, 18.225, 18.356, 18.308, 18.304, 18.239], #8
#             [64.628, 22.325, 22.283, 22.437, 22.385, 22.473, 22.413, 22.435, 22.367, 22.488]] #10
rtt_re = [
        [12.0, 6.32, 6.18, 6.15, 6.14, 6.13, 6.12], #2
        [19.0, 10.4, 10.2, 10.2, 10.2, 10.1, 10.1], #4
        [24.0, 14.5, 14.4, 14.3, 14.3, 14.2, 14.2], #6
        [30.1, 19.2, 18.6, 18.4, 18.3, 18.3, 18.2], #8
        [35.5, 22.6, 22.5, 22.4, 22.4, 22.3, 22.3]] #10

rtt_pro = [
            [6.49, 6.16, 6.15, 6.14, 6.14, 6.13, 6.13], #2
            [10.9, 10.2, 10.2, 10.2, 10.2, 10.2, 10.2], #4
            [15.2, 14.3, 14.3, 14.3, 14.2, 14.2, 14.2], #6
            [19.7, 18.4, 18.4, 18.4, 18.3, 18.3, 18.3], #8
            [24.4, 22.5, 22.5, 22.5, 22.4, 22.4, 22.4]] #10

label_list = ["2 switches", "4 switches","6 switches","8 switches","10 switches"]
style_list = ['o','^','x','s','*']
# plt.figure(figsize=(8, 4))
plt.subplot(121)
for n in range(len(rtt_re)):
    rtt_list = rtt_re[n]
    label = label_list[n]
    style = style_list[n]
    plt.plot(x,rtt_list,"k-"+style,label=label)
plt.axis([1,7,0,40])
plt.xticks([1,2,3,4,5,6,7])
plt.xlabel("the order of packets", fontsize=15)
plt.ylabel("the RTT of each packet(ms)", fontsize=15)
plt.title("(A) contain Extra Latency", fontsize=15)
plt.legend()

plt.subplot(122)
for n in range(len(rtt_pro)):
    rtt_list = rtt_pro[n]
    label = label_list[n]
    style = style_list[n]
    plt.plot(x,rtt_list,"k-"+style,label=label)
plt.axis([1,7,0,40])
plt.xticks([1,2,3,4,5,6,7])
plt.xlabel("the order of  packets", fontsize=15)
plt.ylabel("the RTT of each packet(ms)", fontsize=15)
plt.title("(B) no Extra Latency", fontsize=15)
plt.legend()
plt.show()




