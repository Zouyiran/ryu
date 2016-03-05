#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
plot for:pre_install_mpls and not_install_mpls
'''

x = [2,3,4,5,6,7,8,9]
latency_list = [[55.2, 58.7, 71.1, 86.6, 101, 110, 123, 138],
                [60.0, 71.3, 84.7, 102, 111, 128,  140, 159]]
label_list = ["pre-install mpls label", "no mpls label"]
color_list = ['red','blue']
for n in range(len(latency_list)):
    rtt_list = latency_list[n]
    label = label_list[n]
    color = color_list[n]
    plt.plot(x,rtt_list,label=label,color=color)
    plt.plot(x,rtt_list,'s',color=color)
plt.axis([0,10,0,200])
plt.xticks([0,1,2,3,4,5,6,7,8,9,10])
plt.xlabel("the number of switches")
plt.ylabel("the average RTT of the 1st packet(ms)")
plt.legend()
plt.show()


