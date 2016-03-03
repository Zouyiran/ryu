#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
plot for:install_exact_app(exact match rule) and install_wildcard_app(wildcard match rule)
'''

x = [100,500,1000,1500,2000,3000,4000]
latency_list = [[2.22, 4.32, 6.34, 7.54, 8.34, 10.12, 11.89],
                [4.32,9.23,18.44,30.35,70.22,160.44,220.55]]
label_list = ["exact match rule", "wildcard match rule"]
color_list = ['red','blue']
for n in range(len(latency_list)):
    rtt_list = latency_list[n]
    label = label_list[n]
    color = color_list[n]
    plt.plot(x,rtt_list,label=label,color=color)
    plt.plot(x,rtt_list,'o',color=color)
plt.axis([0,5000,0,300])
plt.xticks([100,500,1000,1500,2000,3000,4000])
plt.xlabel("packet send rate(packet number/s)")
plt.ylabel("the avarage latency(ms)")
plt.legend()
plt.show()


