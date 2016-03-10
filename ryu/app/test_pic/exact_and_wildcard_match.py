#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
plot for:install_exact_app(exact match rule) and install_wildcard_app(wildcard match rule)
'''

x = [100,500,1000,1500,2000,3000,4000]
latency_list = [[4.32,9.23,18.44,30.35,70.22,160.44,220.55],
                [2.22, 4.32, 6.34, 7.54, 8.34, 10.12, 11.89]
                ]
label_list = ["exact match rule", "wildcard match rule"]
style_list = ['s','*']

plt.plot(x,latency_list[0],"k-"+style_list[0],label=label_list[0])
plt.plot(x,latency_list[1],"k-"+style_list[1],label=label_list[1])
plt.axis([0,5000,0,300])
plt.xticks([100,500,1000,1500,2000,3000,4000])
plt.xlabel("packet send rate(packet number/s)", fontsize=16)
plt.ylabel("the average latency(ms)", fontsize=16)
plt.legend()
plt.show()


