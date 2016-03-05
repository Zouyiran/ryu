#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
plot for:pre_install_app(no Extra Latency) and react_install_app(contain Extra Latency)
'''

x = [1,2,3,4,5]
simple = [42.35,74.9,98.01,121.5,158.6]
pre_install = [36.78,58.53,78.81,92.55,109.81]

plt.plot(x,simple,label="contain Extra Latency",color="red")
plt.plot(x,simple,'o',color="red")
plt.plot(x,pre_install,label="no Extra Latency",color="blue")
plt.plot(x,pre_install,'o',color="blue")
plt.axis([0,5,0,200])
plt.xticks([0,1,2,3,4,5,6])
plt.xlabel("the number of switch nodes")
plt.ylabel("the RTT of the 1st packet(ms)")
plt.legend()
plt.show()


