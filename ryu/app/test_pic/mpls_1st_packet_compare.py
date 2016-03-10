#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
1st packet rtt compare
plot for:pre_install_app(no Extra Latency) and react_install_app(contain Extra Latency)
'''

x = [3,4,5,6,7,8,9]
other_packet = [6.17, 8.18, 10.2, 12.2, 14.2, 16.3, 18.4, 20.4]

# ---contain arp---
simple =      [ 74.5, 85.1, 103.5, 115, 129, 142, 155] #58.3,
pre_install = [ 57.1, 68.6, 87.6, 100, 110, 122, 135]

# ---not contain arp---
# simple = [6.16+5.4, 8.18+8.1, 10.0+9.3, 12.2+10.4, 14.3+11.8, 16.3+15.8, 18.3+18.8, 20.3+22.4]
# simple = [11.56, 16.28, 19.3, 22.6, 26.1, 32.1, 37.1, 42.7]
# pre_install = [6.16, 8.18, 10.2, 12.2, 14.3, 16.3, 18.3, 20.3]

plt.plot(x,simple,"k-^",label="reactive")
plt.plot(x,pre_install,"k-*",label="pre-install")
plt.axis([1,10,0,200])
plt.xticks([3,4,5,6,7,8,9])
plt.xlabel("the number of switch nodes", fontsize=16)
plt.ylabel("the latency of the 1st packet(ms)", fontsize=16)
plt.legend()
plt.show()


