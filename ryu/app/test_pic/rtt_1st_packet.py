#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
1st packet rtt compare
plot for:pre_install_app(no Extra Latency) and react_install_app(contain Extra Latency)
'''

x = [2,3,4,5,6,7,8,9,10]

# # ---contain arp---
# # simple =      [22.4, 30.8, 39.4, 46.2, 52.1, 62.0, 71.2, 79.5]
# # pre_install = [17.0, 22.7, 30.1, 35.6, 40.3, 46.2, 52.4, 57.1]
#
# # ---not contain arp---
# # simple = [6.16+5.4, 8.18+8.1, 10.0+9.3, 12.2+10.4, 14.3+11.8, 16.3+15.8, 18.3+18.8, 20.3+22.4]
# simple = [11.56, 16.28, 19.3, 22.6, 26.1, 32.1, 37.1, 42.7]
# pre_install = [6.16, 8.18, 10.2, 12.2, 14.3, 16.3, 18.3, 20.3]

#-----fix error understanding-----
simple = [12.0, 15.2, 19.0, 21.2, 24.0, 27.3, 30.1, 32.5, 35.5]

pre_install = [6.49, 8.69, 10.9, 13.1, 15.2, 17.5, 19.7, 21.9, 24.4]

plt.plot(x,simple,"k-o",label="contain Extra Latency")
plt.plot(x,pre_install,"k-^",label="no Extra Latency")
plt.axis([0,10,0,50])
plt.xticks([0,1,2,3,4,5,6,7,8,9,10])
plt.xlabel("the number of switch nodes", fontsize=16)
plt.ylabel("the RTT of the 1st ICMP packet(ms)", fontsize=16)
plt.legend()
plt.show()


