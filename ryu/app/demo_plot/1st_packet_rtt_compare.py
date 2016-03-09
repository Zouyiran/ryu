#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt

'''
1st packet rtt compare
plot for:pre_install_app(no Extra Latency) and react_install_app(contain Extra Latency)
'''

x = [2,3,4,5,6,7,8,9]
simple = [] #[ ,46.2 ,56.2 ,62.0 ,71.2, 79.5]
pre_install = [] #[,40.3 ,46.2 ,52.4 ,57.1]

plt.plot(x,simple,"k-o",label="contain Extra Latency")
plt.plot(x,pre_install,"k-^",label="no Extra Latency")
plt.axis([0,10,0,100])
plt.xticks([0,1,2,3,4,5,6,7,8,9,10])
plt.xlabel("the number of switch nodes", fontsize=16)
plt.ylabel("the RTT of the 1st packet(ms)", fontsize=16)
plt.legend()
plt.show()


