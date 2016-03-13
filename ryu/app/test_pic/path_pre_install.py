# -*- coding: utf-8 -*-
#!/usr/bin/env python


import numpy as np
import matplotlib.pyplot as plt

'''
simulate for path pre-install
1st packet latency use tcp-packet
响应式流表下发
MPLS路径预安装
端到端节点数目
首包时延(ms)
'''

x = [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]

#dumb
dum = [21.2, 23.5, 27.0, 32.0, 36.0, 43.5, 47.0, 53.0, 60.7, 67.2, 74.3, 81.8, 88.0, 96.8, 105, 112, 123]
# pre-install
pre = [21.5, 23.2, 26.0, 28.0, 31.0, 36.4, 41.1, 45.5, 50.2, 56.7, 60.6, 65.8, 69.2, 73.8, 78.2, 82.1, 86]

plt.plot(x,dum,"k-o",label="dumb")
plt.plot(x,pre,"k-*",label="path pre-install")
plt.axis([0,20,0,140])
plt.xticks([3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18])
plt.xlabel("the number of nodes", fontsize=16)
plt.ylabel("the average latency of 1st packet(ms)", fontsize=16)
plt.legend(loc= 'best')
plt.show()


