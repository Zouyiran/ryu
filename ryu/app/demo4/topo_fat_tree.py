import fnss
import random
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import OVSController, OVSSwitch, RemoteController, Host, Ryu
from mininet.cli import CLI
from mininet.util import dumpNodeConnections

'''
can NOT be used
'''

#  create a custom switch extends OVSSwitch
class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        self.stp = True

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def main():
    topology = fnss.fat_tree_topology(k=4)

    fnss.set_weights_constant(topology, 1)

    # fnss.set_delays_constant(topology, 1, 'ms')

    # set varying capacities among 10, 100 and 1000 Mbps proprtionally to edge
    # betweenness centrality
    fnss.set_capacities_edge_betweenness(topology, [10, 100, 1000], 'Mbps')

    # Write topology, event schedule and traffic matrix to files
    fnss.write_topology(topology, 'topology.xml')

    mn_topo = fnss.to_mininet(topology=topology, relabel_nodes=True)
    net = Mininet(topo=mn_topo, link=TCLink,  switch=CustomSwitch, host=Host, controller=None, cleanup=True)

    net.addController( name='c0',
                   controller=RemoteController,
                   ip=CONTROLLER_IP,
                   port=CONTROLLER_PORT)


    net.start()
    dumpNodeConnections(net.hosts)
    CLI(net)
    # # Dump host connections
    # dumpNodeConnections(net.hosts)
    #
    # # Test network connectivity
    # net.pingAll()
    #
    # # Test bandwidth between nodes
    # h1, h4 = net.get('h1', 'h4')
    # net.iperf((h1, h4))

    net.stop()

if __name__ == "__main__":
    main()