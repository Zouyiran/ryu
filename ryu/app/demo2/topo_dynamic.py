"""
Dynamic topology
================

This example shows how to generate a topology, an event schedule and a traffic
matrix.

In this specific example we create a Waxman topology and create an event
schedule listing random link failures and restores and generate a static
traffic matrix.

This scenario could be used to assess the performance of a routing algorithm
in case of frequent link failures.
"""
import fnss
import random
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import OVSController, OVSSwitch, RemoteController, Host, Ryu
from mininet.cli import CLI
from mininet.util import dumpNodeConnections

#  create a custom switch extends OVSSwitch
class CustomSwitch(OVSSwitch):

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.datapath = 'userspace'
        self.protocols = 'OpenFlow13'
        self.stp = True

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633

def waxman_topology(n_switch, n_host, alpha=0.4, beta=0.1, L=1.0, distance_unit='Km', seed=None):
    topo = fnss.waxman_1_topology(n=n_switch, alpha=alpha, beta=beta, L=L, distance_unit=distance_unit, seed=seed)
    for v in range(n_switch):
        topo.node[v]["type"] = "switch"
    for _ in range(n_host):
        v = topo.number_of_nodes()
        topo.add_node(v)
        topo.node[v]['type'] = 'host'
        u = random.randint(0,n_switch-1)
        topo.add_edge(v, u)
    return topo


def main():
    # generate a Waxman1 topology with 200 nodes
    topology = waxman_topology(n_switch=10, n_host=8, alpha=0.99, beta=0.2, L=1.0)

    # assign constant weight (1) to all links
    fnss.set_weights_constant(topology, 1)


    # set delay equal to 1 ms to all links
    fnss.set_delays_constant(topology, 1, 'ms')

    # set varying capacities among 10, 100 and 1000 Mbps proprtionally to edge
    # betweenness centrality
    fnss.set_capacities_edge_betweenness(topology, [10, 100, 1000], 'Mbps')


    # now create a static traffic matrix assuming all nodes are both origins
    # and destinations of traffic
    # traffic_matrix = fnss.static_traffic_matrix(topology, mean=2, stddev=0.2, max_u=0.5)

    # # This is the event generator function, which generates link failure events
    # def rand_failure(links):
    #     link = random.choice(links)
    #     return {'link': link, 'action': 'down'}
    #
    # # Create schedule of link failures
    # event_schedule = fnss.poisson_process_event_schedule(
    #                         avg_interval=0.5,               # 0.5 min = 30 sec
    #                         t_start=0,                      # starts at 0
    #                         duration= 60,                   # 2 hours
    #                         t_unit='min',                   # minutes
    #                         event_generator= rand_failure,  # event gen function
    #                         links=topology.edges(),         # 'links' argument
    #                         )
    #
    # # Now let's create a schedule with link restoration events
    # # We assume that the duration of a failure is exponentially distributed with
    # # average 1 minute.
    # restore_schedule = fnss.EventSchedule(t_start=0, t_unit='min')
    # for failure_time, event in event_schedule:
    #     link = event['link']
    #     restore_time = failure_time + random.expovariate(1)
    #     restore_schedule.add(time=restore_time,
    #                          event={'link': link, 'action': 'up'},
    #                          absolute_time=True
    #                          )
    #
    # # Now merge failure and restoration schedules
    # # After merging events are still chronologically sorted
    # event_schedule.add_schedule(restore_schedule)

    # Note: there are several ways to create this link failure-restoration schedule
    # This method has been used to illustrate a variety of functions and methods
    # that FNSS provides to manipulate event schedules

    # Write topology, event schedule and traffic matrix to files
    fnss.write_topology(topology, 'topology.xml')
    # fnss.write_event_schedule(event_schedule, 'event_schedule.xml')
    # fnss.write_traffic_matrix(traffic_matrix, 'traffic_matrix.xml')

    mn_topo = fnss.to_mininet(topology=topology, relabel_nodes=True)
    net = Mininet(topo=mn_topo, link=TCLink,  switch=CustomSwitch, host=Host, controller=None, cleanup=True)

    net.addController( name='c0',
                   controller=RemoteController,
                   ip=CONTROLLER_IP,
                   port=CONTROLLER_PORT)

    # net.addHost('h1', cls=Host, mac='00:00:00:00:00:01')
    # net.addHost('h2', cls=Host, mac='00:00:00:00:00:02')
    # net.addHost('h3', cls=Host, mac='00:00:00:00:00:03')
    # net.addHost('h4', cls=Host, mac='00:00:00:00:00:04')
    # net.addHost('h5', cls=Host, mac='00:00:00:00:00:05')
    # net.addHost('h6', cls=Host, mac='00:00:00:00:00:06')
    # net.addHost('h7', cls=Host, mac='00:00:00:00:00:07')
    # net.addHost('h8', cls=Host, mac='00:00:00:00:00:08')
    # net.addHost('h9', cls=Host, mac='00:00:00:00:00:09')
    # net.addHost('h10', cls=Host, mac='00:00:00:00:00:0a')
    # net.addLink('h1','s1',cls=TCLink, bw=1)
    # net.addLink('h2','s4',cls=TCLink, bw=1)
    # net.addLink('h3','s5',cls=TCLink, bw=1)
    # net.addLink('h4','s9',cls=TCLink, bw=1)
    # net.addLink('h5','s14',cls=TCLink, bw=1)
    # net.addLink('h6','s15',cls=TCLink, bw=1)
    # net.addLink('h7','s17',cls=TCLink, bw=1)
    # net.addLink('h8','s19',cls=TCLink, bw=1)
    # net.addLink('h9','s30',cls=TCLink, bw=1)
    # net.addLink('h10','s45',cls=TCLink, bw=1)
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

    # Stop Mininet
    net.stop()

if __name__ == "__main__":
    main()


