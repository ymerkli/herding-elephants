import re

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI

class LBController(object):
    '''
    Controller for the load balancer switch.
    Writes the rules to probabilistically balance flows over two switches
    '''

    def __init__(self):

        self.topo          = Topology(db="topology.db")
        self.controller_lb = {}
        self.lb_name       = None
        self.init()

    def init(self):
        self.connect_to_load_balancer()
        self.reset_states()

    def reset_states(self):
        self.controller_lb.reset_state()

    def connect_to_load_balancer(self):
        '''
        Connects to the load balancer
        Naming convention: load balancing switches are called lb<id>
        '''

        for p4switch in self.topo.get_p4switches():
            if re.match(r"lb\d+", p4switch):
                thrift_port        = self.topo.get_thrift_port(p4switch)
                self.controller_lb = SimpleSwitchAPI(thrift_port)
                self.lb_name       = p4switch

    def route(self):
        '''
        Write routing rules into get_port table for all connected switches
        and all connected hosts (usually only one host)
        '''

        for sw_dst in self.topo.get_p4switches():
            match = re.match(r"s(\d+)", sw_dst)
            if match:
                dst_port   = self.topo.node_to_node_port_num(self.lb_name, sw_dst)
                dst_sw_mac = self.topo.node_to_node_mac(sw_dst, self.lb_name)
                switch_id  = match.group(1)

                self.controller_lb.table_add("get_port", "set_nhop", [str(switch_id)], [str(dst_sw_mac), str(dst_port)])


    def main(self):
        self.route()

class AGController(object):
    '''
    Controller for the aggreagting switch.
    Writes the rules to just forward traffic from ingress switches to an internal host.
    '''

    def __init__(self):

        self.topo          = Topology(db="topology.db")
        self.controller_ag = {}
        self.ag_name       = None
        self.init()

    def init(self):
        self.connect_to_aggregator()
        self.reset_states()

    def reset_states(self):
        self.controller_ag.reset_state()

    def connect_to_aggregator(self):
        '''
        Connects the aggreagting switch
        Naming convention: aggregating switches are called ag<id>
        '''

        for p4switch in self.topo.get_p4switches():
            if re.match(r"ag\d+", p4switch):
                thrift_port        = self.topo.get_thrift_port(p4switch)
                self.controller_ag = SimpleSwitchAPI(thrift_port)
                self.ag_name       = p4switch

    def route(self):
        '''
        Write routing rules into the ipv4_lpm table. This table basically matches ALL IP traffic
        and sends it to the connected host. We thus do longest prefix matching with prefix 0
        '''

        host      = self.topo.get_hosts_connected_to(self.ag_name)[0]
        host_port = self.topo.node_to_node_port_num(self.ag_name, host)
        host_mac  = self.topo.get_host_mac(host)
        match_ip  = unicode("0.0.0.0/0")

        self.controller_ag.table_add("ipv4_lpm", "set_nhop",\
            [str(match_ip)], [str(host_mac), str(host_port)])

    def main(self):
        self.route()

if __name__ == "__main__":
    controller = LBController().main()
    print("lb_switch ready")
    controller = AGController().main()
    print("ag_switch ready")
