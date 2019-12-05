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

    def get_mac(self):
        host      = self.topo.get_hosts_connected_to(self.lb_name)[0]
        mac = self.topo.node_to_node_mac(self.lb_name, host)
        print(mac)

    def main(self):
        self.get_mac()




if __name__ == "__main__":
    controller = LBController().main()
