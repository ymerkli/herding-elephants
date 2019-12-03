from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI

class RoutingController(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        self.controller_lb = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()

    def reset_states(self):
        self.controller_lb.reset_state()

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            if (p4switch == "lb"):
                thrift_port = self.topo.get_thrift_port(p4switch)
                self.controller_lb = SimpleSwitchAPI(thrift_port)

    def route(self):

        for sw_dst in self.topo.get_p4switches():
            if (sw_dst != "lb" and sw_dst != "ag"):
                dst_port = self.topo.node_to_node_port_num("lb", sw_dst)
                dst_sw_mac  = self.topo.node_to_node_mac(sw_dst, "lb")
                number = sw_dst[-1]
                print "table_add at lb:"
                self.controller_lb.table_add("get_port", "set_nhop", [str(number)], [str(dst_sw_mac), str(dst_port)])
        host = self.topo.get_hosts_connected_to("lb")[0]
        host_port = self.topo.node_to_node_port_num("lb", host)
        self.controller_lb.register_write("host_port", 0, host_port)

    def main(self):
        self.route()

class DummyController(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        self.controller_ag = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()

    def reset_states(self):
        self.controller_ag.reset_state()

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            if (p4switch == "ag"):
                thrift_port = self.topo.get_thrift_port(p4switch)
                self.controller_ag = SimpleSwitchAPI(thrift_port)

    def route(self):
        host = self.topo.get_hosts_connected_to("ag")[0]
        host_port = self.topo.node_to_node_port_num("ag", host)
        host_mac = self.topo.get_host_mac(host)
        dummy = host_mac[0:2] + host_mac[3:5] + host_mac[6:8] + host_mac[9:11] + host_mac[12:14] + host_mac[15:17]
        host_mac = int(dummy, 16)
        self.controller_ag.register_write("host_mac", 0, host_mac)
        self.controller_ag.register_write("host_port", 0, host_port)

    def main(self):
        self.route()

if __name__ == "__main__":
    controller = RoutingController().main()
    controller = DummyController().main()
