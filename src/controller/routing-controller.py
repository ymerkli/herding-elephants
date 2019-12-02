from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI

class RoutingController(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            if (p4switch[0] != "s"):
                print(p4switch)
                thrift_port = self.topo.get_thrift_port(p4switch)
                self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def route(self):

        for sw_name, controllers in self.controllers.items():
            for sw_dst in self.topo.get_p4switches():
                if (sw_dst[0] == "s"):
                    dst_port = self.topo.node_to_node_port_num(sw_name, sw_dst)
                    dst_sw_mac  = self.topo.node_to_node_mac(sw_dst, sw_name)
                    number = sw_dst[-1]
                    print "table_add at {}:".format(sw_name)
                    self.controllers[sw_name].table_add("get_port", "set_nhop", [str(number)], [str(dst_sw_mac), str(dst_port)])
            host = self.topo.get_hosts_connected_to(sw_name)
            host = host[0]
            sw_port = self.topo.node_to_node_port_num(sw_name, host)
            host_mac = self.topo.get_host_mac(host)
            self.controllers[sw_name].register_write("host_mac", 0, host_mac)
            self.controllers[sw_name].register_write("host_port", 0, sw_port)

    def main(self):
        self.route()


if __name__ == "__main__":
    controller = RoutingController().main()
