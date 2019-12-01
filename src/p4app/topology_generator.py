import json
import argparse
import networkx

topo_base = {
  "program": "p4src/switch.p4",
  "switch": "simple_switch",
  "compiler": "p4c",
  "options": "--target bmv2 --arch v1model --std p4-16",
  "switch_cli": "simple_switch_CLI",
  "exec_scripts": [],
  "cli": True,
  "pcap_dump": True,
  "enable_log": True,
  "exec_scripts": [],
  "topo_module": {
    "file_path": "",
    "module_name": "p4utils.mininetlib.apptopo",
    "object_name": "AppTopoStrategies"
  },
  "controller_module": None,
  "topodb_module": {
    "file_path": "",
    "module_name": "p4utils.utils.topology",
    "object_name": "Topology"
  },
  "mininet_module": {
    "file_path": "",
    "module_name": "p4utils.mininetlib.p4net",
    "object_name": "P4Mininet"
  },
  "topology": {
      "assignment_strategy": "l2"
  }
}


def create_topo(num_switches):
    topo_base["topology"]["links"] = []

    #connect host 1 with switches
    for i in range(1, num_switches+1):
        topo_base["topology"]["links"].append(["h1", "s{0}".format(i)])

    #connect host 2 with switches
    for i in range(1, num_switches +1):
        topo_base["topology"]["links"].append(["s{0}".format(i), "h2"])

    topo_base["topology"]["hosts"] = {"h{0}".format(i): {} for i in range(1, 3)}
    topo_base["topology"]["switches"] = {"s{0}".format(i): {} for i in range(1, num_switches + 1)}

"""

def create_circular_topo(num_switches):

    create_linear_topo(num_switches)
    #add link between  s1 and sN
    topo_base["topology"]["links"].append(["s{}".format(1), "s{}".format(num_switches)])

def create_random_topo(degree=4, num_switches=10):

    topo_base["topology"]["links"] = []
    g = networkx.random_regular_graph(degree, num_switches)
    trials = 0
    while not networkx.is_connected(g):
        g = networkx.random_regular_graph(degree, num_switches)
        trials +=1
        if trials >= 10:
            print "Could not Create a connected graph"
            return

    # connect hosts with switches
    for i in range(1, num_switches + 1):
        topo_base["topology"]["links"].append(["h{}".format(i), "s{0}".format(i)])

    for edge in g.edges:
        topo_base["topology"]["links"].append(["s{}".format(edge[0]+1), "s{}".format(edge[1] + 1)])

    topo_base["topology"]["hosts"] = {"h{0}".format(i): {} for i in range(1, num_switches + 1)}
    topo_base["topology"]["switches"] = {"s{0}".format(i): {} for i in range(1, num_switches + 1)}

"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_name', type=str, required=False, default="p4app_generated.json")
    parser.add_argument('-n', type=int, required=False, default=3)
    args = parser.parse_args()
    create_topo(args.n)

    json.dump(topo_base, open("p4app_generated0.json", "w+"), sort_keys=True, indent=2)
    print("Finished")
