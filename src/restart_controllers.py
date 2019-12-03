import argparse
import os

from p4utils.utils.topology import Topology

def write_bash_skript(t, e, s, path, reporting_thresh_R):
    topo = Topology(db="topology.db")
    f    = open("start_controllers.sh", "w+")

    f.write("lxterminal -e bash -c 'sudo python controller/coordinator.py --r {0}; bash'\n".format(
        reporting_thresh_R
    ))
    f.write("sleep 5\n")

    for p4switch_name in topo.get_p4switches():
        # starting controllers in different shells
        start_controller = "lxterminal -e bash -c 'sudo python controller/l2_controller.py --n %s --t %s --e %s --s %s'\n" % (p4switch_name, t, e, s)
        f.write(start_controller)

    # run the load balancer and aggregating switch controller
    start_controller = "lxterminal -e bash -c 'sudo python controller/lb_ag_controller.py'\n"
    f.write(start_controller)

    f.write("sleep 10\n")
    f.write("mx h1 sudo tcpreplay -i h1-eth0 {0}".format(path))
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True, help="The global threshold T")
    parser.add_argument('--s', type=float, required=True, help="The sampling probability s")
    parser.add_argument('--e', type=float, required=True, help="Epsilon")
    parser.add_argument('--p', type=str, required=True, help="The path to the pcap file")
    parser.add_argument('--r', type=int, required=True, help="The reporting threshold R")
    args = parser.parse_args()

    write_bash_skript(args.t, args.e, args.s, args.p, args.r)

    os.system("sudo bash start_controllers.sh")
