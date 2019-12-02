import argparse
import os
from p4utils.utils.topology import Topology

def write_bash_skript(t, e, s, path):
    topo = Topology(db="topology.db")
    f = open("start_controllers.sh", "w+")
    f.write("lxterminal -e bash -c 'sudo python controller/coordinator.py; bash'\n")
    f.write("sleep 5\n")

    switches   = topo.get_p4switches()
    switch_num = len(switches)

    '''
    Issue with P4Utils: if a host has multiple connections to switches, the MAC address
    of the interface on the host pointing to the first and last switch are equivalent.
    To prevent this, we add one more switch than necessary but never use it
    '''
    ignore_switch = None
    if switch_num > 9:
        ignore_switch = "s{0}".format(switch_num)

    for p4switch_name in switches.keys():
        if ignore_switch and p4switch_name == ignore_switch:
            continue

        # starting controllers in different shells
        start_controller = "lxterminal -e bash -c 'sudo python controller/l2_controller.py --n %s --t %s --e %s --s %s'\n" % (p4switch_name, t, e, s)
        f.write(start_controller)

    switch_num *= 2
    f.write("sleep 5\n")
    f.write("mx h1 python send.py --p %s --i 10.0.0.%s" % (path, switch_num))
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True)
    parser.add_argument('--s', type=float, required=True)
    parser.add_argument('--e', type=float, required=True)
    parser.add_argument('--p', type=str, required=True)
    args = parser.parse_args()

    write_bash_skript(args.t, args.e, args.s, args.p)

    os.system("sudo bash start_controllers.sh")
