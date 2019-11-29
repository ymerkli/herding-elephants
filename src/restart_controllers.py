import argparse
import os
from p4utils.utils.topology import Topology

def write_bash_skript(t, e, s):
    topo = Topology(db="topology.db")
    f = open("start_controllers.sh", "w+")
    for p4switch in topo.get_p4switches():
        # starting all controllers in the same shell
        # start_controller = "sudo python l2_controller.py --n %s --t 1 --e 1 --s 1 &\n" % p4switch

        # starting controllers in different shells
        start_controller = "lxterminal -e 'sudo python l2_controller.py --n %s --t %s --e %s --s %s'\n" % (p4switch, t, e, s)
        f.write(start_controller)
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True)
    parser.add_argument('--s', type=float, required=True)
    parser.add_argument('--e', type=float, required=True)
    args = parser.parse_args()

    write_bash_skript(args.t, args.e, args.s)

    os.system("sudo ./start_controllers.sh")
