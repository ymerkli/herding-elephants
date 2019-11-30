import argparse
import os
from p4utils.utils.topology import Topology

def write_bash_skript(t, e, s, path):
    topo = Topology(db="topology.db")
    f = open("start_controllers.sh", "w+")
    f.write("cd controller\n")
    f.write("lxterminal -e 'python coordinator.py'\n")
    switch_num = 0
    for p4switch in topo.get_p4switches():
        switch_num += 1
        # starting all controllers in the same shell
        # start_controller = "sudo python l2_controller.py --n %s --t 1 --e 1 --s 1 &\n" % p4switch

        # starting controllers in different shells
        start_controller = "lxterminal -e 'sudo python l2_controller.py --n %s --t %s --e %s --s %s'\n" % (p4switch, t, e, s)
        f.write(start_controller)

    switch_num *= 2
    dummy_text = "boop"
    f.write("cd ..\n")
    f.write("sleep 5\n")
    ## TODO: switch to send.py
    f.write("mx h1 python send_one_message.py 10.0.0.%s %s" % (switch_num, dummy_text))
    # f.write("python send.py --p %s --i 10.0.0.%s" % (path, switch_num))
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True)
    parser.add_argument('--s', type=float, required=True)
    parser.add_argument('--e', type=float, required=True)
    parser.add_argument('--p', type=str, required=True)
    args = parser.parse_args()

    write_bash_skript(args.t, args.e, args.s, args.p)

    os.system("./start_controllers.sh")
