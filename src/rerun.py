import argparse
import os
import subprocess
import signal
import time

from p4utils.utils.topology import Topology

path = '~/adv-comm-net-18/02-herding/src/'


def startup(global_threshold, report_threshold, epsilon, sampling_probability):

    pids_to_kill = []
    topo = Topology(db="topology.db")

    # start controllers and coordinator here

    coordinator = subprocess.Popen(['sudo', 'python', 'controller/coordinator.py', '--r', '%s' % report_threshold])
    pids_to_kill.append(coordinator.pid)

    print(pids_to_kill)

    time.sleep(5)

    for p4switch_name in topo.get_p4switches():
        controller = subprocess.Popen(['sudo', 'python', 'controller/l2_controller.py', '--t', '%s' % global_threshold, '--n', '%s' % p4switch_name, '--e', '%s' % epsilon, '--s', '%s' % sampling_probability])
        pids_to_kill.append(controller.pid)

    print(pids_to_kill)

    lb_ag_controller = subprocess.Popen(['sudo', 'python', 'controller/lb_ag_controller.py'])
    pids_to_kill.append(lb_ag_controller.pid)

    print(pids_to_kill)
    return pids_to_kill

'''
def write_bash_skript(t, e, s, path, reporting_thresh_R):
    topo = Topology(db="topology.db")
    f    = open("start_controllers.sh", "w+")

    f.write("sudo python controller/coordinator.py --r {0} &\n".format(reporting_thresh_R))
    f.write("sleep 5\n")

    for p4switch_name in topo.get_p4switches():
        f.write("sudo python controller/l2_controller.py --n %s --t %s --e %s --s %s &\n" % (p4switch_name, t, e, s))

    # run the load balancer and aggregating switch controller
    f.write("sudo python controller/lb_ag_controller.py &\n")


    f.write("sleep 10\n")
    f.write("mx h1 sudo tcpreplay -i h1-eth0 {0}".format(path))
    f.close()
'''

if __name__ == '__main__':
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True, help="The global threshold T")
    parser.add_argument('--s', type=float, required=True, help="The sampling probability s")
    parser.add_argument('--e', type=float, required=True, help="Epsilon")
    parser.add_argument('--r', type=int, required=True, help="The reporting threshold R")
    args = parser.parse_args()
    write_bash_skript(args.t, args.e, args.s, args.p, args.r)
    os.system("sudo bash start_controllers.sh")
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', type=str, required=True, help="The path to the pcap file")
    args = parser.parse_args()

    kill_list = startup(1, 1, 1, 1)
    print("Startup finished, waiting for controllers to be ready")
    time.sleep(10)

    send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', args.p])
    time.sleep(5)
    print("Sending finished, killing processes")
    for i in range (0,10):
        for pid in kill_list:
            os.system('sudo kill %s' % pid)
