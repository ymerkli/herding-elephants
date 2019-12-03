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

def kill_processes(pid_list):
    for pid in pid_list:
        print(pid)
        subprocess.call(['sudo', 'kill', '%s' % pid])


class InputValueError(Exception):
    pass


def parser():

    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True, help="The global threshold T")
    parser.add_argument('--s', type=float, required=True, help="The sampling probability s")
    parser.add_argument('--e', type=float, required=True, help="Epsilon")
    parser.add_argument('--r', type=int, required=True, help="The reporting threshold R")
    parser.add_argument('--p', type=str, required=True, help="The path to the pcap file")
    parser.add_argument('--n', type=int, required=False, help="The number of evaluation rounds", default=1)
    args = parser.parse_args()

    args = parser.parse_args()

    if (args.s < 0 or 1 < args.s):
        raise InputValueError

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.t, args.r, args.e, args.s, args.p, args.n


if __name__ == '__main__':
    '''
    try:
        t, r, e, s, path, rounds = parser()
    except InputValueError:
        print("The sampling probability and epsilon should be between 0 and 1")

    # for i in range(0, rounds):
    '''

    pid_list = startup(1, 1, 1, 1)
    print(pid_list)
    print("Startup finished, waiting for controllers to be ready")
    time.sleep(10)

    send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', 'data/first5.pcap'])

    print("Sending finished, killing processes")
    time.sleep(5)
    kill_processes(pid_list)

        ## TODO: evaluate results

    print("All rounds finished")
