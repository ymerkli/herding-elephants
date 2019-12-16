from __future__ import division

import argparse
import os
import subprocess
import signal
import time
import csv
import json
import string
import re
import sys

from p4utils.utils.topology import Topology

global_thresh_to_percentile = {
    'eval500': {
        11: '99',
        37: '99_9',
        37: '99_99'
    }
}

def startup(global_threshold, report_threshold, epsilon, sampling_probability):
    '''
    Starts the coordinator and controllers with the given parameters. Returns the pids of all
    processes that are started.

    '''

    pids_to_kill = []
    topo = Topology(db="topology.db")

    # start controllers and coordinator here
    coordinator = subprocess.Popen(['sudo', 'python', 'controller/coordinator.py', '--v', '--r', '%s' % report_threshold])
    pids_to_kill.append(coordinator.pid)

    time.sleep(5)

    for p4switch_name in topo.get_p4switches():
        # only start controller for ingress switches
        if re.match(r"s\d+", p4switch_name):
            controller = subprocess.Popen(['sudo', 'python', 'controller/herd_controller.py', '--v', '--t', '%s' % global_threshold, '--n', '%s' % p4switch_name, '--e', '%s' % epsilon, '--s', '%s' % sampling_probability])

            '''
            Prepend Controller PIDs
            This way socket.recv errors are avoid since we dont kill the coordinator first
            '''
            pids_to_kill.insert(0, controller.pid)

    # we need to sleep for a bit before running the lb ag controllers
    time.sleep(5)
    # start lb and ag controllers
    lb_ag_controller = subprocess.Popen(['sudo', 'python', 'controller/lb_ag_controller.py'])
    pids_to_kill.append(lb_ag_controller.pid)

    print(pids_to_kill)

    return pids_to_kill

def kill_processes(pid_list):
    '''
    Writes a bash kill command to kill_script.sh for every entry in the pid list

    '''

    f = open("kill_script.sh", "w+")
    for pid in pid_list:
        print(pid)
        f.write("sudo kill -2 %s\n" % pid)
    f.close()

def main():

    pid_list = startup(5, 2, 0.1, 0.5)
    print(pid_list)
    print("Startup finished, waiting for controllers to be ready")
    time.sleep(10)

    # send traffic from host
    send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '-p', '300', '../data/eval500.pcap'])

    time.sleep(10)
    print("Sending finished, killing processes")
    kill_processes(pid_list)

    os.system("lxterminal -e bash -c 'sudo bash kill_script.sh'")


if __name__ == '__main__':
    sys.tracebacklimit = 0
    main()
