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
from flow_evaluator import FlowEvaluator

'''

Evaluates f1 score, recall and precicion for multiple rounds and writes the
results to a csv file.

Args:
    global threshold: The threshold corresponding to the percentile one wants to
                      evaluate.
    pcap file path:   The pcap file the algorithm should use for evaluation.
    input csv file:   The csv file where this skript can find the epsilon,
                      report probability,report threshold and sampling probability
                      to use for each round.
    outuput csv file: The file which should be used to write the results

Returns: The results of each round are written to the specified csv file.

'''

#Get the full path to the src folder
path_to_src = os.path.realpath(__file__)
path_to_src = re.match(r"^(.+/)*(.+)\.(.+)", path_to_src).group(1) #remove the filename from the path

found_elephants_path = "{0}../evaluation/data/found_elephants.json".format(path_to_src)

global_thresh_to_percentile = {
    'eval5m': {
        239: '99',
        1728: '99_9',
        5577: '99_99'
    },
    'eval1m': {
        134: '99',
        901: '99_9',
        3180: '99_99'
    },
    'eval400k': {
        91: '99',
        470: '99_9',
        1504: '99_99'
    },
    'eval100k': {
        50: '99',
        247: '99_9',
        1091: '99_99'
    },
    'eval500': {
        11: '99',
        37: '99_9',
        37: '99_99'
    }
}

def startup(global_threshold, report_threshold, epsilon, sampling_probability):

    pids_to_kill = []
    topo = Topology(db="topology.db")

    # start controllers and coordinator here
    coordinator = subprocess.Popen(['sudo', 'python', 'controller/coordinator.py', '--r', '%s' % report_threshold])
    pids_to_kill.append(coordinator.pid)

    print("Coordinator PID: ", coordinator.pid)
    time.sleep(5)

    for p4switch_name in topo.get_p4switches():
        # only start controller for ingress switches
        if re.match(r"s\d+", p4switch_name):
            controller = subprocess.Popen(['sudo', 'python', 'controller/herd_controller.py', '--t', '%s' % global_threshold, '--n', '%s' % p4switch_name, '--e', '%s' % epsilon, '--s', '%s' % sampling_probability])

            '''
            Prepend Controller PIDs
            This way socket.recv errors are avoid since we dont kill the coordinator first
            '''
            pids_to_kill.insert(0, controller.pid)

    print(pids_to_kill)

    # we need to sleep for a bit before running the lb ag controllers
    time.sleep(5)
    # start lb and ag controllers
    lb_ag_controller = subprocess.Popen(['sudo', 'python', 'controller/lb_ag_controller.py'])
    pids_to_kill.append(lb_ag_controller.pid)

    print(pids_to_kill)

    return pids_to_kill

def kill_processes(pid_list):
    f = open("kill_skript.sh", "w+")
    for pid in pid_list:
        print(pid)
        f.write("sudo kill -2 %s\n" % pid)
    f.close()

def parser():

    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True, help="The global threshold T")
    parser.add_argument('--p', type=str, required=True, help="The path to the pcap file")
    parser.add_argument('--i', type=str, required=True, help="The path to the input csv file")
    parser.add_argument('--o', type=str, required=True, help="The path to the output csv file")

    args = parser.parse_args()


    return args.t, args.p, args.i, args.o


def main():

    global_threshold, pcap_file_path, param_csv_file_path, output_csv_file_path = parser()

    pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", pcap_file_path).group(2)
    # naming convention for evaluation pcap datasets: eval<num_packets>.pcap
    num_packets    = re.match(r"eval(\d+[km]?)", pcap_file_name).group(1)

    # select the real elephants depending on the global threshold
    if pcap_file_name not in global_thresh_to_percentile:
        raise ValueError("Error: pcap set {0} is not known".format(pcap_file_name))
    if global_threshold not in global_thresh_to_percentile[pcap_file_name]:
        raise ValueError("Error: global threshold {0} is not mapped to a percentile for {1}".format(global_threshold, pcap_file_name))

    real_elephants_path  = "{0}../evaluation/data/real_elephants_{1}_{2}.json".format(
        path_to_src, num_packets, global_thresh_to_percentile[pcap_file_name][global_threshold]
    )
    print("Real elephants path: ", real_elephants_path)

    round = 0

    evaluator = FlowEvaluator(output_csv_file_path, 'round')

    # use input csv file to get parameters
    with open(param_csv_file_path) as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            # skip first row (parameter names)
            if (round == 0):
                round += 1
                continue
            print("Evaluation round: %s" % round)

            round += 1
            epsilon = row[0]
            report_prob = row[1]
            report_thresh_R = row[2]
            sampl_prob = row[3]

            print("Starting with parameters: epsilon - %s, report probability - %s report threshold - %s sampling probability - %s" % (epsilon, report_prob, report_thresh_R, sampl_prob))
            pid_list = startup(global_threshold, report_thresh_R, epsilon, sampl_prob)
            print(pid_list)
            print("Startup finished, waiting for controllers to be ready")
            time.sleep(10)

            # send traffic from host
            send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '-p', '300', '%s' % pcap_file_path])

            time.sleep(60)
            print("Sending finished, killing processes")
            kill_processes(pid_list)

            os.system("lxterminal -e bash -c 'sudo bash kill_skript.sh'")

            # wait for everything to finish (especially the coordinator to write out found_elephants.json)
            time.sleep(5)

            # Start the evaluation of the current round
            f1_score, precision, recall = evaluator.get_accuracy(real_elephants_path, found_elephants_path)
            # Write the found measures to the output csv file
            evaluator.write_accuracies_to_csv(f1_score, precision, recall, round)

    print("All rounds finished")

if __name__ == '__main__':
    sys.tracebacklimit = 0
    main()
