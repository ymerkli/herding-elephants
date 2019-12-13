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



def startup(global_threshold, report_threshold, epsilon, sampling_probability, mode):

    pids_to_kill = []
    topo = Topology(db="topology.db")

    # start controllers and coordinator here
    coordinator = subprocess.Popen(['sudo', 'python', 'controller/coordinator.py', '--r', '%s' % report_threshold])
    pids_to_kill.append(coordinator.pid)

    print("Coordinator PID: ", coordinator.pid)
    time.sleep(5)

    for p4switch_name in topo.get_p4switches():
        # only start controllers for ingress switches
        if re.match(r"s\d+", p4switch_name):
            if (mode == 'herd'):
                controller = subprocess.Popen(['sudo', 'python', 'controller/herd_controller.py', '--t', '%s' % global_threshold, '--n', '%s' % p4switch_name, '--e', '%s' % epsilon, '--s', '%s' % sampling_probability])
            elif (mode == 'rla'):
                controller = subprocess.Popen(['sudo', 'python', 'controller/rla_controller.py', '--t', '%s' % global_threshold, '--n', '%s' % p4switch_name, '--e', '%s' % epsilon])
            elif (mode == 'ps'):
                controller = subprocess.Popen(['sudo', 'python', 'controller/ps_controller.py', '--n', '%s' % p4switch_name, '--s', '%s' % sampling_probability])

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
    f = open("kill_script.sh", "w+")
    for pid in pid_list:
        print(pid)
        f.write("sudo kill -2 %s\n" % pid)
    f.close()

def read_rounds(csv_file_path):
    '''
    Reads the csv file and gets the parameters for each round
    The first row, first element of the csv is the parameter to be swept over
    The first element of the following rows are the parameters for each round
    The csv file will also be used to write back the results of the evaluation
    (i.e. the f1score, precision, recall)

    example csv file layout:
        <parameter_name>,f1score,precision,recall
        1,
        2,

    Args:
        csv_file_path (str): The file path to the csv file
    '''

    if os.path.exists(csv_file_path):
        with open(csv_file_path) as csv_file:
            reader = csv.reader(csv_file)

            row_counter      = 0
            parameter_name   = None
            parameter_rounds = []
            for row in reader:
                if row_counter == 0:
                    parameter_name = row[0]
                else:
                    parameter_rounds.append(row[0])
                row_counter += 1

        return parameter_rounds, parameter_name
    else:
        raise ValueError("Error: csv file {0} does not exit".format(csv_file_path))

class InputValueError(Exception):
    pass


def parser():

    parser = argparse.ArgumentParser()
    parser.add_argument('--t', type=int, required=True, help="The global threshold T")
    parser.add_argument('--s', type=float, required=True, help="The sampling probability s")
    parser.add_argument('--e', type=float, required=True, help="Epsilon")
    parser.add_argument('--p', type=str, required=True, help="The path to the pcap file")
    parser.add_argument('--f', type=str, required=True, help="The path to the csv file for the normal round")
    parser.add_argument('--g', type=str, required=True, help="The path to the csv file for the rla round")
    parser.add_argument('--h', type=str, required=True, help="The path to the csv file for the probabilistic sampling round")

    args = parser.parse_args()

    if (args.s < 0 or 1 < args.s):
        raise InputValueError

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.t, args.e, args.s, args.p, args.f, args.g, args.h


def main():
    try:
        t, e, s, pcap_file_path, csv_file_path, csv_file_path_rla, csv_file_path_ps= parser()
    except InputValueError:
        print("The sampling probability and epsilon should be between 0 and 1")

    pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", pcap_file_path).group(2)
    # naming convention for evaluation pcap datasets: eval<num_packets>.pcap
    num_packets    = re.match(r"eval(\d+[km]?)", pcap_file_name).group(1)

    # select the real elephants depending on the global threshold
    if pcap_file_name not in global_thresh_to_percentile:
        raise ValueError("Error: pcap set {0} is not known".format(pcap_file_name))
    if t not in global_thresh_to_percentile[pcap_file_name]:
        raise ValueError("Error: global threshold {0} is not mapped to a percentile for {1}".format(t, pcap_file_name))

    real_elephants_path  = "{0}../evaluation/data/real_elephants_{1}_{2}.json".format(
        path_to_src, num_packets, global_thresh_to_percentile[pcap_file_name][t]
    )
    print("Real elephants path: ", real_elephants_path)

    parameter_rounds_norm, parameter_name = read_rounds(csv_file_path)
    parameter_rounds_rla, dummy = read_rounds(csv_file_path_rla)
    parameter_rounds_ps, dummy = read_rounds(csv_file_path_ps)

    parameter_name = string.lower(parameter_name)

    evaluator = FlowEvaluator(csv_file_path, parameter_name)
    evaluator_rla = FlowEvaluator(csv_file_path_rla, parameter_name)
    evaluator_ps =  FlowEvaluator(csv_file_path_ps, parameter_name)

    if parameter_name == 'epsilon':
        os.system("lxterminal -e 'sudo p4run --conf p4app/p4app_10_switches_herd.json' &")
        time.sleep(30)

        for epsilon in parameter_rounds_norm:


            print("Evaluating for epsilon = {0}".format(epsilon))
            r = int(1/float(epsilon))
            mode = 'herd'
            pid_list = startup(t, r, epsilon, s, mode)
            print(pid_list)
            print("Startup finished, waiting for controllers to be ready")
            time.sleep(10)

            # send traffic from host
            send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '-p', '300', '%s' % pcap_file_path])

            time.sleep(10)
            print("Sending finished, killing processes")
            kill_processes(pid_list)

            os.system("lxterminal -e bash -c 'sudo bash kill_script.sh'")

            # wait for everything to finish (especially the coordinator to write out found_elephants.json)
            time.sleep(5)

            # Start the evaluation of the current round
            f1_score, precision, recall = evaluator.get_accuracy(real_elephants_path, found_elephants_path)
            # Write the found measures to the csv file
            evaluator.write_accuracies_to_csv(f1_score, precision, recall, epsilon)

            f = open("../evaluation/counters/counter_results_herd","a")
            f.write("-\n-\n **** Evaluation for epsilon {0} finished ****\n-\n-\n".format(epsilon))
            f.close()


        # rla part
        os.system("lxterminal -e 'sudo p4run --conf p4app/p4app_10_switches_rla.json' &")
        time.sleep(30)

        for epsilon in parameter_rounds_rla:


            r = int(1/float(epsilon))
            mode = 'rla'
            pid_list = startup(t, r, epsilon, 1, mode)
            print(pid_list)
            print("Startup finished, waiting for controllers to be ready")
            time.sleep(10)
            # send traffic from host
            send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '-p', '300', '%s' % pcap_file_path])

            time.sleep(10)
            print("Sending finished, killing processes")
            kill_processes(pid_list)

            os.system("lxterminal -e bash -c 'sudo bash kill_script.sh'")

            # wait for everything to finish (especially the coordinator to write out found_elephants.json)
            time.sleep(5)

            # Start the evaluation of the current round
            f1_score, precision, recall = evaluator_rla.get_accuracy(real_elephants_path, found_elephants_path)
            # Write the found measures to the csv file
            evaluator_rla.write_accuracies_to_csv(f1_score, precision, recall, epsilon)

            f = open("../evaluation/counters/counter_results_rla","a")
            f.write("-\n-\n **** Evaluation for epsilon {0} finished ****\n-\n-\n".format(epsilon))
            f.close()

        # probabilistic sampling part
        os.system("lxterminal -e 'sudo p4run --conf p4app/p4app_10_switches_ps.json' &")
        time.sleep(30)

        for epsilon in parameter_rounds_ps:


            r = int(t/(1/s))
            mode = 'ps'
            s = epsilon
            pid_list = startup(1, r, 1, s, mode)
            print(pid_list)
            print("Startup finished, waiting for controllers to be ready")
            time.sleep(10)
            # send traffic from host
            send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '-p', '300', '%s' % pcap_file_path])

            time.sleep(10)
            print("Sending finished, killing processes")
            kill_processes(pid_list)

            os.system("lxterminal -e bash -c 'sudo bash kill_script.sh'")

            # wait for everything to finish (especially the coordinator to write out found_elephants.json)
            time.sleep(5)

            # Start the evaluation of the current round
            f1_score, precision, recall = evaluator_ps.get_accuracy(real_elephants_path, found_elephants_path)
            # Write the found measures to the csv file
            evaluator_ps.write_accuracies_to_csv(f1_score, precision, recall, epsilon)

            f = open("../evaluation/counters/counter_results_ps","a")
            f.write("-\n-\n **** Evaluation for epsilon {0} finished ****\n-\n-\n".format(epsilon))
            f.close()

        f = open("../evaluation/counters/counter_results_ps","a")
        f.write("-\n-\n **** All rounds finished ****\n-\n-\n".format(epsilon))
        f.close()
        f = open("../evaluation/counters/counter_results_rla","a")
        f.write("-\n-\n **** All rounds finished ****\n-\n-\n".format(epsilon))
        f.close()
        f = open("../evaluation/counters/counter_results_herd","a")
        f.write("-\n-\n **** All rounds finished ****\n-\n-\n".format(epsilon))
        f.close()

    else:
        raise ValueError("Error: unknown parameter name {0}".format(parameter_name))

    print("All rounds finished")

if __name__ == '__main__':
    sys.tracebacklimit = 0
    main()