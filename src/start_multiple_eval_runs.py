from __future__ import division

import argparse
import os
import subprocess
import signal
import time
import csv
import json
import string

from p4utils.utils.topology import Topology
from flow_evaluator import FlowEvaluator

#Get the full path to the src folder
path_to_src = os.path.realpath(__file__)
path_to_src = re.match(r"^(.+/)*(.+)\.(.+)", path).group(1) #remove the filename from the path

real_elephants_path  = "{0}../evaluation/data/real_elephants.json".format(path_to_src)
found_elephants_path = "{0}../evaluation/data/found_elephants.json".format(path_to_src)

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
    f = open("kill_skript.sh", "w+")
    for pid in pid_list:
        print(pid)
        f.write("sudo kill %s\n" % pid)
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
        with open(self.csv_file_path) as csv_file:
            reader = csv.reader(csv_file)

            row_counter      = 0
            parameter_name   = None
            parameter_rounds = []
            for row in reader:
                if row_counter == 0:
                    parameter_name = row[0]
                else:
                    parameter_rounds.append(row[0])

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
    parser.add_argument('--r', type=int, required=True, help="The reporting threshold R")
    parser.add_argument('--p', type=str, required=True, help="The path to the pcap file")
    parser.add_argument('--c', type=str, required=True, help="The path to the csv file")
    args = parser.parse_args()

    args = parser.parse_args()

    if (args.s < 0 or 1 < args.s):
        raise InputValueError

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.t, args.r, args.e, args.s, args.p, args.c


def main():
    try:
        t, r, e, s, pcap_file_path, csv_file_path= parser()
    except InputValueError:
        print("The sampling probability and epsilon should be between 0 and 1")

    parameter_rounds, parameter_name = read_rounds(csv_file_path)

    parameter_name = string.lower(parameter_name)

    evalautor = FlowEvaluator(csv_file_path, parameter_name) 

    if parameter_name == 'epsilon': 
        for epsilon in parameter_rounds:

            print("Evaluating for epsilon = {0}".format(epsilon))
            pid_list = startup(t, r, epsilon, s)
            print(pid_list)
            print("Startup finished, waiting for controllers to be ready")
            time.sleep(10)

            # send traffic from host
            send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '%s' % path])

            print("Sending finished, killing processes")
            time.sleep(5)
            kill_processes(pid_list)

            os.system("lxterminal -e bash -c 'sudo bash kill_skript.sh'")

            # Start the evaluation of the current round
            f1_score, precision, recall = evaluator.get_accuracy(real_elephants, found_elephants)
            # Write the found measures to the csv file
            evaluator.write_accuracies_to_csv(f1_score, precision, recall)

    elif parameter_name == 'sampling_probability':
        for sampling_prob in parameter_rounds:

            print("Evaluating for sampling probability = {0}".format(sampling_prob))
            pid_list = startup(t, r, e, sampling_prob)
            print(pid_list)
            print("Startup finished, waiting for controllers to be ready")
            time.sleep(10)

            # send traffic from host
            send = subprocess.call(['mx', 'h1', 'sudo', 'tcpreplay', '-i', 'h1-eth0', '%s' % path])

            print("Sending finished, killing processes")
            time.sleep(5)
            kill_processes(pid_list)

            os.system("lxterminal -e bash -c 'sudo bash kill_skript.sh'")

            # Start the evaluation of the current round
            f1_score, precision, recall = evaluator.get_accuracy(real_elephants, found_elephants)
            # Write the found measures to the csv file
            evaluator.write_accuracies_to_csv(f1_score, precision, recall)
    else:
        raise ValueError("Error: unknown parameter name {0}".format(parameter_name))

    print("All rounds finished")

if __name__ == '__main__':
    main()