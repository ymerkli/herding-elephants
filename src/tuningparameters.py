from __future__ import division
import random
import argparse
from scapy.all import *

def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')

    parser.add_argument(
        '--p', 
        required = True, 
        help = 'Path to .pcap file'
    )

    parser.add_argument(
        '--t',
        type = int,
        required = True,
        help = 'Global Threshold'
    )

    parser.add_argument(
        '--c',
        type = int,
        required = True,
        help = 'Communication budget'
    )

    parser.add_argument(
        '--s',
        type = int,
        required = True,
        help = 'switch memory'
    )

    args = parser.parse_args()

    return args.p, args.t, args.c, args.s

def pcap_to_list(pcap_path):
    '''
    Parses a pcap file and creates a list of five-tuples

    Args:
        pcap_path (str): The path to the pcap file

    Returns:
        packets (list): A list of 5-tuples (flows)
    '''

    packets = []

    pkts = rdpcap(pcap_path)

    for pkt in pkts:
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                src_port = pkt[IP].sport
                dst_port = pkt[IP].dport

                five_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
                packets.append(five_tuple)
        except Exception as e:
            continue

    return packets

##### Given #####
# (T) glob_thresh_T -> Global threshold
# (C) comm_budget -> Communication budget per switch
# (S) switch_mem -> Memory budget per switch (# counters)
# (k) ingress_switches_k -> Total number of ingress switches
# (l) observers_l -> Number of switches which observe a flow
# (D) train_data -> (list) Training Data

##### Determine #####
# epsilon -> Approximation Factor
# (tau) mule_tau -> Local (Mule) threshold
# (M) moles_M -> (dict) Set of moles observed at switch
# (U) mules_U -> (dict) Set of mules at a switch
# (r) report_prob -> Reporting probability to coordinator
# (s) sampl_prob -> Sampling probability at a switch
# (R) report_thresh_R -> coordinator identifies as mule as a network-wide
#                      heavy hitter if it receives R reports


def GetSampling(switch_mem, train_data, mole_tau):
    '''
    Determine the highest possible sampling probability, given the memory constraint

    Args:
        switch_mem (int):   The memory budget of the switch
        train_data (list):  A list of flows (5-tuple) from the pcap file
        mole_tau (int):     The count threshold for a flow to become a mole

    Returns:
        mole_tau (int):     The resulting mole_tau
    '''

    sampl_prob = 1/(mole_tau)
    moles_M = CalculateMoles(train_data, sampl_prob)

    while len(moles_M) < switch_mem and mole_tau > 1:
        mole_tau -= 1
        sampl_prob = 1/mole_tau
        moles_M = CalculateMoles(train_data, sampl_prob)

    return mole_tau

def DeriveReporting(comm_budget, epsilon, observers_l, sampl_prob):
    '''
    configures reporting parameters based on the gives contraints
    '''

    mule_tau = epsilon * glob_thresh_T / observers_l
    moles_M = CalculateMoles(train_data, sampl_prob)
    mules_U = CalculateMules(moles_M, mule_tau)

    print("Mules: ", len(mules_U))
    print('report prob: ', comm_budget * mule_tau / (glob_thresh_T * len(mules_U)))

    try:
        report_prob = min(comm_budget * mule_tau / (glob_thresh_T * len(mules_U)), 1)

    # if no mules found, always report
    except ZeroDivisionError:
        print("Error: zero div")
        report_prob = 1

    report_thresh_R = max(int(round(observers_l * report_prob / glob_thresh_T)),1)

    print("DeriveReporting: report_thresh_R = {0}, mules_U = {1}, report_prob = {2}, mule_tau = {3}".format(report_thresh_R, "x", report_prob, mule_tau))

    return report_thresh_R, mules_U, report_prob, mule_tau

def CalculateMoles(train_data, sampl_prob):
    '''
    Iterate through Training Data and add a sample with probability sampl_prob to moles
    '''

    moles_M = {}
    for i in train_data:
        if i in moles_M:
            moles_M[i] = moles_M[i]+1
        elif random.random() <= sampl_prob:
            moles_M[i] = 1

    return moles_M

def CalculateMules(moles_M, mule_tau):
    '''
    iterate through moles and add moles with at least mule_tau traffic packets
    '''

    mules_U = {}
    for i in moles_M:
        if moles_M[i] >= mule_tau:
            mules_U[i] = moles_M[i]

    return mules_U

def TuneAccuracy(glob_thresh_T, switch_mem, comm_budget, train_data, observers_l, ingress_switches_k):
    '''
    determine the accuracy of the System
    '''

    accuracy_max = 0
    mole_tau     = GetSampling(switch_mem, train_data, glob_thresh_T)
    sampl_prob   = 1 / mole_tau

    eps_min = max(ingress_switches_k / glob_thresh_T, 0) # Theorem 1?
    eps_max = min(observers_l / ingress_switches_k, 1) # Theorem 2?

    sigma   = observers_l / glob_thresh_T # Theorem 4
    epsilon = eps_max

    while (eps_min <= epsilon and epsilon <= eps_max):
        report_thresh_R, mules_U, report_prob, mule_tau = DeriveReporting(comm_budget, epsilon, observers_l, sampl_prob)

        accuracy = GetAccuracy(train_data, report_thresh_R, glob_thresh_T, mules_U, report_prob, sampl_prob, mule_tau)

        if accuracy >= accuracy_max:
            eps_max = epsilon
            epsilon = epsilon - sigma
            accuracy_max = accuracy
        else:
            break

    # we use the last epsilon that still worked
    print("TuneAccuracy: epsilon = {0}".format(eps_max))

    report_thresh_R, mules_U, report_prob, mule_tau = DeriveReporting(comm_budget, eps_max, observers_l, sampl_prob)

    return eps_max, mule_tau, report_prob 

# determine the accuracy of the System using this parameter configuration
def GetAccuracy(train_data, report_thresh_R, glob_thresh_T, mules_U, report_prob, sampl_prob, mule_tau):
    found_elephants = []
    real_elephants  = []

    for i in mules_U:
        possible_reports = 0
        possible_reports = int(mules_U[i] // mule_tau)

        report_count = 0
        for j in range(possible_reports):
            if random.random() <= report_prob:
                report_count = report_count+1

        if report_count >= report_thresh_R:
            found_elephants.append(i)

    real_count = {}
    for flow in train_data:
        if flow in real_count:
            real_count[flow] = real_count[flow]+1
        else:
            real_count[flow] = 1

    for flow in real_count:
        if real_count[flow] >= glob_thresh_T:
            real_elephants.append(flow)

    tp, fp, fn = performance(found_elephants, real_elephants)

    try:
        precision = tp/(tp+fp)
    except ZeroDivisionError:
        raise ValueError("Error: zero division while calculating precision")
    try:
        re = tp/(tp+fn)
    except ZeroDivisionError:
        raise ValueError("Error: zero division while calculating precision")

    # we use the F1 score as accuracy
    accuracy = (2 * tp) / (2*tp + fp + fn) 

    print("GetAccuracy: F1 score = {}".format(accuracy))

    return accuracy

# calculate the TP, FP, (TN) and FN of 2 lists (TN can't be calculated, but it isn't needed anyway)
def performance(found_elephants, real_elephants):
    tp = 0
    fp = 0
    fn = 0

    for flow in real_elephants:
        if flow in found_elephants:
            tp = tp+1
        else:
            fn = fn+1

    for flow in found_elephants:
        if flow not in real_elephants:
            fp = fp+1

    print("performance: tp = {0}, fp = {1}, fn = {2}".format(tp, fp, fn))

    return tp, fp, fn

# if tuningparameters.py gets run as script
if __name__ == "__main__":
    print("running tuningparameters.py as a script")

    # Generate a list with random entries. Used for debugging.
    def randomlist(size):
        lisst = []
        for i in range(size):
            lisst.append(random.randint(0,50))
        return lisst

    # Get arguments from argparse.
    parser = parser()
    pcap_path = parser[0]
    glob_thresh_T = parser[1]
    comm_budget = parser[2]
    switch_mem = parser[3]
    ingress_switches_k = 10
    observers_l = 2

    train_data = pcap_to_list(pcap_path)

    # Calculate epsilon for the given parameters.
    eps_max, mule_tau, report_prob = TuneAccuracy(glob_thresh_T, switch_mem, comm_budget, train_data, observers_l, ingress_switches_k)

    # return epsilon, tau, report_prob
    print("epsilon = {0}, tau = {1}, report_prob = {2}".format(eps_max, mule_tau, report_prob))
