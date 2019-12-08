from __future__ import division

import random
import argparse
import os
import json
import dpkt

from scapy.all import *
from dpkt.compat import compat_ord

global_thresh_to_percentile = {
    239: '99',
    1728: '99_9',
    5577: '99_99'
}

def pcap_to_list(pcap_path):
    '''
    Parses a pcap file and creates a list of five-tuples

    Args:
        pcap_path (str): The path to the pcap file

    Returns:
        packets (list): A list of 5-tuples (flows)
    '''

    packets = []

    pcap_file = open(pcap_path)
    pkts = dpkt.pcap.Reader(pcap_file)

    for ts, buf in pkts:

        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            tcp = ip.data
            try:
                src_ip   = inet_to_str(ip.src)
                dst_ip   = inet_to_str(ip.dst)
                protocol = ip.p
                src_port = tcp.sport
                dst_port = tcp.dport
            except:
                continue

            five_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
            packets.append(five_tuple)

    return packets

##### Given #####
# (T) glob_thresh_T -> Global threshold
# (C) comm_budget_c -> Communication budget per switch
# (S) switch_mem -> Memory budget per switch (# counters)
# (k) ingress_switches_k -> Total number of ingress switches
# (l) observers_l -> Number of switches which observe a flow
# (D) real_count ->  A dict of flows (5-tuple) with the respective packet count

##### Determine #####
# epsilon -> Approximation Factor
# (tau) mule_tau -> Local (Mule) threshold
# (M) moles_M -> (dict) Set of moles observed at switch
# (U) mules_U -> (dict) Set of mules at a switch
# (r) report_prob -> Reporting probability to coordinator
# (s) sampl_prob -> Sampling probability at a switch
# (R) report_thresh_R -> coordinator identifies as mule as a network-wide
#                      heavy hitter if it receives R reports


def GetSampling(switch_mem, real_count, mole_tau):
    '''
    Determine the highest possible sampling probability, given the memory constraint

    Args:
        switch_mem (int):   The memory budget of the switch
        real_count (dict):  A dict of flows (5-tuple) with the respective packet count
        mole_tau (int):     The count threshold for a flow to become a mole

    Returns:
        mole_tau (int):     The resulting mole_tau
    '''

    sampl_prob = 1/(float(mole_tau))
    moles_M    = CalculateMoles(real_count, sampl_prob)

    while len(moles_M) < switch_mem and mole_tau > 1:
        mole_tau    -= 1
        sampl_prob  = 1/float(mole_tau)
        moles_M     = CalculateMoles(real_count, sampl_prob)

    return mole_tau, sampl_prob

def CalculateMoles(real_count, sampl_prob):
    '''
    Iterate through Training Data and add a sample with probability sampl_prob to moles

    Args:
        real_count (dict):      A dict with flows (5-tuple) as keys and packet count (int) for the respective flow as values
        sampl_prob (float):     The probability for which we sample a flow at a switch

    Returns:
        moles_M (dict):         A dict with mole flows (5-tuples) as keys and packet count (int) for the respective mole flow as values
    '''

    moles_M = {}
    for flow, pkt_count in real_count.items():
        if random.random() <= sampl_prob:
            moles_M[flow] = pkt_count

    return moles_M

def CalculateMules(moles_M, mule_tau):
    '''
    Iterate through moles and add moles with at least mule_tau traffic packets

    Args:
        moles_M (dict):         A dict with mole flows (5-tuples) as keys and packet count (int) for the respective mole flow as values
        mule_tau (int):         The threshold on the number of packets for which we promote a mole flow to a mule flow

    Returns:
        mules_U (dict):         A dict with mule flows (5-tuples) as keys and packet count (int) for the respective flow as values
    '''

    mules_U = {}
    for flow, pkt_count in moles_M.items():
        if pkt_count >= mule_tau:
            mules_U[flow] = pkt_count

    return mules_U

def DeriveReporting(comm_budget_c, epsilon, observers_l, sampl_prob, real_count):
    '''
    configures reporting parameters based on the gives contraints
    '''

    mule_tau = epsilon * glob_thresh_T / float(observers_l)
    moles_M  = CalculateMoles(real_count, sampl_prob)
    mules_U  = CalculateMules(moles_M, mule_tau)

    try:
        report_prob = min(comm_budget_c * mule_tau / (glob_thresh_T * len(mules_U)), 1)

    # if no mules found, always report
    except ZeroDivisionError:
        report_prob = 1

    report_thresh_R = max(int(observers_l * report_prob / float(glob_thresh_T)), 1)

    print("DeriveReporting: report_thresh_R = {0}, mules_U = {1}, report_prob = {2}, mule_tau = {3}".format(report_thresh_R, "x", report_prob, mule_tau))

    return report_thresh_R, mules_U, report_prob, mule_tau

def GetAccuracy(real_count, real_elephants, report_thresh_R, glob_thresh_T, mules_U, report_prob, sampl_prob, mule_tau):
    '''
    Determine the accuracy of the System using this parameter configuration

    Args:
        real_count (dict):      A dict with flows (5-tuple) as keys and packet count (int) for the respective flow as values
        real_elephants (list):  A list of flows (5-tuples) which are all flows whose packet count exceeds the global threshold
        report_thresh_R (int):  The threshold on the number of reports for which we promote a mule flow to a elephant flow
        glob_thresh_T (int):    The threshold on the total number of packets of a flow fot the flow to be an elephant flow
        mules_U (dict):         A dict with mule flows (5-tuples) as keys and packet count (int) for the respective flow as values
        report_prob (float):    The probability for which we report a flow when the flow's packet count has reached the mule threshold (mule_tau)
        sampl_prob (float):     The probability for which we sample a flow at a switch
        mule_tau (int):         The threshold on the number of packets for which we promote a mole flow to a mule flow

    Returns:
        f1_score (float):       The resulting f1 score for the found and real elephants
    '''

    found_elephants = []
    '''
    Iterate over the number of mules
    Run a probability to simulate if we would have reported
    Check if the report count exceeds a threshold and add flow
    to heavy hitter set if so
    '''
    for flow, pkt_count in mules_U.items():
        possible_reports = 0
        possible_reports = int(pkt_count // mule_tau)

        report_count = 0
        for j in range(possible_reports):
            if random.random() <= report_prob:
                report_count = report_count+1

        if report_count >= report_thresh_R:
            found_elephants.append(flow)

    tp, fp, fn = performance(found_elephants, real_elephants)

    f1_score, precision, recall = 0,0,0
    try:
        precision = tp/(tp+fp)
    except ZeroDivisionError:
        raise ValueError("Error: zero division while calculating precision")
    try:
        recall = tp/(tp+fn)
    except ZeroDivisionError:
        raise ValueError("Error: zero division while calculating precision")

    try:
        f1_score = (2 * tp) / (2*tp + fp + fn)
    except ZeroDivisionError:
        raise ValueError("Error: zero division while calculating precision")

    print("GetAccuracy: F1 score = {0}, precision = {1}, recall = {2}".format(f1_score, precision, recall))
    print("Sampling probability: {0}".format(sampl_prob))

    return f1_score

def performance(found_elephants, real_elephants):
    '''
    Calculates true positives, false positives and false negatives based on the provided
    flow sets.

    Args:
        found_elephant (list):  A list of flows (5-tuple) with the flows out algorithm classified
                                as heavy hitters (elephants)
        real_elephants (list):  A list of flows (5-tuples) with all heavy hitter flows

    Returns:
        tp (int):               True positives
        fp (int):               False positives
        fn (int):               False negatives
    '''

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

def TuneAccuracy(glob_thresh_T, switch_mem, comm_budget_c, real_count, real_elephants, observers_l, ingress_switches_k):
    '''
    Determine the accuracy of the System

    Args:
        glob_thresh_T (int):        The threshold on the total number of packets of a flow fot the flow to be an elephant flow
        switch_mem (int):           The memory budget in the switch (number of counters)
        comm_budget_c (int):        The communication budget per switch
        real_count (dict):          A dict with flows (5-tuple) as keys and packet count (int) for the respective flow as values
        real_elephants (list):      A list of flows (5-tuples) which are all flows whose packet count exceeds the global threshold
        observers_l (int):          The number of ingress switches that observe a flow
        ingress_switches_k (int):   The number of ingress switches for in the network

    Returns:
        eps_max (float):            The epsilon for which the highest F1 score was achieved
        mule_tau (int):             The optimal threshold on the number of packets for which we promote a mole flow to a mule flow
        report_prob (float):        The optimal probability for which we report a flow when the flow's packet count has reached the mule threshold (mule_tau)
        report_thresh_R (int):      The optimal threshold on the number of reports for which we promote a mule flow to a elephant flow
        sampl_prob (float):         The optimal probability for which we sample a flow at a switch
        accuracy_max (float):       The maximum accuracy (F1 score) which is achieved with the optimal set of parameters
    '''

    accuracy_max         = 0
    mole_tau, sampl_prob = GetSampling(switch_mem, real_count, glob_thresh_T)
    sampl_prob           = 1 / mole_tau

    eps_min = max(ingress_switches_k / glob_thresh_T, 0) # Theorem 1?
    eps_max = min(observers_l / ingress_switches_k, 1) # Theorem 2?

    sigma   = observers_l / glob_thresh_T # Theorem 4
    epsilon = eps_max

    while (eps_min <= epsilon and epsilon <= eps_max):
        report_thresh_R, mules_U, report_prob, mule_tau = DeriveReporting(comm_budget_c, epsilon, observers_l, sampl_prob, real_count)

        accuracy = GetAccuracy(real_count, real_elephants, report_thresh_R, glob_thresh_T, mules_U, report_prob, sampl_prob, mule_tau)

        if accuracy >= accuracy_max:
            eps_max = epsilon
            epsilon = epsilon - sigma
            accuracy_max = accuracy
        else:
            break

    # we use the last epsilon that still worked
    print("TuneAccuracy: epsilon = {0}".format(eps_max))

    report_thresh_R, mules_U, report_prob, mule_tau = DeriveReporting(comm_budget_c, eps_max, observers_l, sampl_prob, real_count)

    return eps_max, mule_tau, report_prob, report_thresh_R, sampl_prob, accuracy_max

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

def do_tuning(glob_thresh_T, real_count, real_elephants, observers_l, ingress_switches_k):
    '''
    Iterates over a set of switch_mem and comm_budget_c parameters to find the best config

    Args:
        glob_thresh_T (int):        The threshold on the total number of packets of a flow fot the flow to be an elephant flow
        real_count (dict):          A dict with flows (5-tuple) as keys and packet count (int) for the respective flow as values
        real_elephants (list):      A list of flows (5-tuples) which are all flows whose packet count exceeds the global threshold
        observers_l (int):          The number of ingress switches that observe a flow
        ingress_switches_k (int):   The number of ingress switches for in the network

    Returns:
        eps_opt (float):            The epsilon for which the highest F1 score was achieved
        mule_tau_opt (int):         The optimal threshold on the number of packets for which we promote a mole flow to a mule flow
        report_prob_opt (float):    The optimal probability for which we report a flow when the flow's packet count has reached the mule threshold (mule_tau)
        report_thresh_R_opt (int):  The optimal threshold on the number of reports for which we promote a mule flow to a elephant flow
        sampl_prob_opt (float):     The optimal probability for which we sample a flow at a switch
        f1_opt (float):             The maximum accuracy (F1 score) which is achieved with the optimal set of parameters
    '''

    switch_mem_list     = [10000, 20000, 50000, 100000, 200000, 500000]
    comm_budget_list    = [2000, 4000, 6000, 10000, 20000, 50000, 100000]

    f1_opt              = 0
    eps_opt             = 0
    mule_tau_opt        = 0
    report_thresh_R_opt = 0
    report_prob_opt     = 0
    sampl_prob_opt      = 0

    for switch_mem in switch_mem_list:
        for comm_budget_c in comm_budget_list:
            eps, mule_tau, report_prob, report_thresh_R, sampl_prob, f1_score = TuneAccuracy(\
                glob_thresh_T, switch_mem, comm_budget_c, real_count, real_elephants, observers_l, ingress_switches_k\
            )

            if f1_score > f1_opt:
                f1_opt              = f1_score
                eps_opt             = eps
                mule_tau_opt        = mule_tau
                report_thresh_R_opt = report_thresh_R
                report_prob_opt     = report_prob
                sampl_prob_opt      = sampl_prob

    return f1_opt, eps_opt, mule_tau_opt, report_thresh_R_opt, report_prob_opt, sampl_prob_opt

# if tuningparameters.py gets run as script
if __name__ == "__main__":
    print("running tuningparameters.py as a script")

    # Get arguments from argparse.
    pcap_path, glob_thresh_T, comm_budget_c, switch_mem = parser()

    '''
    How many ingress switches and how many ingress switches see a flow
    '''
    ingress_switches_k = 10
    observers_l        = 2

    real_count = {}
    real_count_path = '../evaluation/data/real_count.json'
    if os.path.exists(real_count_path):
        with open(real_count_path) as json_file:
            real_count = json.load(json_file)
            json_file.close()
    else:
        raise ValueError("Error: didnt find real count JSON: {0}".format(real_count_path))
    print("Read {0} to dict".format(real_count_path))

    real_elephants = {}
    real_elephants_path = "../evaluation/data/real_elephants_{0}.json".format(global_thresh_to_percentile[glob_thresh_T])
    if os.path.exists(real_elephants_path):
        with open(real_elephants_path) as json_file:
            real_elephants = json.load(json_file)
            json_file.close()
    else:
        raise ValueError("Error: didnt find real elephants JSON: {0}".format(real_elephants_path))
    real_elephants = real_elephants['real_elephants']
    print("Read {0} to dict".format(real_elephants_path))

    # Calculate epsilon for the given parameters.
    f1_opt, eps_opt, mule_tau, report_thresh_R, report_prob, sampl_prob = do_tuning(glob_thresh_T, real_count, real_elephants, observers_l, ingress_switches_k)

    # return epsilon, tau, report_prob
    f = open("communication_budget_parameters.txt", "w+")
    f.append("With C = {3}: epsilon = {0}, sampling probability = {1} report_thresh_R = {2}\n".format(eps_max, sampl_prob, report_thresh_R, comm_budget_c))
    f.close()
    print("epsilon = {0}, sampling probability = {1} report_thresh_R = {2}".format(eps_max, sampl_prob, report_thresh_R))
    print("Optimum:")
    print("epsilon = {0}, sampling probability = {1} report_thresh_R = {2}, max F1 = {3}".format(eps_opt, sampl_prob, report_thresh_R, f1_opt))
