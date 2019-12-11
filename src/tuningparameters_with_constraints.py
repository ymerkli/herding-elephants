from __future__ import division

import random
import argparse
import os
import json
import dpkt
import re
import csv

from scapy.all import *
from dpkt.compat import compat_ord

global_thresh_to_percentile_5m = {
    239: '99',
    1728: '99_9',
    5577: '99_99'
}

global_thresh_to_percentile_100k = {
    50: '99',
    247: '99_9',
    1091: '99_99'
}

global_thresh_to_percentile_400k = {
    91: '99',
    470: '99_9',
    1504: '99_99'
}

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
        # for each packet we have the chance to sample
        for _ in range(pkt_count):
            if (random.random()) <= sampl_prob:
                moles_M[flow] = pkt_count
                break

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
        report_prob = min(comm_budget_c * mule_tau / (float(glob_thresh_T) * len(mules_U)), 1)
        #report_prob = comm_budget_c * mule_tau / (float(glob_thresh_T) * len(mules_U))

    # if no mules found, always report
    except ZeroDivisionError:
        report_prob = 1

    report_thresh_R = max(int(observers_l * report_prob / float(glob_thresh_T)), 1)
    #report_thresh_R = int(observers_l * report_prob / float(glob_thresh_T))

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

    return f1_score, precision, recall

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

    #print("performance: tp = {0}, fp = {1}, fn = {2}".format(tp, fp, fn))

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
        f1_max (float):             The maximum F1 score which is achieved with the optimal set of parameters
    '''

    f1_max               = 0
    mole_tau, sampl_prob = GetSampling(switch_mem, real_count, glob_thresh_T)
    sampl_prob           = 1 / float(mole_tau)

    eps_min = max(ingress_switches_k / glob_thresh_T, 0) # Theorem 1?
    eps_max = min(observers_l / ingress_switches_k, 1) # Theorem 2?

    sigma   = observers_l / float(glob_thresh_T) # Theorem 4
    epsilon = eps_max

    while (eps_min <= epsilon and epsilon <= eps_max):
        report_thresh_R, mules_U, report_prob, mule_tau = DeriveReporting(comm_budget_c, epsilon, observers_l, sampl_prob, real_count)

        f1_score, precision, recall = GetAccuracy(real_count, real_elephants, report_thresh_R, glob_thresh_T, mules_U, report_prob, sampl_prob, mule_tau)

        if f1_score >= f1_max:
            eps_max = epsilon
            epsilon = epsilon - sigma
            f1_max  = f1_score
        else:
            break

    # we use the last epsilon that still worked
    print("TuneAccuracy: best epsilon = {0}, max F1 score = {1}".format(eps_max, f1_max))

    report_thresh_R, mules_U, report_prob, mule_tau = DeriveReporting(comm_budget_c, eps_max, observers_l, sampl_prob, real_count)

    return eps_max, mule_tau, report_prob, report_thresh_R, sampl_prob, f1_max

def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')

    parser.add_argument(
        '--lbs',
        required = True,
        type = int,
        help = 'Lower bound for switch memory'
    )

    parser.add_argument(
        '--ubs',
        type = int,
        required = True,
        help = 'Upper bound for switch memory'
    )

    parser.add_argument(
        '--lbc',
        required = True,
        type = int,
        help = 'Lower bound for communication budget'
    )

    parser.add_argument(
        '--ubc',
        type = int,
        required = True,
        help = 'Upper bound for communication budget'
    )

    parser.add_argument(
        '--p',
        required = True,
        help = 'Path to .pcap file'
    )

    parser.add_argument(
        '--t',
        type = int,
        required = True,
        help = 'global threshold'
    )

    args = parser.parse_args()

    return args.lbs, args.ubs,args.lbc, args.ubc, args.p, args.t


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

    switch_mem_list     = [10000, 20000, 40000, 60000, 100000]
    comm_budget_list    = [20000, 40000, 60000, 80000, 100000]

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

    lower_bound_state, upper_bound_state, lower_bound_comm, upper_bound_comm, pcap_path, glob_thresh_T = parser()

    if (re.findall("100k", pcap_path) != [] ):
        real_count_path = "../evaluation/data/real_count_100k.json"
        real_elephants_path = "../evaluation/data/real_elephants_100k_{0}.json".format(global_thresh_to_percentile_100k[glob_thresh_T])
        parameters_state_file_path = "../parameters/constrained_state/parameters_100k.csv"
        parameters_comm_file_path = "../parameters/constrained_comm/parameters_100k.csv"
    if (re.findall("400k", pcap_path) != [] ):
        real_count_path = "../evaluation/data/real_count_400k.json"
        real_elephants_path = "../evaluation/data/real_elephants_100k_{0}.json".format(global_thresh_to_percentile_400k[glob_thresh_T])
        parameters_state_file_path = "../parameters/constrained_state/parameters_400k.csv"
        parameters_comm_file_path = "../parameters/constrained_comm/parameters_400k.csv"

    real_count = {}
    if os.path.exists(real_count_path):
        with open(real_count_path) as json_file:
            real_count = json.load(json_file)
            json_file.close()
    else:
        raise ValueError("Error: didnt find real count JSON: {0}".format(real_count_path))
    print("Read {0} to dict".format(real_count_path))

    real_elephants = {}
    if os.path.exists(real_elephants_path):
        with open(real_elephants_path) as json_file:
            real_elephants = json.load(json_file)
            json_file.close()
    else:
        raise ValueError("Error: didnt find real elephants JSON: {0}".format(real_elephants_path))
    real_elephants = real_elephants['real_elephants']
    print("Read {0} to dict".format(real_elephants_path))

    '''
    How many ingress switches and how many ingress switches see a flow
    '''
    ingress_switches_k = 10
    observers_l        = 2
    nr_eval_rounds     = 20
    # unconstrained communication
    comm_budget_c = 90000

    switch_mem = lower_bound_state
    difference = upper_bound_state - lower_bound_state

    with open(parameters_state_file_path, 'w') as csv_file:
        parameter_names = ['epsilon','report_prob','report_thresh_R','sampling_prob', 'f1_score']
        writer = csv.DictWriter(csv_file, fieldnames=parameter_names)
        writer.writeheader()
        print("Starting calculation of memory constraints parameters")
        while (switch_mem <= upper_bound_state):

            switch_mem += difference/nr_eval_rounds

            # Calculate epsilon for the given parameters.
            eps, mule_tau, report_prob, report_thresh_R, sampl_prob, f1_score = TuneAccuracy(\
                glob_thresh_T, switch_mem, comm_budget_c, real_count, real_elephants, observers_l, ingress_switches_k\
            )
            writer.writerow({'epsilon': eps,'report_prob': report_prob,'report_thresh_R': report_thresh_R,'sampling_prob': sampl_prob, 'f1_score': f1_score})

    # unconstrained memory
    switch_mem = 400000

    comm_budget_c = lower_bound_comm
    difference = upper_bound_comm - lower_bound_comm

    with open(parameters_comm_file_path, 'w') as csv_file:
        parameter_names = ['epsilon','report_prob','report_thresh_R','sampling_prob', 'f1_score']
        writer = csv.DictWriter(csv_file, fieldnames=parameter_names)
        writer.writeheader()
        print("Starting calculation of communication constraints parameters")
        while (comm_budget_c <= upper_bound_comm):

            comm_budget_c += difference/nr_eval_rounds

            # Calculate epsilon for the given parameters.
            eps, mule_tau, report_prob, report_thresh_R, sampl_prob, f1_score = TuneAccuracy(\
                glob_thresh_T, switch_mem, comm_budget_c, real_count, real_elephants, observers_l, ingress_switches_k\
            )
            writer.writerow({'epsilon': eps,'report_prob': report_prob,'report_thresh_R': report_thresh_R,'sampling_prob': sampl_prob, 'f1_score': f1_score})
