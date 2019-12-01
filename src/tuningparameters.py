from __future__ import division
import random
import argparse
from scapy.all import *

def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')
    parser.add_argument('--p', required = True, help = 'Path to .pcap file')
    parser.add_argument('--t', type = int, required = True, help = 'Global Threshold')
    parser.add_argument('--c', type = int, required = True, help = 'Communication budget')
    parser.add_argument('--s', type = int, required = True, help = 'switch memory')
    args = parser.parse_args()
    return args.p, args.t, args.c, args.s

def pcap_to_list(pcap_path):
    packets = []

    pkts = rdpcap(pcap_path)

    for pkt in pkts:
        try:
            '''
            flag signals whether to include IPv6 packets or not.
            '''
            flag = 0

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                src_port = pkt[IP].sport
                dst_port = pkt[IP].dport
                flag = 1
            '''
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                # IPv6 doens't have protocol, but all packets seem to be TCP?
                protocol = 6
                src_port = pkt[IPv6].sport
                dst_port = pkt[IPv6].dport
                flag = 1
                '''

            '''
            When we don't want the IPv6 packets, we can simply make the IPv6 part
            (from 'elif IPv6 ...' to 'flag = 1') a comment.
            '''
            if flag == 1:
                five_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
                packets.append(five_tuple)
        except Exception as e:
            print('Could not extract all 5-tuple fields: ', e)
            continue

    return packets


##### Given #####
# (T) glob_thresh -> Global threshold
# (C) comm_budget -> Communication budget per switch
# (S) switch_mem -> Memory budget per switch (# counters)
# (k) ingress_switches -> Total number of ingress switches
# (l) observers -> Number of switches which observe a flow
# (D) train_data -> (list) Training Data

##### Determine #####
# epsilon -> Approximation Factor
# (tau) mule_tau -> Local (Mule) threshold
# (M) moles -> (dict) Set of moles observed at switch
# (U) mules -> (dict) Set of mules at a switch
# (r) report_prob -> Reporting probability to coordinator
# (s) sampl_prob -> Sampling probability at a switch
# (R) report_thresh -> coordinator identifies as mule as a network-wide
#                      heavy hitter if it receives R reports

# determine the highest possible sampling prob-ability,
# given the memory constraint
def GetSampling(switch_mem, train_data, mole_tau):
    #print("GetSampling started")
    sampl_prob = 1/(mole_tau)
    moles = CalculateMoles(train_data, sampl_prob)
    while len(moles) < switch_mem:
        mole_tau = mole_tau - 1
        sampl_prob = 1/mole_tau
        moles = CalculateMoles(train_data, sampl_prob)
    #print("GetSampling: mole_tau = {0}".format(mole_tau))
    return mole_tau

# configures reporting parameters based on the gives contraints
def DeriveReporting(comm_budget, epsilon, observers, sampl_prob):
    print("DeriveReporting started")
    mule_tau = epsilon * glob_thresh / observers
    moles = CalculateMoles(train_data, sampl_prob)
    mules = CalculateMules(moles, mule_tau)
    try:
        report_prob = min(comm_budget * mule_tau / (glob_thresh * len(mules)), 1)
    # if no mules found, always report
    except ZeroDivisionError:
        report_prob = 1
    report_thresh = max(int(round(observers * report_prob / glob_thresh)),1)
    print("DeriveReporting: report_thresh = {0}, mules = {1}, report_prob = {2}, mule_tau = {3}".format(report_thresh, "x", report_prob, mule_tau))
    return report_thresh, mules, report_prob, mule_tau

# determine the accuracy of the System
def TuneAccuracy(glob_thresh, switch_mem, comm_budget, train_data, observers, ingress_switches):
    print("TuneAccuracy started")
    accuracy_max = 0
    mole_tau = GetSampling(switch_mem, train_data, glob_thresh)
    sampl_prob = 1 / mole_tau
    eps_min = max(observers / glob_thresh, 0) # Theorem 1?
    eps_max = min(ingress_switches/observers, 1) # Theorem 2?
    sigma = observers / glob_thresh # Theorem 4
    epsilon = eps_max
    while (eps_min <= epsilon and epsilon <= eps_max):
        report = DeriveReporting(comm_budget, epsilon, observers, sampl_prob)
        accuracy = GetAccuracy(train_data, report[0], glob_thresh, report[1],
                               report[2], sampl_prob, report[3])
        if accuracy >= accuracy_max:
            eps_max = epsilon
            epsilon = epsilon - sigma
            accuracy_max = accuracy
        else:
            break
    # we use the last epsilon that still worked
    print("TuneAccuracy: epsilon = {0}".format(eps_max))
    report = DeriveReporting(comm_budget, eps_max, observers, sampl_prob)
    return eps_max, report[3], report[2]

# determine the accuracy of the System using this parameter configuration
def GetAccuracy(train_data, report_thresh, glob_thresh, mules, report_prob, sampl_prob, mule_tau):
    print("GetAccuracy started")
    elephants = []
    real_elephants = []

    for i in mules:
        possible_reports = 0
        possible_reports = mules[i]//mule_tau
        possible_reports = int(possible_reports)
        if possible_reports > 0:
            report_count = 0
            for j in range(possible_reports):
                if random.randint(0, 1) <= report_prob:
                    report_count = report_count+1
            if report_count >= report_thresh:
                elephants.append(i)

    real_count = {}
    for i in train_data:
        if i in real_count:
            real_count[i] = real_count[i]+1
        else:
            real_count[i] = 1
    for i in real_count:
        if real_count[i] >= glob_thresh:
            real_elephants.append(i)
    # print("real_count = {}".format(real_count))
    print("len(elephants = {}".format(len(elephants)))
    print("len(real_elephants) = {}".format(len(real_elephants)))
    perf = performance(elephants, real_elephants)

    tp = perf[0]
    fp = perf[1]
    fn = perf[3]

    try:
        pr = tp/(tp+fp)
    except ZeroDivisionError:
        pr = 1
    try:
        re = tp/(tp+fn)
    except ZeroDivisionError:
        re = 1

    # we use the F1 score as accuracy
    accuracy = 2*pr*re/(pr+re)
    print("GetAccuracy: accuracy = {}".format(accuracy))
    return accuracy

# iterate through Training Data and add a sample with probability sampl_prob to moles
def CalculateMoles(train_data, sampl_prob):
    print("CalculateMoles started")
    moles = {}
    for i in train_data:
        if i in moles:
            moles[i] = moles[i]+1
        elif random.randint(0, 1) <= sampl_prob:
            moles[i] = 1
    # print("CalculateMoles: moles = {0}".format(moles))
    print("len(moles)={}".format(len(moles)))
    return moles

# iterate through moles and add moles with at least mule_tau traffic packets
def CalculateMules(moles, mule_tau):
    print("CalculateMules started")
    mules = {}
    for i in moles:
        if moles[i] >= mule_tau:
            mules[i] = moles[i]
    # print("CalculateMules: mules = {0}".format(mules))
    print("len(mules)={}".format(len(mules)))
    return mules

# calculate the TP, FP, (TN) and FN of 2 lists (TN can't be calculated, but it isn't needed anyway)
def performance(my_list, real_list):
    print("performance started")
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for i in real_list:
        if i in my_list:
            tp = tp+1
        if i not in my_list:
            fp = fp+1

    for i in my_list:
        if i not in real_list:
            fn = fn+1

    print("performance: tp = {0}, fp = {1}, tn = {2}, fn = {3}".format(tp, fp, tn, fn))
    return tp, fp, tn, fn

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
    glob_thresh = parser[1]
    comm_budget = parser[2]
    switch_mem = parser[3]
    ingress_switches = 10
    observers = 2
    train_data = pcap_to_list(pcap_path)

    # Calculate epsilon for the given parameters.
    parameters = TuneAccuracy(glob_thresh, switch_mem, comm_budget, train_data, observers, ingress_switches)

    # return epsilon, tau, report_prob
    print("epsilon = {0}, tau = {1}, report_prob = {2}".format(parameters[0], parameters[1], parameters[2]))
