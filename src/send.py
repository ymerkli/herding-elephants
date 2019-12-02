#!/usr/bin/env python
import argparse
import sys
import socket
import random
import re
import argparse
import time
import json
import os
import random

from p4utils.utils.topology import Topology
from scapy.all import sendp, get_if_list, get_if_hwaddr, rdpcap
from scapy.all import Ether, IP, UDP, TCP
from subprocess import Popen, PIPE
from timeit import default_timer as timer
from p4utils.utils.topology import Topology

def get_tables():
    '''
    Creates three dicts, mapping switch destinations to the MAC of the outgoing interface,
    to the MAC of the destination interface on the switch and to the interface name on the host

    Returns:
        src_mac_table (dict):   The src MAC table
        dst_mac_table (dict):   The dst MAC table
        interface_table (dict): The interface name table
    '''

    topo = Topology(db="topology.db")

    src_mac_table   = {}
    dst_mac_table   = {}
    interface_table = {}
    num_switches    = 0

    for sw_dst in topo.get_p4switches():
        # extract switch ID
        match = re.match(r"s(\d+)", sw_dst)
        if match:
            sw_dst_id = int(match.group(1))
            host_if_mac = topo.node_to_node_mac('h1', sw_dst)
            dst_sw_mac  = topo.node_to_node_mac(sw_dst, 'h1')

            src_mac_table[sw_dst] = host_if_mac
            dst_mac_table[sw_dst] = dst_sw_mac
            interface_table[sw_dst] = "h1-eth{0}".format(sw_dst_id-1)

            num_switches += 1

    return src_mac_table, dst_mac_table, interface_table, num_switches

def send_packet(iface, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, protocol, manual_mode):
    '''
    Sends a single packet for the given parameters
    '''

    if manual_mode == True:
        raw_input("Press the return key to send a packet:")

    print("Sending on interface {0}: ({1}, {2}, {3}, {4}, {5})".format(
            iface, src_ip, dst_ip, src_port, dst_port, protocol)
    )

    # assemble the packet
    pkt = Ether(src=ether_src, dst=ether_dst)
    pkt = pkt /IP(src=src_ip, dst=dst_ip, tos=0)
    pkt = pkt /TCP(sport=src_port, dport=dst_port)
    sendp(pkt, iface=iface, verbose=False)

def send_pcap(pcap_path, internal_host_ip, global_threshold, manual_mode, count_real_elephants):
    '''
    Reads the provided pcap file and iterates over all packets, sending each to the provided host IP

    Args:
        pcap_path (str):             The file path to the pcap file to send
        internal_host_ip (str):      The IP of the host in the mininet where traffic should be sent to
        global_threshold (int):      The threshold for a flow to be a heavy hitter. Only need when
                                     count_real_elephants is set
        manual_mode (bool):          If true, you have to press enter to send every single packet
        count_real_elephants (bool): If true, we will count flows and keep track of heavy hitters
                                     and then write them to JSON
    '''
    real_elephants = []
    real_count     = {}
    groups         = []

    num_switches                 = None
    secondary_switch_probability = 0.05

    # read the provide pcap file
    pcap_packets = rdpcap(pcap_path)

    start_time     = timer()
    packet_counter = 0

    src_mac_table, dst_mac_table, interface_table, num_switches = get_tables()
    '''
    Issue with P4Utils: if a host has multiple connections to switches, the MAC address
    of the interface on the host pointing to the first and last switch are equivalent.
    To prevent this, we add one more switch than necessary but never use it
    '''
    if num_switches > 9:
        num_switches -= 1

    # we want to send all packets to a host inside the network
    # Since not all IPs in the pcap packets are mapped to the interal host, we use its real IP
    # to get the destination MAC

    ether_dst = get_dst_mac()
    if not ether_dst:
        raise ValueError("Mac address for %s was not found in the ARP table" % internal_host_ip)

    for pkt in pcap_packets:
        if IP in pkt:
            try:
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
                protocol = pkt[IP].proto
                src_port = pkt[IP].sport
                dst_port = pkt[IP].dport

                '''
                Packets from a given source IP are processed at a 'prefered' ingress switch with probability
                p = 0.95 and probability (1-p) at the other ingress switch.
                This main ingress switch (its ID) is selected based on the hash of the source IP.
                The secondary ingress switch (its ID) is: <NUM_SWITCHES> - <MAIN_SWITCH_ID> + 1
                '''
                ingress_switch_id  = hash(src_ip) % num_switches + 1

                if random.random() < secondary_switch_probability:
                    ingress_switch_id = num_switches - ingress_switch_id + 1

                ingress_switch = "s{0}".format(ingress_switch_id)
                ether_src      = src_mac_table[ingress_switch]
                ether_dst      = dst_mac_table[ingress_switch]
                iface          = interface_table[ingress_switch]

                if count_real_elephants:
                    five_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
                    src_group = re.match(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', src_ip).group(1)
                    dst_group = re.match(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', dst_ip).group(1)
                    group = (src_group, dst_group)
                    if group not in groups:
                        groups.append(group)

                    '''
                    If this five_tuple was never seen before add it into the dictionary
                    real_count with a value of 1, if it was  already seen simply increase
                    the value of that flow in the dictionary.
                    '''
                    if five_tuple in real_count:
                        real_count[five_tuple] += 1
                    else:
                        real_count[five_tuple] = 1

                send_packet(iface, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, protocol, manual_mode)
                packet_counter += 1

            except Exception as e:
                print('Could not extract all 5-tuple fields: ', e)
                continue

    end_time = timer()

    for flow in real_count:
        if real_count[flow] >= global_threshold:
            real_elephants.append(str(flow))

    print("Finished, this took {0} seconds".format(end_time - start_time))
    print("Sent {0} packets".format(packet_counter))
    if count_real_elephants:
        print("Found {0} groups".format(len(groups)))
        print("Found {0} heavy hitters flows:\n".format(len(real_elephants)))
        print(real_elephants)
        write_json(real_elephants, pcap_path)

def write_json(real_elephants, pcap_file):
    '''
    Read existing json file or create it if not existing and write into json

    Args:
        real_elephants (array): Array of 5-tuples with all heavy hitter flows
        pcap_file (str):        The file path to the pcap file
    '''

    json_decoded = {}
    if os.path.exists('real_elephants.json'):
        with open('real_elephants.json') as json_file:
            json_decoded = json.load(json_file)
            json_file.close()

    pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", pcap_file).group(2)

    flow_key  = "{0}_real_elephants".format(pcap_file_name)
    count_key = "{0}_elephant_count".format(pcap_file_name)

    json_decoded[flow_key]  = real_elephants
    json_decoded[count_key] = len(real_elephants)

    with open('real_elephants.json', 'w+') as json_file:
        json.dump(json_decoded, json_file, indent=4)
        json_file.close()

    print("Wrote heavy hitters to json")

def parser():
    '''
    Parses the CLI arguments for the pcap file path and whether manual mode should be used
    '''
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')

    parser.add_argument(
        "--p",
        type=str,
        required=True,
        help='The file path of the pcap file to be parsed'
    )

    parser.add_argument(
        "--i",
        type=str,
        required=True,
        help="The IP of the internal host where we want to send traffic to"
    )

    parser.add_argument(
        "--m",
        help = "Send packets manually",
        action = 'store_true'
    )

    parser.add_argument(
        "--t",
        type=int,
        required=False,
        help="The global threshold"
    )

    parser.add_argument(
        "--re",
        action='store_true',
        help='Set flag if you want to count real elephants and write them to json'
    )

    args = parser.parse_args()

    return args.p, args.i, args.m, args.t, args.re

if __name__ == '__main__':
    pcap_path, internal_host_ip, manual_mode, global_threshold, count_real_elephants = parser()

    if count_real_elephants and not global_threshold:
        print("Error: When --re is set, you need to provide a global threshold. Use --t")
        exit(0)

    send_pcap(pcap_path, internal_host_ip,  global_threshold, manual_mode, count_real_elephants)
