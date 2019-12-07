import argparse
import json
import re
import numpy as np
import socket
import dpkt

from dpkt.compat import compat_ord
from scapy.all import *


def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')
    parser.add_argument('--p', required = True, help = 'Path to .pcap file')
    parser.add_argument('--perc', type = float, required = True, help = 'The percentile which was used for the global threshold')
    args = parser.parse_args()

    return args.p, args.perc

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

'''
Read the specified .pcap file and count how many packets for each flow 
'''
def flow_counter(pcap_path):
    real_count = {}
    groups = []

    pcap_file = open(pcap_path)
    pkts = dpkt.pcap.Reader(pcap_file)

    pkt_counter = 0
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

            five_tuple = str((src_ip, dst_ip, src_port, dst_port, protocol))
            print(pkt_counter, five_tuple)

            srcIP_str = str(src_ip)
            dstIP_str = str(dst_ip)
            srcGroup = re.match(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',srcIP_str).group(1)
            dstGroup = re.match(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',dstIP_str).group(1)
            group = (srcGroup, dstGroup)
            if group not in groups:
                groups.append(group)
            '''
            If this five_tuple was never seen before add it into the dictionary
            real_count with a value of 1, if it was already seen simply increase
            the value of that flow in the dictionary.
            '''
            if five_tuple in real_count:
                real_count[five_tuple] = real_count[five_tuple]+1
            else:
                real_count[five_tuple] = 1

        pkt_counter += 1

    print("Found {0} flows".format(len(real_count)))

    return real_count, len(groups)

def get_percentile(real_count, percentile):
    count_array = []
    for flow_count in real_count.values():
        count_array.append(flow_count)

    count_array = np.array(count_array)

    return int(np.percentile(count_array, percentile))

def write_json(global_threshold, flow_count, group_count, pcap_file, pcap_file_name, percentile):
    '''
    Read existing json file or create it if not existing and write into json

    Args:
        real_elephants (array): Array of 5-tuples with all heavy hitter flows
        pcap_file (str):        The file path to the pcap file
    '''

    json_decoded = {}
    if os.path.exists('global_thresholds.json'):
        with open('global_thresholds.json') as json_file:
            json_decoded = json.load(json_file)
            json_file.close()

    threshold_key   = "{0}_global_threshold_{1}".format(pcap_file_name, percentile)
    flow_count_key  = "{0}_flow_count".format(pcap_file_name)
    group_count_key = "{0}_group_count".format(pcap_file_name)

    json_decoded[threshold_key]   = global_threshold
    json_decoded[flow_count_key]  = flow_count 
    json_decoded[group_count_key] = group_count

    with open('global_thresholds.json', 'w+') as json_file:
        json.dump(json_decoded, json_file, indent=4)
        json_file.close()

    print("Wrote global_threshold for {0} to file global_threshold.json".format(pcap_file))


if __name__ == '__main__':
    pcap_path, percentile = parser()

    # extract the filename of the pcap file (without the filepath)
    pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", pcap_path).group(2)

    real_count, num_groups = flow_counter(pcap_path)

    # get the 99.99th percentile of the flow counts
    global_threshold = get_percentile(real_count, percentile)

    print("{0} has {1} flows, {2} groups and global_threshold ({3}th percentile) = {4}".format(
        pcap_file_name, len(real_count), num_groups, percentile, global_threshold
    ))

    write_json(global_threshold, len(real_count), num_groups, pcap_path, pcap_file_name, percentile)
