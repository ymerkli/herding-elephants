import argparse
import json
import re
import dpkt
import socket

from dpkt.compat import compat_or
from scapy.all import *

def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')
    parser.add_argument('--p', required = True, help = 'Path to .pcap file')
    parser.add_argument('--t', type = int, required = True, help = 'Global Threshold')
    parser.add_argument('--perc', type = float, required = True, help = 'The percentile which was used for the global threshold')

    args = parser.parse_args()

    return args.p, args.t, args.perc

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
Read the specified .pcap file and write out all the elephants (flows that are
at least glob_thresh times received) in it.
'''
def real_elephants(pcap_path, glob_thresh):
    real_elephants = []
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

    '''
    If we have seen a flow at least glob_thresh times it is an elephant and thus
    add it into our list of elephants.
    '''
    for flow in real_count:
        if real_count[flow] >= glob_thresh:
            real_elephants.append(str(flow))

    print("Found {0} groups".format(len(groups)))
    print("Found {0} heavy hitter flows".format(len(real_elephants)))

    return real_elephants, len(groups)

'''
Write the real_elephants into real_elephants.json.
'''
def write_json(real_elephants, num_groups, pcap_path, percentile):
    '''
    Read existing json file or create it if not existing and write into json

    Args:
        real_elephants (array): Array of 5-tuples with all heavy hitter flows
        pcap_file (str):        The file path to the pcap file
    '''

    json_decoded = {}
    real_elephants_path = "real_elephants_{0}.json".format(percentile)

    if os.path.exists(real_elephants_path):
        with open(real_elephants_path) as json_file:
            json_decoded = json.load(json_file)
            json_file.close()

    pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", pcap_path).group(2)

    json_decoded['real_elephants'] = real_elephants
    json_decoded['num_groups']     = num_groups

    with open(real_elephants_path, 'w+') as json_file:
        json.dump(json_decoded, json_file, indent=4)
        json_file.close()

    print("Wrote real heavy hitters to ", real_elephants_path)

if __name__ == '__main__':
    pcap_path, glob_thresh, percentile = parser()

    real_elephants, num_groups = real_elephants(pcap_path, glob_thresh)

    write_json(real_elephants, num_groups, pcap_path, percentile)
