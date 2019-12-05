import argparse
import json
import re

import numpy as np

from scapy.all import rdpcap
from scapy.all import Ether, IP, UDP, TCP


def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')
    parser.add_argument(
        '--p',
        type=str,
        required = True,
        help = 'Path to .pcap file'
    )
    parser.add_argument(
        '--perc',
        type=float,
        required = False,
        default=99.9,
        help = 'The percentile on the flow count to get the global threshold'
    )

    args = parser.parse_args()

    return args.p, args.perc

'''
Read the specified .pcap file and count how many packets for each flow 
'''
def flow_counter(pcap_path):
    real_count = {}

    pkts = rdpcap(pcap_path)

    for pkt in pkts:
        if IP in pkt:
            try:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                src_port = pkt[IP].sport
                dst_port = pkt[IP].dport
            except:
                continue

            five_tuple = str((src_ip, dst_ip, src_port, dst_port, protocol))

            '''
            If this five_tuple was never seen before add it into the dictionary
            real_count with a value of 1, if it was already seen simply increase
            the value of that flow in the dictionary.
            '''
            if five_tuple in real_count:
                real_count[five_tuple] = real_count[five_tuple]+1
            else:
                real_count[five_tuple] = 1

    print("Found {0} flows".format(len(real_count)))

    return real_count

def get_percentile(real_count, percentile):
    count_array = []
    for flow_count in real_count.values():
        count_array.append(flow_count)

    count_array = np.array(count_array)

    return int(np.percentile(count_array, percentile))

def write_json(global_threshold, flow_count, pcap_file, pcap_file_name, percentile):
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

    threshold_key  = "{0}_global_threshold_{1}".format(pcap_file_name, percentile)
    flow_count_key = "{0}_flow_count".format(pcap_file_name)

    json_decoded[threshold_key]  = global_threshold
    json_decoded[flow_count_key] = flow_count 

    with open('global_thresholds.json', 'w+') as json_file:
        json.dump(json_decoded, json_file, indent=4)
        json_file.close()

    print("Wrote global_threshold for {0} to file global_threshold.json".format(pcap_file))


if __name__ == '__main__':
    pcap_path, percentile = parser()

    # extract the filename of the pcap file (without the filepath)
    pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", pcap_path).group(2)

    real_count = flow_counter(pcap_path)

    # get the percentile of the flow counts
    global_threshold = get_percentile(real_count, percentile)

    print("{0} has {1} flows and global_threshold ({2}) = {3}".format(pcap_file_name, len(real_count), percentile, global_threshold))

    write_json(global_threshold, len(real_count), pcap_path, pcap_file_name, percentile)
