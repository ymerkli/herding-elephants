import argparse
from scapy.all import *
import json
import re

def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')
    parser.add_argument('--p', required = True, help = 'Path to .pcap file')
    parser.add_argument('--t', type = int, required = True, help = 'Global Threshold')
    args = parser.parse_args()
    return args.p, args.t

'''
Read the specified .pcap file and write out all the elephants (flows that are
at least glob_thresh times received) in it.
'''
def real_elephants(pcap_path, glob_thresh):
    real_elephants = []
    real_count = {}
    groups = []

    pkts = rdpcap(pcap_path)

    for pkt in pkts:
        '''
        flag signals whether to include IPv6 packets or not.
        '''
        flag = 0
        if IP in pkt:
            try:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                src_port = pkt[IP].sport
                dst_port = pkt[IP].dport
                flag = 1
            except:
                continue
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

    '''
    If we have seen a flow at least glob_thresh times it is an elephant and thus
    add it into our list of elephants.
    '''
    for i in real_count:
        if real_count[i] >= glob_thresh:
            real_elephants.append(i)

    print("Found {0} groups".format(len(groups)))
    print(groups)
    print("Found {0} heavy hitter flows:\n".format(len(real_elephants)))
    print(real_elephants)

    return real_elephants

'''
Write the real_elephants into real_elephants.json.
'''
def write_json(real_elephants):
    data = {
        'real_elephants': real_elephants
    }
    with open('real_elephants.json', 'w') as outfile:
        json.dump(data, outfile)
        outfile.close()


if __name__ == '__main__':
    parser = parser()
    pcap_path = parser[0]
    glob_thresh = parser[1]
    real_elephants = real_elephants(pcap_path, glob_thresh)
    write_json(real_elephants)
