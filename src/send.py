#!/usr/bin/env python
import sys
import socket
import random
import re
import argparse

from scapy.all import sendp, get_if_list, get_if_hwaddr, rdpcap
from scapy.all import Ether, IP, UDP, TCP
from subprocess import Popen, PIPE

def get_if():
    '''
    Returns the interface of the host we're currently on

    Returns:
        iface (str): The interface name
    '''

    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def get_dst_mac(ip):
    '''
    Looks for the next hop mac for a given destination IP

    Args:
        ip (str): The IP we want to send to

    Returns:
        mac (str): The next hop MAC address
    '''

    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def send_packet(iface, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, protocol, random_ports, manual_mode):
    '''
    Sends a single packet for the given parameters
    '''

    if manual_mode == True:
        raw_input("Press the return key to send a packet:")

    print "Sending on interface %s to %s" % (iface, str(addr))
    print(src_ip, dst_ip, src_port, dst_port, protocol)

    # assemble the packet
    pkt =  Ether(src=ether_src, dst=ether_dst)
    pkt = pkt /IP(src=src_ip, dst=dst_ip, tos=0)
    if random_ports:
        pkt = pkt /TCP(sport=random.randint(49152,65535), dport=random.randint(5000,60000))
    else:
        pkt = pkt /TCP(sport=src_por, tdport=dst_port)
    sendp(pkt, iface=iface, verbose=False)

def send_pcap(pcap_path, internal_host_ip, manual_mode):
    '''
    Reads the provided pcap file and iterates over all packets, sending each to the provided host IP
    '''

    iface = get_if()
    # read the provide pcap file
    pcap_packets = rdpcap(pcap_path)

    for pkt in pcap_packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            src_port = pkt[IP].sport
            dst_port = pkt[IP].dport

            ether_src = get_if_hwaddr(iface)
            # we want to send all packets to a host inside the network
            # Since not all IPs in the pcap packets are mapped to the interal host, we use its real IP
            # to get the destination MAC
            ether_dst = get_dst_mac(internal_host_ip)
            if not ether_dst:
                print "Mac address for %s was not found in the ARP table" % internal_host_ip
                continue

            send_packet(iface, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, protocol, random_ports, manual_mode)

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

    args = parser.parse_args()
    return args.p, args.i, args.m

if __name__ == '__main__':
    pcap_path, internal_host_ip, manual_mode = parser()

    send_pcap(pcap_path, internal_host_ip, manual_mode)
