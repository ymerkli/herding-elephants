#!/usr/bin/env python
import sys
import socket
import random
import time
from threading import Thread, Event
from scapy.all import *
import argparse


def get_if():
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

def send_packet(iface, ether_dst, random_ports, src_ip, dst_ip, src_port, dst_port, protocol):

    if manual == True:
        raw_input("Press the return key to send a packet:")
    print "Sending on interface %s\n" % (iface)
    pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt /IP(src=src_ip, dst=dst_ip, tos=0)
    if random_ports:
        pkt = pkt /TCP(dport=random.randint(5000,60000), sport=random.randint(49152,65535))
    else:
        pkt = pkt /TCP(dport=dst_port, sport=src_port)
    print(src_ip, dst_ip, src_port, dst_port, protocol)
    sendp(pkt, iface=iface, verbose=False)

def main():

    ether_dst = sys.argv[1]
    random_ports = False
    if len(sys.argv) > 2:
        if sys.argv[2] == '-r':
            random_ports = True

    #ether_dst = 1
    #random_ports = False

    iface = get_if()

    pkts = rdpcap(pcap_path)
    print("read pcap")
    for pkt in pkts:

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            src_port = pkt[IP].sport
            dst_port = pkt[IP].dport

            send_packet(iface, ether_dst, random_ports,  src_ip, dst_ip, src_port, dst_port, protocol)
        time.sleep(0.1)

def parser():
    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')

    parser.add_argument("--m",help = "Send packets manually",action = 'store_true')
    args = parser.parse_args()
    return args.m

if __name__ == '__main__':
    manual = parser()
    pcap_path = "Ethernet_test_pcap.pcap"
    main()
